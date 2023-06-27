#![warn(clippy::pedantic, clippy::cargo)]

use std::collections::{BTreeMap, HashMap, HashSet};
use std::fmt::{Debug, Display};
use std::fs::File;
use std::io::{self, IsTerminal};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::config::{Config, RecordType};

use anyhow::{Context, Result};
use clap::{Parser, Subcommand, ValueEnum};
use reqwest::Url;
use serde::{Deserialize, Serialize};
use serde_json::json;
use tabled::settings::object::Column;
use tabled::settings::{Alignment, Modify};
use tabled::{Table, Tabled};
use tokio::time;
use tracing::{debug, info, instrument, trace, warn, Level};
use tracing_subscriber::filter::Directive;
use tracing_subscriber::fmt::Subscriber;
use tracing_subscriber::EnvFilter;

mod config;

const X_AUTH_EMAIL: &str = "X-Auth-Email";
const X_AUTH_KEY: &str = "X-Auth-Key";

/// Scuffed Cloudflare dynamic DNS script.
///
/// If std
#[derive(Parser, Clone, Debug)]
#[clap(author = clap::crate_authors!(), version = clap::crate_version!())]
pub struct Args {
    /// Path to the configuration file.
    ///
    /// If not provided, checks the current working directory, the current
    /// user's local config directory, and finally the system wide config
    /// directory.
    #[clap(short, long, global = true)]
    config_file: Option<PathBuf>,
    #[clap(short, long, global = true, value_delimiter = ',')]
    verbose: Vec<Directive>,
    // Force whether or not to print colors
    #[clap(long, default_value_t = Color::default())]
    color: Color,
    #[command(subcommand)]
    cmd: Command,
}

#[derive(Subcommand, Clone, Debug)]
pub enum Command {
    /// Fetch a reflected IP address and update A and AAAA entries in DNS.
    Run,
    /// List all A and AAAA entries in each zone in the config.
    List(List),
}

#[derive(Parser, Clone, Debug)]
pub struct List {
    /// Limit which zones to emit.
    ///
    /// If not provided, print all zones in the config.
    zones: Option<Vec<String>>,
    /// Which format to output zone data in.
    #[clap(short, long, default_value_t = OutputFormat::default())]
    output: OutputFormat,
}

#[derive(ValueEnum, Default, Debug, Clone, Copy)]
enum OutputFormat {
    #[default]
    Table,
    Json,
}

impl Display for OutputFormat {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            OutputFormat::Table => Display::fmt("table", f),
            OutputFormat::Json => Display::fmt("json", f),
        }
    }
}

#[derive(ValueEnum, Default, Debug, Clone, Copy, PartialEq, Eq)]
enum Color {
    #[default]
    Auto,
    Never,
    Always,
}

impl Display for Color {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Color::Auto => Display::fmt("auto", f),
            Color::Never => Display::fmt("never", f),
            Color::Always => Display::fmt("always", f),
        }
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    let env_filter = args
        .verbose
        .into_iter()
        .fold(EnvFilter::from_default_env(), |env, directive| {
            env.add_directive(directive)
        });

    let is_stdout_terminal = io::stdout().is_terminal();
    let use_ansi = match args.color {
        Color::Auto => is_stdout_terminal || io::stderr().is_terminal(),
        other => other == Color::Always,
    };

    Subscriber::builder()
        .with_env_filter(env_filter)
        .with_ansi(use_ansi)
        .with_writer(move || -> Box<dyn io::Write> {
            // If we're redirecting stdout, use stderr for logs
            // This makes json output work as expected for redirection
            if is_stdout_terminal {
                Box::new(io::stdout())
            } else {
                Box::new(io::stderr())
            }
        })
        .init();

    let config = load_config(args.config_file).context("Failed to find a suitable config file")?;
    match args.cmd {
        Command::Run => handle_run(config).await,
        Command::List(list) => handle_list(config, list).await,
    }
}

async fn handle_run(conf: Config) -> Result<()> {
    let ipv4 = if let Some(addr_to_req) = conf.ip_reflector.ipv4 {
        let ip = get_ipv4(addr_to_req)
            .await
            .context("Failed to query for IPv4 address, bailing.")?;
        debug!(addr=%ip, "Found reflected IPv4");
        Some(IpAddr::V4(ip))
    } else {
        info!("No IPv4 reflector endpoint provided. Not updating IPv6 addresses");
        None
    };
    let ipv6 = if let Some(addr_to_req) = conf.ip_reflector.ipv6 {
        let ip = get_ipv6(addr_to_req)
            .await
            .context("Failed to query for IPv6 address, bailing.")?;
        debug!(addr=%ip, "Found reflected IPv6");
        Some(IpAddr::V6(ip))
    } else {
        debug!("No IPv6 reflector endpoint provided. Not updating IPv6 addresses");
        None
    };

    let ip_cache_path = ip_cache_path().context("while getting the ip cache path")?;
    let mut cache_file = load_ip_cache(&ip_cache_path).context("while loading the ip cache")?;

    let mut rate_limit = time::interval(Duration::from_millis(250));
    for (human_readable_name, zone) in conf.zone {
        let span = tracing::span!(Level::TRACE, "zone", domain = %human_readable_name);
        let _enter = span.enter();

        let records_to_process = zone
            .record
            .into_iter()
            .filter(|record| !record.disabled)
            .filter_map(|record| {
                // Only process ipv4 entries if we have a reflected ip
                if record.is_ipv4() {
                    return ipv4.map(|ip| (ip, record));
                }

                // Only process ipv6 entries if we have a reflected ip
                if record.is_ipv6() {
                    return ipv6.map(|ip| (ip, record));
                }

                None
            });

        for (addr, record) in records_to_process {
            #[derive(Deserialize, Debug)]
            #[allow(dead_code)]
            struct UpdateDnsResponse {
                success: bool,
                errors: Vec<Message>,
                messages: Vec<Message>,
            }

            let span = tracing::span!(Level::TRACE, "record", name = %record);
            let _enter = span.enter();

            // Can't put this in a filter combinator because cache_file gets
            // immutably borrowed for the duration of the iterator
            let cache_entry = cache_file.0.get(&record.id).copied();
            let should_skip = match cache_entry {
                entry @ Some(IpAddr::V4(_)) => entry == ipv4,
                entry @ Some(IpAddr::V6(_)) => entry == ipv6,
                None => false,
            };

            if should_skip {
                debug!("Skipping entry since it was up to date in cache");
                continue;
            }

            debug!(cached_ip=?cache_entry, "Need to update entry");

            rate_limit.tick().await;
            let resp: UpdateDnsResponse = reqwest::Client::new()
                .put(format!(
                    "https://api.cloudflare.com/client/v4/zones/{}/dns_records/{}",
                    &zone.id, &record.id
                ))
                .header(X_AUTH_EMAIL, &conf.account.email.to_string())
                .header(X_AUTH_KEY, &conf.account.api_key)
                .json(&json!({
                    "type": record.protocol_type,
                    "name": record.name,
                    "content": addr,
                    "ttl": 1, // Auto TTL
                    "proxied": record.proxy,
                }))
                .send()
                .await
                .context("while requesting an api endpoint")?
                .json()
                .await
                .context("while parsing into a json")?;

            if resp.success {
                trace!("Update successful");
                cache_file.0.insert(record.id, addr);
                continue;
            }
        }
    }

    // Updating the ip cache last is better in case we get interrupted. Better
    // to update too frequently than not enough.
    update_ip_cache(ip_cache_path, &cache_file).context("while updating the cache file")?;
    Ok(())
}

fn update_ip_cache<P: AsRef<Path>>(path: P, data: &CacheFile) -> Result<()> {
    let data = serde_json::to_string(data).expect("serialization to work");
    std::fs::write(path, data).context("while writing the ip cache file")?;
    Ok(())
}

#[derive(Serialize, Deserialize, Default, Debug)]
struct CacheFile(HashMap<String, IpAddr>);

#[instrument(level = "trace", ret)]
fn load_ip_cache<P: AsRef<Path> + Debug>(path: P) -> Result<CacheFile> {
    let file = File::options()
        .create(true)
        .read(true)
        .write(true)
        .open(path)
        .context("while opening the ip cache file")?;
    let data = std::io::read_to_string(file).context("while reading the ip cache file")?;
    Ok(match serde_json::from_str(&data) {
        Ok(cache) => cache,
        Err(e) => {
            warn!("Failed to parse the ip cache file; assuming empty: {e}");
            CacheFile::default()
        }
    })
}

fn ip_cache_path() -> Result<PathBuf> {
    dirs::cache_dir()
        .context("Failed to determine cache directory")
        .map(|path| path.join("cloudflare-ddns.cache"))
}

#[derive(Deserialize, Debug)]
#[allow(dead_code)]
struct Message {
    code: u16,
    message: String,
}

async fn handle_list(conf: Config, args: List) -> Result<()> {
    // Use provided zones or list all in config
    let known_zones: HashSet<_> = conf.zone.values().map(|zone| &zone.id).collect();
    let zones: Vec<_> = match args.zones {
        Some(zones) => {
            // These zones may be human readable. Map them to zone IDs.
            zones
                .into_iter()
                .filter_map(|maybe_zone_id| {
                    if known_zones.contains(&maybe_zone_id) {
                        return Some(maybe_zone_id);
                    }

                    if let Some(zone) = conf.zone.get(&maybe_zone_id) {
                        return Some(zone.id.clone());
                    }

                    warn!("Unknown zone {maybe_zone_id}, skipping");
                    None
                })
                .collect()
        }
        None => known_zones.into_iter().cloned().collect(),
    };

    let mut output = BTreeMap::new();
    let mut rate_limit = time::interval(Duration::from_millis(250));
    for zone in zones {
        #[derive(Deserialize, Debug)]
        #[allow(dead_code)]
        struct ListZoneResponse {
            success: bool,
            errors: Vec<Message>,
            messages: Vec<Message>,
            result: Vec<DnsResponse>,
        }

        #[derive(Serialize, Deserialize, Debug, Tabled)]
        #[tabled(rename_all = "PascalCase")]
        struct DnsResponse {
            name: String,
            #[tabled(rename = "Type")]
            r#type: RecordType,
            #[tabled(rename = "IP Address")]
            content: IpAddr,
            proxied: bool,
            id: String,
        }

        let mut entries = vec![];
        for page_no in 1.. {
            // This technically requests one more than optimal, but tbh it
            // doesn't really matter

            rate_limit.tick().await;
            let resp: ListZoneResponse = reqwest::Client::new()
                .get(format!(
                "https://api.cloudflare.com/client/v4/zones/{zone}/dns_records?type=A,AAAA&page={page_no}"
            ))
                .header(X_AUTH_EMAIL, &conf.account.email.to_string())
                .header(X_AUTH_KEY, &conf.account.api_key)
                .send()
                .await
                .context("while requesting an api endpoint")?
                .json()
                .await
                .context("while parsing into a json")?;

            // todo: handle messages, errors, and non-success response

            if resp.result.is_empty() {
                break;
            }

            entries.extend(resp.result);
        }

        // Sort by subdomain, with higher level subdomains taking higher precedence than lower ones.
        entries.sort_unstable_by(|a, b| a.name.split('.').rev().cmp(b.name.split('.').rev()));

        output.insert(zone, entries);
    }

    let human_readable_mapping: HashMap<_, _> = conf
        .zone
        .into_iter()
        .map(|(human, zone)| (zone.id, human))
        .collect();
    match args.output {
        OutputFormat::Table => {
            for (zone_id, data) in output {
                println!(
                    "{} ({zone_id})\n{}",
                    human_readable_mapping.get(&zone_id).unwrap(),
                    Table::new(data).with(Modify::new(Column::from(0)).with(Alignment::right()))
                );
            }
        }
        OutputFormat::Json => {
            let map: serde_json::Map<String, serde_json::Value> = output
                .into_iter()
                .map(|(zone_id, data)| {
                    (
                        human_readable_mapping.get(&zone_id).unwrap().clone(),
                        json!({
                            "id": zone_id,
                            "records": data,
                        }),
                    )
                })
                .collect();
            println!(
                "{}",
                serde_json::to_string(&map).expect("serialization to work")
            );
        }
    }

    Ok(())
}

async fn get_ipv4(url: Url) -> Result<Ipv4Addr> {
    reqwest::get(url)
        .await
        .context("Failed send IPv4 reflector request")?
        .text()
        .await
        .context("Failed to get IPv4 reflector data")?
        .parse()
        .context("Response was not an IPv4 address")
}

async fn get_ipv6(url: Url) -> Result<Ipv6Addr> {
    reqwest::get(url)
        .await
        .context("Failed send IPv4 reflector request")?
        .text()
        .await
        .context("Failed to get IPv4 reflector data")?
        .parse()
        .context("Response was not an IPv4 address")
}

fn load_config(user_provided_path: Option<PathBuf>) -> Option<Config> {
    if let Some(path) = user_provided_path {
        tracing::trace!("User provided path to config");
        let maybe_config = load_config_from_path(&path);
        if maybe_config.is_some() {
            tracing::info!(
                path = %path.to_string_lossy(),
                "Loaded config file"
            );
        }
        return maybe_config;
    }

    let file_path = Path::new("./cloudflare-ddns.toml");
    let resolved_path = file_path.canonicalize();
    let resolved_path = resolved_path.as_deref().unwrap_or(file_path);
    if let Some(config) = load_config_from_path(resolved_path) {
        tracing::info!(
            path = %resolved_path.to_string_lossy(),
            "Loaded config file"
        );
        return Some(config);
    }

    if let Some((path, config)) = dirs::config_dir()
        .map(|path| path.join(file_path))
        .and_then(|path| load_config_from_path(&path).map(|conf| (path, conf)))
    {
        tracing::info!(
            path = %path.to_string_lossy(),
            "Loaded config file"
        );
        return Some(config);
    }

    if let Some(config) = load_config_from_path("/etc/cloudflare-ddns.toml") {
        tracing::info!(path = "/etc/cloudflare-ddns.toml", "Loaded config file");
        return Some(config);
    }

    None
}

fn load_config_from_path<P: AsRef<Path>>(path: P) -> Option<Config> {
    match std::fs::read_to_string(&path) {
        Ok(data) => match toml::from_str(&data) {
            Ok(config) => return Some(config),
            Err(err) => {
                debug!(
                    "Failed to parse config file at {}: {}",
                    path.as_ref().to_string_lossy(),
                    err
                );
            }
        },
        Err(err) => {
            debug!(
                "Unable to read the config file at {}: {}",
                path.as_ref().to_string_lossy(),
                err
            );
        }
    }
    None
}
