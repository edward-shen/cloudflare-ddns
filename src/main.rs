#![warn(clippy::pedantic)]

use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::config::{Config, RecordType};

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use reqwest::Url;
use serde::Deserialize;
use serde_json::json;
use tabled::settings::object::Column;
use tabled::settings::{Alignment, Modify};
use tabled::{Table, Tabled};
use tracing::{error, info, warn};

mod config;

const X_AUTH_EMAIL: &str = "X-Auth-Email";
const X_AUTH_KEY: &str = "X-Auth-Key";

#[derive(Parser, Clone, Debug)]
pub struct Args {
    #[command(subcommand)]
    cmd: Command,
}

#[derive(Subcommand, Clone, Debug)]
pub enum Command {
    Run,
    List(List),
}

#[derive(Parser, Clone, Debug)]
pub struct List {
    zones: Option<Vec<String>>,
}

#[tokio::main]
async fn main() -> Result<()> {
    match Args::parse().cmd {
        Command::Run => handle_run(load_config()?).await,
        Command::List(list) => handle_list(load_config()?, list).await,
    }
}

async fn handle_run(conf: Config) -> Result<()> {
    let ipv4_addr = match conf.ip_reflector.ipv4 {
        Some(addr_to_req) => Some(IpAddr::V4(
            get_ipv4(addr_to_req)
                .await
                .context("Failed to query for ipv4 address, bailing.")?,
        )),
        None => None,
    };
    let ipv6_addr = match conf.ip_reflector.ipv6 {
        Some(addr_to_req) => Some(IpAddr::V6(
            get_ipv6(addr_to_req)
                .await
                .context("Failed to query for ipv4 address, bailing.")?,
        )),
        None => None,
    };

    for zone in conf.zone.into_values() {
        let zone_id = zone.id;

        let records_to_process = zone.record.into_iter().filter_map(|record| {
            if ipv4_addr.is_some() && record.is_ipv4() {
                return Some((&ipv4_addr, record));
            }

            if ipv6_addr.is_some() && record.is_ipv6() {
                return Some((&ipv6_addr, record));
            }

            None
        });

        for (addr, record) in records_to_process.take(3) {
            #[derive(Deserialize, Debug)]
            #[allow(dead_code)]
            struct UpdateDnsResponse {
                success: bool,
                errors: Vec<Message>,
                messages: Vec<Message>,
            }

            let record_id = record.id;
            let resp: UpdateDnsResponse = reqwest::Client::new()
                .put(format!(
                    "https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records/{record_id}"
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

            // TODO: handle success
        }
    }
    Ok(())
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

                    eprintln!("Unknown zone {maybe_zone_id}, skipping");
                    None
                })
                .collect()
        }
        None => known_zones.into_iter().cloned().collect(),
    };

    for zone in zones {
        #[derive(Deserialize, Debug)]
        #[allow(dead_code)]
        struct ListZoneResponse {
            success: bool,
            errors: Vec<Message>,
            messages: Vec<Message>,
            result: Vec<DnsResponse>,
        }

        #[derive(Deserialize, Debug, Tabled)]
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
            } else {
                entries.extend(resp.result);
            }
        }

        // Sort by subdomain, with higher level subdomains taking higher precedence than lower ones.
        entries.sort_unstable_by(|a, b| a.name.split('.').rev().cmp(b.name.split('.').rev()));

        println!(
            "{}",
            Table::new(entries).with(Modify::new(Column::from(0)).with(Alignment::right()))
        );
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

fn load_config() -> Result<Config> {
    let conf_str = std::fs::read_to_string("./config.toml")?;
    Ok(toml::from_str(&conf_str)?)
}
