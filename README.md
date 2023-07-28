# DDNS for Cloudflare

Small binary to update Cloudflare DNS entries via a config file.

## How does it work

This system is split into two portions, the binary itself and an external timer
that periodically executes the binary.

To install the binary, either build your own `.deb` file or find a release. More
distro support is appreciated but not currently promised.

An external timer can be a system provided one or something like `crontab`.
For convenience, a `systemd` system and timer file is provided that activates it
on an hourly interval. This is automatically installed if you use the `.deb`.

The binary contains various subcommands:

|Subcommand|Description|
|----------|-----------|
|`run`|Reads from a config file and calls into Cloudflare's API|
|`list`|Read the config file to list information about your zones|

This binary must be activated at your preferred interval via an external timer.

This only supports updating one IP address to any number of zones and DNS
entries. For another IP address, install and run this on the machine with
different IP address.

## Installation

First, create an initial file at `/etc/cloudflare-ddns.toml`. Populate it with
the following:

```toml
[account]
email = "your@email.com"
api_key = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

[ip_reflector]
ipv4 = "https://what.is.my.ipv4.example"
ipv6 = "https://what.is.my.ipv6.example"

[zone."example.com"]
id = "deadbeefdeadbeefdeadbeefdeadbeef"
```

### `account` section

The `email` should be the email associated with your Cloudflare account.

The `api_key` field should be populated with your Global API Key. This is found
at on your [account profile].

[account profile]: https://dash.cloudflare.com/profile/api-tokens

### `ip_reflector` section

The `ipv4` and `ipv6` fields should be populated with a URL that when provided
a `GET` request, returns the IP address in the body as a string, without a
newline.

For example, `curl` should return something similar to this:

```
$ curl https://what.is.my.ipv4.example
1.2.3.4%
```
The `%` is added by `curl` to indicate no line ending.

### `zone` section

Each zone subsection should contain a website registered to your account. Each
zone needs an `id`, which can be found on the Overview tab of the respective
website.

Once you've populated all fields, run `cloudflare-ddns list` to list the ids of
each DNS entry:

```
example.com (deadbeefdeadbeefdeadbeefdeadbeef)
+--------------------+------+--------------------------+---------+----------------------------------+
|               Name | Type | IP Address               | Proxied | Id                               |
+--------------------+------+--------------------------+---------+----------------------------------+
|        example.com | A    | 6.6.6.6                  | false   | fefefefefefefefefefefefefefefefe |
+--------------------+------+--------------------------+---------+----------------------------------+
|   irys.example.com | A    | 6.6.6.6                  | true    | c0ffeec0ffeec0ffeec0ffeec0ffeec0 |
+--------------------+------+--------------------------+---------+----------------------------------+
| suisei.example.com | AAAA | 1111:11::1111            | true    | 1337c0d31337c0d31337c0d31337c0d3 |
+--------------------+------+--------------------------+---------+----------------------------------+
```

This lists all relevant data necessary for dynamically updating each DNS entry.

For each DNS entry for `example.com` you want to dynamically update, create an
entry as follows:

```toml
[[zone."example.com".record]]
name = "@" # Use @ for the root domain
id = "fefefefefefefefefefefefefefefefe"
proxy = false
type = "A"

[[zone."example.com".record]]
name = "irys"
id = "c0ffeec0ffeec0ffeec0ffeec0ffeec0"
proxy = true
type = "A"

[[zone."example.com".record]]
name = "suisei"
id = "1337c0d31337c0d31337c0d31337c0d3"
proxy = true
type = "AAAA"
```

A full example config can be found in the repo.

At this point, you can run `cloudflare-ddns run` to verify that everything
works. If you run into issues, you can provide `--log=debug` or `--log=trace`
for more information.

If successful, attempt to trigger it via the external timer. If that is
successful, installation is complete.

## Building packages

A `.deb` package is created via [`cargo-deb`].

[`cargo-deb`]: https://github.com/kornelski/cargo-deb