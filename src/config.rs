use std::collections::HashMap;
use std::fmt::Display;

use lettre::Address;
use reqwest::Url;

use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug)]
pub struct Config {
    pub account: Account,
    #[serde(default)]
    pub ip_reflector: Reflector,
    #[serde(default)]
    pub zone: HashMap<String, Zone>,
}

#[derive(Serialize, Deserialize, Default, Debug)]
pub struct Reflector {
    pub ipv4: Option<Url>,
    pub ipv6: Option<Url>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Account {
    pub email: Address,
    pub api_key: String,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Zone {
    pub id: String,
    #[serde(default)]
    pub record: Vec<DnsRecord>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct DnsRecord {
    #[serde(default)]
    pub disabled: bool,
    pub name: String,
    pub id: String,
    pub proxy: bool,
    #[serde(rename = "type")]
    pub protocol_type: RecordType,
}

impl Display for DnsRecord {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if f.alternate() {
            self.id.fmt(f)
        } else {
            self.name.fmt(f)
        }
    }
}

impl DnsRecord {
    pub fn is_ipv4(&self) -> bool {
        self.protocol_type == RecordType::A
    }

    pub fn is_ipv6(&self) -> bool {
        self.protocol_type == RecordType::AAAA
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
// One of the rare times where I don't actually care about this.
#[allow(clippy::upper_case_acronyms)]
pub enum RecordType {
    A,
    AAAA,
}

impl Display for RecordType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::A => "A".fmt(f),
            Self::AAAA => "AAAA".fmt(f),
        }
    }
}
