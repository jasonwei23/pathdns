use crate::config::IpSetPair;
use anyhow::{anyhow, Result};
use std::net::IpAddr;

#[derive(Debug, Clone)]
pub(super) struct SetPair {
    pub(super) v4: Option<SetName>,
    pub(super) v6: Option<SetName>,
}

#[derive(Debug, Clone, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub(super) enum SetName {
    IpSet(String),
    NftSet {
        family: NftFamily,
        table: String,
        set: String,
    },
}

#[derive(Debug, Clone, Copy, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub(super) enum NftFamily {
    Inet,
    Ip,
    Ip6,
    Arp,
    Bridge,
    Netdev,
}

impl SetPair {
    pub(super) fn parse(pair: &IpSetPair) -> Result<Self> {
        Ok(Self {
            v4: pair.v4.as_deref().map(SetName::parse).transpose()?,
            v6: pair.v6.as_deref().map(SetName::parse).transpose()?,
        })
    }

    pub(super) fn set_for(&self, ip: IpAddr) -> Option<&SetName> {
        match ip {
            IpAddr::V4(_) => self.v4.as_ref(),
            IpAddr::V6(_) => self.v6.as_ref(),
        }
    }

    pub(super) fn summary(&self) -> String {
        format!(
            "{},{}",
            self.v4
                .as_ref()
                .map(SetName::display_name)
                .unwrap_or_else(|| "-".to_string()),
            self.v6
                .as_ref()
                .map(SetName::display_name)
                .unwrap_or_else(|| "-".to_string())
        )
    }
}

impl SetName {
    pub(super) fn parse(raw: &str) -> Result<Self> {
        if raw.contains('@') {
            let mut parts = raw.split('@');
            let family = parse_nft_family(parts.next().unwrap_or_default())?;
            let table = parts.next().unwrap_or_default();
            let set = parts.next().unwrap_or_default();
            if table.is_empty() || set.is_empty() || parts.next().is_some() {
                return Err(anyhow!("invalid nftset name: {raw}"));
            }
            Ok(Self::NftSet {
                family,
                table: table.to_string(),
                set: set.to_string(),
            })
        } else {
            Ok(Self::IpSet(raw.to_string()))
        }
    }

    pub(super) fn display_name(&self) -> String {
        match self {
            Self::IpSet(name) => name.clone(),
            Self::NftSet { family, table, set } => {
                format!("{}@{}@{}", family.name(), table, set)
            }
        }
    }
}

impl NftFamily {
    pub(super) fn name(self) -> &'static str {
        match self {
            Self::Inet => "inet",
            Self::Ip => "ip",
            Self::Ip6 => "ip6",
            Self::Arp => "arp",
            Self::Bridge => "bridge",
            Self::Netdev => "netdev",
        }
    }
}

fn parse_nft_family(value: &str) -> Result<NftFamily> {
    match value {
        "inet" => Ok(NftFamily::Inet),
        "ip" => Ok(NftFamily::Ip),
        "ip6" => Ok(NftFamily::Ip6),
        "arp" => Ok(NftFamily::Arp),
        "bridge" => Ok(NftFamily::Bridge),
        "netdev" => Ok(NftFamily::Netdev),
        _ => Err(anyhow!("invalid nft family: {value}")),
    }
}
