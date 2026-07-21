use anyhow::{anyhow, Result};

/// A fully-parsed set identifier, optionally with a prefix-length mask.
///
/// Syntax:
/// - ipset:  `"myset"` or `"myset/24"` (`/N` suffix = mask)
/// - nftset: `"inet@fw4@myset"` or `"inet@fw4@myset@24"` (4th `@` segment = mask)
///
/// The mask, when present, is applied to each resolved IP before it is written to
/// the set (e.g. `1.2.3.100/24` → network address `1.2.3.0`).  For nftset targets
/// the caller additionally queries whether the set carries the `interval` flag; if
/// so the entry is written as a prefix range instead of a single host element.
#[derive(Debug, Clone, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub(super) enum SetName {
    IpSet {
        name: String,
        mask: Option<u8>,
    },
    NftSet {
        family: NftFamily,
        table: String,
        set: String,
        mask: Option<u8>,
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

impl SetName {
    /// `max_prefix` is 32 for an IPv4 (`A`) add-ip target, 128 for IPv6
    /// (`AAAA`) — the config layer derives it from the filter entry's
    /// `response-type`, which `add_ip` requires to be pinned to exactly one
    /// of the two (see `crate::response_filter`).
    pub(super) fn parse(raw: &str, max_prefix: u8) -> Result<Self> {
        let parsed = if raw.contains('@') {
            // nftset: "family@table@set" or "family@table@set@mask"
            let mut parts = raw.splitn(5, '@');
            let family = parse_nft_family(parts.next().unwrap_or_default())?;
            let table = parts.next().unwrap_or_default();
            let set = parts.next().unwrap_or_default();
            let mask_str = parts.next().unwrap_or_default();
            if table.is_empty() || set.is_empty() || parts.next().is_some() {
                return Err(anyhow!("invalid nftset name: {raw}"));
            }
            let mask = parse_mask(mask_str)?;
            Self::NftSet {
                family,
                table: table.to_string(),
                set: set.to_string(),
                mask,
            }
        } else {
            // ipset: "name" or "name/prefix"
            let (name, mask) = if let Some(slash) = raw.rfind('/') {
                let mask = parse_mask(&raw[slash + 1..])?
                    .ok_or_else(|| anyhow!("invalid ipset mask in: {raw}"))?;
                (&raw[..slash], Some(mask))
            } else {
                (raw, None)
            };
            if name.is_empty() {
                return Err(anyhow!("empty ipset name in: {raw}"));
            }
            Self::IpSet {
                name: name.to_string(),
                mask,
            }
        };
        if let Some(mask) = parsed.mask() {
            if mask > max_prefix {
                return Err(anyhow!(
                    "prefix length {mask} exceeds maximum {max_prefix} in: {raw}"
                ));
            }
        }
        Ok(parsed)
    }

    fn mask(&self) -> Option<u8> {
        match self {
            Self::IpSet { mask, .. } | Self::NftSet { mask, .. } => *mask,
        }
    }
}

fn parse_mask(s: &str) -> Result<Option<u8>> {
    if s.is_empty() {
        return Ok(None);
    }
    let n: u8 = s
        .parse()
        .map_err(|_| anyhow!("invalid prefix length '{s}': must be 0–128"))?;
    if n > 128 {
        return Err(anyhow!("invalid prefix length '{s}': must be 0–128"));
    }
    Ok(Some(n))
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
