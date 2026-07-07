use super::parse::{
    authority_host, authority_port, normalize_addr_with_default_port, parse_bootstrap_addr,
    resolve_authority, resolve_host, strip_ipv6_brackets,
};
use super::{EcsMode, EcsSubnet, UpstreamEndpoint, UpstreamProto};
use anyhow::{anyhow, Context, Result};
use std::net::SocketAddr;

pub(super) fn parse_upstreams(items: &[String]) -> Result<Vec<UpstreamEndpoint>> {
    let mut out = Vec::new();
    for item in items {
        out.extend(parse_upstream(item)?);
    }
    if out.is_empty() {
        return Err(anyhow!("at least one upstream DNS is required"));
    }
    Ok(out)
}

pub(super) fn parse_upstream(raw: &str) -> Result<Vec<UpstreamEndpoint>> {
    let raw = raw.trim();
    if raw.is_empty() {
        return Err(anyhow!("upstream cannot be empty"));
    }
    if raw.contains('#') {
        return Err(anyhow!(
            "invalid upstream '{raw}': '#' port syntax is not supported; use udp://host:port or tcp://host:port"
        ));
    }
    if let Some((host, addr)) = raw.rsplit_once('@') {
        return Err(anyhow!(
            "upstream host@addr syntax is not supported: {host}@{addr}"
        ));
    }

    let Some((scheme, rest)) = raw.split_once("://") else {
        // Schemaless: plain IP address, default UDP/53.
        // Hostnames are not supported without an explicit scheme; use
        // udp://host?bootstrap=IP or tls://host?bootstrap=IP instead.
        let normalized = normalize_addr_with_default_port(raw, 53);
        let host = authority_host(&normalized)?;
        let port = authority_port(&normalized, 53);
        let addr = resolve_host(host, port, &[]).with_context(|| format!("upstream '{raw}'"))?;
        return Ok(vec![endpoint(
            UpstreamProto::Udp,
            addr,
            None,
            None,
            false,
            None,
            None,
        )]);
    };

    let proto = parse_upstream_scheme(scheme)?;
    let (rest_no_query, query) = rest.split_once('?').map_or((rest, ""), |(a, q)| (a, q));
    let no_sni = query.split('&').any(|p| p == "no-sni");
    let sni_override = query
        .split('&')
        .find_map(|p| p.strip_prefix("sni="))
        .map(str::to_string);
    let ecs_param = query.split('&').find_map(|p| p.strip_prefix("ecs="));
    let ecs_mode: Option<EcsMode> = match ecs_param {
        None => None,
        Some("strip") => Some(EcsMode::Strip),
        Some("forward") => Some(EcsMode::Forward),
        Some(val) => Some(EcsMode::Fixed(
            parse_ecs_subnet(val)
                .with_context(|| format!("invalid upstream '{raw}': ?ecs={val}"))?,
        )),
    };
    let bootstrap_param = query.split('&').find_map(|p| p.strip_prefix("bootstrap="));
    let bootstrap_addr: Option<SocketAddr> = match bootstrap_param {
        None => None,
        Some(val) => {
            Some(parse_bootstrap_addr(val).with_context(|| format!("invalid upstream '{raw}'"))?)
        }
    };
    let bootstrap_slice: &[SocketAddr] = bootstrap_addr.as_slice();

    let mark: Option<u32> = match query.split('&').find_map(|p| p.strip_prefix("mark=")) {
        None => None,
        Some(val) => Some(
            parse_fwmark(val).with_context(|| format!("invalid upstream '{raw}': ?mark={val}"))?,
        ),
    };

    for param in query.split('&').filter(|p| !p.is_empty()) {
        if param != "no-sni"
            && !param.starts_with("sni=")
            && !param.starts_with("ecs=")
            && !param.starts_with("bootstrap=")
            && !param.starts_with("mark=")
        {
            return Err(anyhow!(
                "invalid upstream '{raw}': unknown query parameter '{param}'"
            ));
        }
    }
    if no_sni && !matches!(proto, UpstreamProto::Tls) {
        return Err(anyhow!(
            "invalid upstream '{raw}': ?no-sni is only valid for tls:// upstreams"
        ));
    }
    if sni_override.is_some() && !proto.uses_tls_name() {
        return Err(anyhow!(
            "invalid upstream '{raw}': ?sni= is only valid for TLS-based upstreams"
        ));
    }

    let (authority, path) = split_upstream_path(rest_no_query)?;
    let port = proto.default_port();
    let (host, addr) = resolve_authority(authority, port, bootstrap_slice)
        .with_context(|| format!("upstream '{raw}'"))?;
    let server_name = sni_override.or_else(|| {
        proto
            .uses_tls_name()
            .then(|| strip_ipv6_brackets(host).to_string())
    });
    let path = match proto {
        UpstreamProto::Https | UpstreamProto::H3 => {
            Some(path.unwrap_or(DEFAULT_DOH_PATH).to_string())
        }
        _ if path.is_some() => {
            return Err(anyhow!(
                "invalid upstream '{raw}': path is only valid for https://, h3://"
            ));
        }
        _ => None,
    };

    Ok(vec![endpoint(
        proto,
        addr,
        server_name,
        path,
        no_sni,
        ecs_mode,
        mark,
    )])
}

const DEFAULT_DOH_PATH: &str = "/dns-query";

/// Parse a `?mark=` fwmark value: hex (`0x1`) or decimal (`1`), into a `u32`.
fn parse_fwmark(s: &str) -> Result<u32> {
    let s = s.trim();
    let parsed = match s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        Some(hex) => u32::from_str_radix(hex, 16),
        None => s.parse::<u32>(),
    };
    parsed.map_err(|_| anyhow!("expected a u32 fwmark such as 0x1 or 100, got '{s}'"))
}

fn endpoint(
    proto: UpstreamProto,
    addr: SocketAddr,
    server_name: Option<String>,
    path: Option<String>,
    no_sni: bool,
    ecs_mode: Option<EcsMode>,
    mark: Option<u32>,
) -> UpstreamEndpoint {
    UpstreamEndpoint {
        proto,
        addr,
        server_name,
        path,
        no_sni,
        ecs_mode,
        mark,
    }
}

fn parse_ecs_subnet(s: &str) -> Result<EcsSubnet> {
    use std::net::IpAddr;
    if let Some((addr_str, prefix_str)) = s.split_once('/') {
        let addr: IpAddr = addr_str
            .parse()
            .with_context(|| format!("invalid address '{addr_str}'"))?;
        let prefix_len: u8 = prefix_str
            .parse()
            .with_context(|| format!("invalid prefix length '{prefix_str}'"))?;
        let max = if addr.is_ipv4() { 32u8 } else { 128u8 };
        if prefix_len > max {
            return Err(anyhow!("prefix length {prefix_len} exceeds maximum {max}"));
        }
        Ok(EcsSubnet { addr, prefix_len })
    } else {
        let addr: IpAddr = s
            .parse()
            .with_context(|| format!("expected IP address or CIDR prefix, got '{s}'"))?;
        let prefix_len = if addr.is_ipv4() { 32 } else { 128 };
        Ok(EcsSubnet { addr, prefix_len })
    }
}

pub(super) fn parse_rcode_name(name: &str) -> Result<u8> {
    match name.to_ascii_uppercase().as_str() {
        "NOERROR" => Ok(0),
        "FORMERR" => Ok(1),
        "SERVFAIL" => Ok(2),
        "NXDOMAIN" => Ok(3),
        "NOTIMP" => Ok(4),
        "REFUSED" => Ok(5),
        other => other
            .parse::<u8>()
            .map_err(|_| anyhow!("unknown RCODE \"{other}\" — use NOERROR/NXDOMAIN/SERVFAIL/REFUSED or a number 0–15")),
    }
}

fn parse_upstream_scheme(scheme: &str) -> Result<UpstreamProto> {
    match scheme.to_ascii_lowercase().as_str() {
        "udp" => Ok(UpstreamProto::Udp),
        "tcp" => Ok(UpstreamProto::Tcp),
        "tls" => Ok(UpstreamProto::Tls),
        "https" => Ok(UpstreamProto::Https),
        "quic" => Ok(UpstreamProto::Quic),
        "h3" => Ok(UpstreamProto::H3),
        other => Err(anyhow!("unsupported upstream scheme '{other}'")),
    }
}

fn split_upstream_path(rest: &str) -> Result<(&str, Option<&str>)> {
    let (authority, path) = rest.split_once('/').map_or((rest, None), |(a, p)| {
        let path = if p.is_empty() { "/" } else { &rest[a.len()..] };
        (a, Some(path))
    });
    if authority.is_empty() {
        return Err(anyhow!("upstream URL is missing a host"));
    }
    Ok((authority, path))
}

impl UpstreamProto {
    pub fn default_port(self) -> u16 {
        match self {
            Self::Udp | Self::Tcp => 53,
            Self::Tls | Self::Quic => 853,
            Self::Https | Self::H3 => 443,
        }
    }

    fn uses_tls_name(self) -> bool {
        matches!(self, Self::Tls | Self::Https | Self::Quic | Self::H3)
    }
}
