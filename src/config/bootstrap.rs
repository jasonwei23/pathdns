use crate::dns;
use anyhow::{anyhow, Context, Result};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket};
use std::os::fd::AsRawFd;
use std::time::Duration;

/// Send a one-shot UDP DNS query and return the first IP of the requested type.
///
/// `mark`, when set, applies the same `SO_MARK` (fwmark) the upstream's own
/// query traffic uses, so bootstrap resolution follows the same policy route
/// instead of going out the default table.
pub(super) fn bootstrap_udp_query(
    hostname: &str,
    qtype: u16,
    server: SocketAddr,
    mark: Option<u32>,
) -> Result<IpAddr> {
    let query = build_bootstrap_query(hostname, qtype)?;
    let bind = if server.is_ipv6() {
        "[::]:0"
    } else {
        "0.0.0.0:0"
    };
    let sock = UdpSocket::bind(bind).context("bootstrap: bind UDP socket")?;
    if let Some(mark) = mark {
        crate::upstream::set_so_mark(sock.as_raw_fd(), mark)?;
    }
    sock.set_read_timeout(Some(Duration::from_secs(3)))
        .context("bootstrap: set read timeout")?;
    sock.send_to(&query, server)
        .with_context(|| format!("bootstrap: send query to {server}"))?;
    let mut buf = [0u8; 512];
    let (n, _) = sock
        .recv_from(&mut buf)
        .with_context(|| format!("bootstrap: no response from {server}"))?;
    parse_bootstrap_answer(&buf[..n], qtype)
}

/// Builds on the shared query encoder (`dns::synthetic_query`/`encode_dns_name`)
/// instead of hand-rolling label encoding a second time, picking up its stricter
/// validation (rejects empty labels, enforces the 255-byte wire limit) for free.
pub(super) fn build_bootstrap_query(hostname: &str, qtype: u16) -> Result<Vec<u8>> {
    let (pkt, _question_end) = dns::synthetic_query(hostname, qtype)?;
    Ok(pkt)
}

/// Parses via the shared `dns::question_end`/`dns::extract_answer_records`
/// instead of a hand-rolled RR walk, so this untrusted-input parser (a bootstrap
/// UDP reply can be spoofed) gets the same hardened bounds-checking as every
/// other response parser in the crate rather than a separately maintained copy.
fn parse_bootstrap_answer(resp: &[u8], qtype: u16) -> Result<IpAddr> {
    if resp.len() < 12 {
        return Err(anyhow!("bootstrap: response too short"));
    }
    if !dns::is_reply(resp) {
        return Err(anyhow!("bootstrap: not a response packet"));
    }
    let rcode = dns::rcode(resp);
    if rcode != 0 {
        return Err(anyhow!("bootstrap: RCODE={rcode}"));
    }
    let ancount = u16::from_be_bytes([resp[6], resp[7]]) as usize;
    if ancount == 0 {
        return Err(anyhow!("bootstrap: NODATA (no answer records)"));
    }
    let question_end =
        dns::question_end(resp).ok_or_else(|| anyhow!("bootstrap: question section truncated"))?;
    for (rtype, _ttl, rdata) in dns::extract_answer_records(resp, question_end) {
        if rtype != qtype {
            continue;
        }
        if qtype == 1 && rdata.len() == 4 {
            return Ok(IpAddr::V4(Ipv4Addr::new(
                rdata[0], rdata[1], rdata[2], rdata[3],
            )));
        } else if qtype == 28 && rdata.len() == 16 {
            let mut o = [0u8; 16];
            o.copy_from_slice(&rdata);
            return Ok(IpAddr::V6(Ipv6Addr::from(o)));
        }
    }
    Err(anyhow!(
        "bootstrap: no {} records in answer",
        if qtype == 1 { "A" } else { "AAAA" }
    ))
}
