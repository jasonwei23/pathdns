use anyhow::{anyhow, Context, Result};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket};
use std::time::Duration;

/// Send a one-shot UDP DNS query and return the first IP of the requested type.
pub(super) fn bootstrap_udp_query(hostname: &str, qtype: u16, server: SocketAddr) -> Result<IpAddr> {
    let query = build_bootstrap_query(hostname, qtype)?;
    let bind = if server.is_ipv6() { "[::]:0" } else { "0.0.0.0:0" };
    let sock = UdpSocket::bind(bind).context("bootstrap: bind UDP socket")?;
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

pub(super) fn build_bootstrap_query(hostname: &str, qtype: u16) -> Result<Vec<u8>> {
    let mut pkt: Vec<u8> = Vec::with_capacity(64);
    // Header: ID=0x1000, QR=0 RD=1, QDCOUNT=1, rest=0
    pkt.extend_from_slice(&[
        0x10, 0x00, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ]);
    for label in hostname.trim_end_matches('.').split('.') {
        if label.len() > 63 {
            return Err(anyhow!(
                "bootstrap: label too long in hostname '{hostname}'"
            ));
        }
        pkt.push(label.len() as u8);
        pkt.extend_from_slice(label.as_bytes());
    }
    pkt.push(0); // root label
    pkt.extend_from_slice(&qtype.to_be_bytes());
    pkt.extend_from_slice(&1u16.to_be_bytes()); // QCLASS IN
    Ok(pkt)
}

fn parse_bootstrap_answer(resp: &[u8], qtype: u16) -> Result<IpAddr> {
    if resp.len() < 12 {
        return Err(anyhow!("bootstrap: response too short"));
    }
    if resp[2] & 0x80 == 0 {
        return Err(anyhow!("bootstrap: not a response packet"));
    }
    let rcode = resp[3] & 0x0f;
    if rcode != 0 {
        return Err(anyhow!("bootstrap: RCODE={rcode}"));
    }
    let ancount = u16::from_be_bytes([resp[6], resp[7]]) as usize;
    if ancount == 0 {
        return Err(anyhow!("bootstrap: NODATA (no answer records)"));
    }
    let qdcount = u16::from_be_bytes([resp[4], resp[5]]) as usize;
    let mut pos = 12usize;
    for _ in 0..qdcount {
        pos = skip_dns_name(resp, pos)?;
        pos = pos
            .checked_add(4)
            .filter(|&p| p <= resp.len())
            .ok_or_else(|| anyhow!("bootstrap: question section truncated"))?;
    }
    for _ in 0..ancount {
        pos = skip_dns_name(resp, pos)?;
        if pos + 10 > resp.len() {
            return Err(anyhow!("bootstrap: answer section truncated"));
        }
        let rtype = u16::from_be_bytes([resp[pos], resp[pos + 1]]);
        let rdlen = u16::from_be_bytes([resp[pos + 8], resp[pos + 9]]) as usize;
        pos += 10;
        if pos + rdlen > resp.len() {
            return Err(anyhow!("bootstrap: RDATA truncated"));
        }
        if rtype == qtype {
            if qtype == 1 && rdlen == 4 {
                return Ok(IpAddr::V4(Ipv4Addr::new(
                    resp[pos],
                    resp[pos + 1],
                    resp[pos + 2],
                    resp[pos + 3],
                )));
            } else if qtype == 28 && rdlen == 16 {
                let mut o = [0u8; 16];
                o.copy_from_slice(&resp[pos..pos + 16]);
                return Ok(IpAddr::V6(Ipv6Addr::from(o)));
            }
        }
        pos += rdlen;
    }
    Err(anyhow!(
        "bootstrap: no {} records in answer",
        if qtype == 1 { "A" } else { "AAAA" }
    ))
}

/// Skip a DNS label sequence (with optional pointer compression) at `pos`.
/// Returns the position immediately after the name.
pub(super) fn skip_dns_name(buf: &[u8], mut pos: usize) -> Result<usize> {
    loop {
        if pos >= buf.len() {
            return Err(anyhow!("bootstrap: name extends past end of packet"));
        }
        match buf[pos] >> 6 {
            0 => {
                let len = buf[pos] as usize;
                if len == 0 {
                    return Ok(pos + 1);
                }
                pos += 1 + len;
            }
            3 => return Ok(pos + 2), // compression pointer
            _ => return Err(anyhow!("bootstrap: unsupported label type 0x{:02x}", buf[pos])),
        }
    }
}
