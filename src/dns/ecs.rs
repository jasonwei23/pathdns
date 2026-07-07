use crate::config::EcsSubnet;
use std::net::IpAddr;

/// IANA EDNS(0) option code for Client Subnet (RFC 7871 §6). Note: this is 8,
/// not 11 (0x000b is edns-tcp-keepalive) — getting it wrong means upstreams do
/// not recognise the subnet and `ecs=strip` fails to remove real clients' ECS.
pub(super) const ECS_OPTION_CODE: u16 = 0x0008;

/// Location of an OPT (type 41) resource record found by [`locate_opt`].
struct OptLocation {
    /// Offset of the fixed RR header's first byte after the owner name (TYPE field).
    name_end: usize,
    rdata_start: usize,
    rdata_end: usize,
}

/// Walk the question/answer/authority sections to reach the additional section,
/// then scan it for the first OPT (type 41) RR — the shared traversal used by
/// [`strip_opt_rdata`], [`strip_edns_ecs`], and [`inject_or_replace_ecs`], which
/// otherwise each re-implemented this identically before diverging.
///
/// - Returns `None` if the packet is too short or a record along the way
///   doesn't fit (malformed) — callers propagate this as their own failure.
/// - Returns `Some(None)` if the additional section parsed cleanly but held no
///   OPT RR.
/// - Returns `Some(Some(loc))` for the first OPT RR found. Only the first is
///   considered even if further additional records follow: a compliant DNS
///   message carries at most one OPT RR (RFC 6891 §6.1.1).
fn locate_opt(packet: &[u8]) -> Option<Option<OptLocation>> {
    if packet.len() < 12 {
        return None;
    }
    let ar = u16::from_be_bytes([packet[10], packet[11]]) as usize;
    if ar == 0 {
        return Some(None);
    }
    let qd = u16::from_be_bytes([packet[4], packet[5]]) as usize;
    let an = u16::from_be_bytes([packet[6], packet[7]]) as usize;
    let ns = u16::from_be_bytes([packet[8], packet[9]]) as usize;

    let mut pos = 12usize;
    for _ in 0..qd {
        pos = super::skip_name(packet, pos)?;
        pos = pos.checked_add(4).filter(|&p| p <= packet.len())?;
    }
    for _ in 0..(an + ns) {
        let fixed = super::skip_name(packet, pos)?;
        if fixed + 10 > packet.len() {
            return None;
        }
        let rdlen = u16::from_be_bytes([packet[fixed + 8], packet[fixed + 9]]) as usize;
        pos = fixed
            .checked_add(10 + rdlen)
            .filter(|&p| p <= packet.len())?;
    }
    for _ in 0..ar {
        let name_end = super::skip_name(packet, pos)?;
        if name_end + 10 > packet.len() {
            return None;
        }
        let rr_type = u16::from_be_bytes([packet[name_end], packet[name_end + 1]]);
        let rdlen = u16::from_be_bytes([packet[name_end + 8], packet[name_end + 9]]) as usize;
        let rdata_start = name_end + 10;
        let rdata_end = rdata_start
            .checked_add(rdlen)
            .filter(|&p| p <= packet.len())?;

        if rr_type == 41 {
            return Some(Some(OptLocation {
                name_end,
                rdata_start,
                rdata_end,
            }));
        }
        pos = rdata_end;
    }
    Some(None)
}

/// Clear all option data from the OPT RDATA in a DNS *response*.
///
/// Keeps the OPT fixed header (extended RCODE, EDNS version, DO bit) but removes
/// all per-connection option payloads (server COOKIE, NSID, EXPIRE, …) so they
/// are not returned to subsequent clients served from cache.
///
/// Returns `Some(new_packet)` only when an OPT RR with non-empty RDATA was found.
/// Returns `None` when no modification is needed (no OPT, or RDATA already empty).
pub fn strip_opt_rdata(packet: &[u8]) -> Option<Vec<u8>> {
    let loc = locate_opt(packet)??;
    if loc.rdata_end == loc.rdata_start {
        return None; // RDATA already empty, nothing to strip
    }
    // Replace RDLEN with 0 and drop the RDATA bytes.
    let rdlen_pos = loc.name_end + 8;
    let mut out = Vec::with_capacity(packet.len() - (loc.rdata_end - loc.rdata_start));
    out.extend_from_slice(&packet[..rdlen_pos]);
    out.extend_from_slice(&0u16.to_be_bytes());
    out.extend_from_slice(&packet[loc.rdata_end..]);
    Some(out)
}

/// Strip the EDNS Client Subnet option (code 8) from a DNS query packet.
///
/// Returns `Some(new_packet)` only when ECS was found and removed.
/// Returns `None` when no ECS is present (fast path: no allocation).
/// All other EDNS options are preserved unchanged.
pub fn strip_edns_ecs(packet: &[u8]) -> Option<Vec<u8>> {
    let loc = locate_opt(packet)??;
    strip_ecs_from_opt(packet, loc.rdata_start, loc.rdata_end)
}

/// Rebuild the OPT RDATA without the ECS option (code 8).
fn strip_ecs_from_opt(packet: &[u8], rdata_start: usize, rdata_end: usize) -> Option<Vec<u8>> {
    let rdata = &packet[rdata_start..rdata_end];
    let mut pos = 0usize;
    let mut found_ecs = false;
    let mut new_rdata: Vec<u8> = Vec::with_capacity(rdata.len());

    while pos + 4 <= rdata.len() {
        let code = u16::from_be_bytes([rdata[pos], rdata[pos + 1]]);
        let opt_len = u16::from_be_bytes([rdata[pos + 2], rdata[pos + 3]]) as usize;
        let end = pos + 4 + opt_len;
        if end > rdata.len() {
            return None; // malformed OPT RDATA
        }
        if code == ECS_OPTION_CODE {
            found_ecs = true;
        } else {
            new_rdata.extend_from_slice(&rdata[pos..end]);
        }
        pos = end;
    }

    if !found_ecs {
        return None;
    }

    let new_rdlen = new_rdata.len() as u16;
    let rdlen_pos = rdata_start - 2; // RDLEN is 2 bytes immediately before RDATA
    let mut out = Vec::with_capacity(packet.len());
    out.extend_from_slice(&packet[..rdata_start]);
    out.extend_from_slice(&new_rdata);
    out.extend_from_slice(&packet[rdata_end..]);
    out[rdlen_pos] = (new_rdlen >> 8) as u8;
    out[rdlen_pos + 1] = (new_rdlen & 0xff) as u8;
    Some(out)
}

/// Inject or replace the EDNS Client Subnet option in a DNS query packet.
///
/// - If an OPT RR is present: replaces any existing ECS option with the new one.
/// - If no OPT RR is present: appends a minimal OPT RR containing only the ECS option
///   and increments ARCOUNT.
///
/// Always returns a new allocation.
pub fn inject_or_replace_ecs(packet: &[u8], subnet: &EcsSubnet) -> Option<Vec<u8>> {
    if packet.len() < 12 {
        return None;
    }
    let ecs_opt = encode_ecs_option(subnet);
    let ar = u16::from_be_bytes([packet[10], packet[11]]) as usize;

    match locate_opt(packet)? {
        Some(loc) => {
            // Rebuild OPT RDATA: remove any existing ECS option and append the new one.
            let rdata = &packet[loc.rdata_start..loc.rdata_end];
            let mut new_rdata: Vec<u8> = Vec::with_capacity(rdata.len() + ecs_opt.len());
            let mut p = 0usize;
            while p + 4 <= rdata.len() {
                let code = u16::from_be_bytes([rdata[p], rdata[p + 1]]);
                let opt_len = u16::from_be_bytes([rdata[p + 2], rdata[p + 3]]) as usize;
                let end = p + 4 + opt_len;
                if end > rdata.len() {
                    return None;
                }
                if code != ECS_OPTION_CODE {
                    new_rdata.extend_from_slice(&rdata[p..end]);
                }
                p = end;
            }
            new_rdata.extend_from_slice(&ecs_opt);

            let rdlen_pos = loc.rdata_start - 2;
            let new_rdlen = new_rdata.len() as u16;
            let mut out = Vec::with_capacity(packet.len() + ecs_opt.len());
            out.extend_from_slice(&packet[..loc.rdata_start]);
            out.extend_from_slice(&new_rdata);
            out.extend_from_slice(&packet[loc.rdata_end..]);
            out[rdlen_pos] = (new_rdlen >> 8) as u8;
            out[rdlen_pos + 1] = (new_rdlen & 0xff) as u8;
            Some(out)
        }
        None => {
            // No OPT RR found: append one with just the ECS option.
            // OPT RR: \x00 (root name) + type=41(2) + udp_size=4096(2) + ttl/flags=0(4) + rdlen(2) + rdata
            let new_rdlen = ecs_opt.len() as u16;
            let mut out = Vec::with_capacity(packet.len() + 11 + ecs_opt.len());
            out.extend_from_slice(packet);
            out.push(0x00); // root name
            out.extend_from_slice(&41u16.to_be_bytes()); // type OPT
            out.extend_from_slice(&4096u16.to_be_bytes()); // UDP payload size
            out.extend_from_slice(&0u32.to_be_bytes()); // extended RCODE + EDNS version + flags
            out.extend_from_slice(&new_rdlen.to_be_bytes());
            out.extend_from_slice(&ecs_opt);
            let new_ar = (ar as u16).wrapping_add(1);
            out[10] = (new_ar >> 8) as u8;
            out[11] = (new_ar & 0xff) as u8;
            Some(out)
        }
    }
}

/// Encode subnet as an EDNS option (code 8) ready to embed in OPT RDATA.
fn encode_ecs_option(subnet: &EcsSubnet) -> Vec<u8> {
    let (family, full_addr): (u16, [u8; 16]) = match subnet.addr {
        IpAddr::V4(v4) => {
            let mut buf = [0u8; 16];
            buf[..4].copy_from_slice(&v4.octets());
            (1, buf)
        }
        IpAddr::V6(v6) => (2, v6.octets()),
    };
    let prefix_len = subnet.prefix_len;
    let addr_bytes = if family == 1 {
        &full_addr[..4]
    } else {
        &full_addr[..]
    };
    let byte_count = (prefix_len as usize).div_ceil(8).min(addr_bytes.len());
    let addr_truncated = &addr_bytes[..byte_count];

    // ECS data: family(2) + source_prefix_len(1) + scope_prefix_len(1) + address bytes
    let data_len = 4 + byte_count;
    let mut opt = Vec::with_capacity(4 + data_len);
    opt.extend_from_slice(&ECS_OPTION_CODE.to_be_bytes()); // option code
    opt.extend_from_slice(&(data_len as u16).to_be_bytes()); // option length
    opt.extend_from_slice(&family.to_be_bytes());
    opt.push(prefix_len);
    opt.push(0); // scope prefix len = 0 in queries
    opt.extend_from_slice(addr_truncated);
    opt
}
