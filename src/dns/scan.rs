use smallvec::SmallVec;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

pub fn rcode(packet: &[u8]) -> u8 {
    if packet.len() < 4 {
        0
    } else {
        packet[3] & 0x0f
    }
}

fn is_good_reply(packet: &[u8]) -> bool {
    if !super::is_reply(packet) || packet.len() < 12 {
        return false;
    }
    let rc = rcode(packet);
    rc == 0 || rc == 3
}

pub fn answer_ips(packet: &[u8], question_end: usize) -> SmallVec<[IpAddr; 4]> {
    let mut ips = SmallVec::new();
    if packet.len() < 12 || question_end > packet.len() {
        return ips;
    }

    let an = u16::from_be_bytes([packet[6], packet[7]]) as usize;
    let mut pos = question_end;

    for _ in 0..an {
        let Some(name_end) = super::skip_name(packet, pos) else {
            return ips;
        };
        pos = name_end;
        if pos + 10 > packet.len() {
            return ips;
        }
        let rr_type = u16::from_be_bytes([packet[pos], packet[pos + 1]]);
        let rdlen = u16::from_be_bytes([packet[pos + 8], packet[pos + 9]]) as usize;
        let rdata = pos + 10;
        let end = rdata + rdlen;
        if end > packet.len() {
            return ips;
        }
        match (rr_type, rdlen) {
            (1, 4) => ips.push(IpAddr::V4(Ipv4Addr::new(
                packet[rdata],
                packet[rdata + 1],
                packet[rdata + 2],
                packet[rdata + 3],
            ))),
            (28, 16) => {
                let mut octets = [0u8; 16];
                octets.copy_from_slice(&packet[rdata..end]);
                ips.push(IpAddr::V6(Ipv6Addr::from(octets)));
            }
            _ => {}
        }
        pos = end;
    }

    ips
}

pub fn effective_ttl_and_offsets(
    packet: &[u8],
    question_end: usize,
    nodata_ttl: u32,
    min_ttl: u32,
    max_ttl: u32,
) -> Option<(u32, SmallVec<[usize; 8]>)> {
    if !is_good_reply(packet) {
        return None;
    }

    let an = u16::from_be_bytes([packet[6], packet[7]]) as usize;
    let ns = u16::from_be_bytes([packet[8], packet[9]]) as usize;
    let ar = u16::from_be_bytes([packet[10], packet[11]]) as usize;
    // Single pass: collect TTL offsets and, when the answer section is empty,
    // the SOA TTL from the authority section (RFC 2308).
    let (offsets, an_offsets, soa_ttl) = ttl_offsets_and_soa(packet, question_end, an, ns, ar)?;

    // NODATA / NXDOMAIN (no answer records): RFC 2308 mandates min(SOA_TTL, SOA_MINIMUM).
    let raw_ttl = if an == 0 {
        soa_ttl.unwrap_or(nodata_ttl)
    } else {
        // Use only answer-section offsets; authority/additional may carry glue with lower TTLs.
        let mut min_seen = u32::MAX;
        for &off in &offsets[..an_offsets] {
            if off + 4 <= packet.len() {
                let t = u32::from_be_bytes(packet[off..off + 4].try_into().ok()?);
                min_seen = min_seen.min(t);
            }
        }
        if min_seen == u32::MAX {
            nodata_ttl
        } else {
            min_seen
        }
    };

    let mut ttl = raw_ttl.max(min_ttl);
    if max_ttl > 0 {
        ttl = ttl.min(max_ttl);
    }
    Some((ttl, offsets))
}

pub fn patch_ttls_at(packet: &mut [u8], offsets: &[usize], ttl: u32) {
    let ttl_bytes = ttl.to_be_bytes();
    for &offset in offsets {
        if offset + 4 <= packet.len() {
            packet[offset..offset + 4].copy_from_slice(&ttl_bytes);
        }
    }
}

/// Single pass over all RR sections.
/// Returns `None` if any RR is malformed or truncated (so callers reject the whole response).
/// On success returns:
/// - `offsets`: TTL byte positions for all non-OPT records (all sections, used for patching).
/// - `an_offsets`: how many of those offsets belong to the answer section.
/// - `soa_ttl`: when the authority section has a SOA, `min(SOA_TTL, SOA_MINIMUM)` per RFC 2308.
fn ttl_offsets_and_soa(
    packet: &[u8],
    question_end: usize,
    an: usize,
    ns: usize,
    ar: usize,
) -> Option<(SmallVec<[usize; 8]>, usize, Option<u32>)> {
    let total = an + ns + ar;
    let mut offsets: SmallVec<[usize; 8]> = SmallVec::new();
    let mut an_offsets = 0usize;
    let mut soa_ttl: Option<u32> = None;

    if packet.len() < 12 || question_end > packet.len() {
        return None;
    }

    let mut pos = question_end;

    for i in 0..total {
        let fixed = super::skip_name(packet, pos)?;
        if fixed + 10 > packet.len() {
            return None;
        }
        let rr_type = u16::from_be_bytes([packet[fixed], packet[fixed + 1]]);
        let rdlen = u16::from_be_bytes([packet[fixed + 8], packet[fixed + 9]]) as usize;
        let rdata = fixed + 10;
        let rdata_end = rdata + rdlen;
        if rdata_end > packet.len() {
            return None;
        }

        // OPT (type 41): its TTL field encodes EDNS version + extended RCODE, not a real TTL.
        if rr_type != 41 {
            offsets.push(fixed + 4);
            if i < an {
                an_offsets += 1;
            }
        }

        // SOA in the authority section: extract min(rr_ttl, MINIMUM) for RFC 2308 NODATA/NXDOMAIN.
        if rr_type == 6 && soa_ttl.is_none() && i >= an && i < an + ns {
            let rr_ttl = u32::from_be_bytes([
                packet[fixed + 4],
                packet[fixed + 5],
                packet[fixed + 6],
                packet[fixed + 7],
            ]);
            // SOA RDATA: MNAME + RNAME + serial(4) + refresh(4) + retry(4) + expire(4) + minimum(4)
            if let Some(minimum) = extract_soa_minimum(packet, rdata, rdata_end) {
                soa_ttl = Some(rr_ttl.min(minimum));
            }
        }

        pos = rdata_end;
    }

    Some((offsets, an_offsets, soa_ttl))
}

fn extract_soa_minimum(packet: &[u8], rdata: usize, rdata_end: usize) -> Option<u32> {
    let p = super::skip_name(packet, rdata)?; // past MNAME
    let p = super::skip_name(packet, p)?; // past RNAME
    if p + 20 > rdata_end {
        return None;
    }
    Some(u32::from_be_bytes([
        packet[p + 16],
        packet[p + 17],
        packet[p + 18],
        packet[p + 19],
    ]))
}
