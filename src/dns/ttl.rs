use smallvec::SmallVec;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// `(byte_offset_of_ttl_field, original_clamped_ttl)` pairs collected from all RR sections.
/// Offsets fit in u32 since DNS packets are at most 65 535 bytes; halves the per-pair size
/// vs `(usize, u32)` on 64-bit targets (8 bytes instead of 16).
pub type TtlOffsets = SmallVec<[(u32, u32); 8]>;

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

/// Parse one resource record at `pos`, returning `(rr_type, class, ttl, rdata_start, rr_end)`.
/// Compression-aware via `skip_name`; returns `None` on any out-of-bounds read.
fn parse_rr(packet: &[u8], pos: usize) -> Option<(u16, u16, u32, usize, usize)> {
    let name_end = super::skip_name(packet, pos)?;
    if name_end + 10 > packet.len() {
        return None;
    }
    let rr_type = u16::from_be_bytes([packet[name_end], packet[name_end + 1]]);
    let class = u16::from_be_bytes([packet[name_end + 2], packet[name_end + 3]]);
    let ttl = u32::from_be_bytes([
        packet[name_end + 4],
        packet[name_end + 5],
        packet[name_end + 6],
        packet[name_end + 7],
    ]);
    let rdlen = u16::from_be_bytes([packet[name_end + 8], packet[name_end + 9]]) as usize;
    let rdata_start = name_end + 10;
    let rr_end = rdata_start + rdlen;
    if rr_end > packet.len() {
        return None;
    }
    Some((rr_type, class, ttl, rdata_start, rr_end))
}

/// Collapse a CNAME chain in an A/AAAA response down to the final address records,
/// renamed to the query name (RouteDNS-style "response collapse").  For example,
/// a chain `www.x.com CNAME …; … A 1.2.3.4` becomes `www.x.com A 1.2.3.4`, keeping
/// each address record's own TTL.
///
/// Returns `None` — leaving the caller to use the original response — when there is
/// nothing to collapse: not an A/AAAA query, no CNAME in the answer, no address
/// record of the queried type, a truncated response, or a malformed packet.
///
/// Restricted to A/AAAA because their RDATA is a raw address with no embedded
/// (possibly compressed) domain names, so it can be copied verbatim.  Owner names
/// are emitted as a compression pointer to the question's QNAME (offset 12).  The
/// single EDNS OPT record, if present, is preserved; the authority section and any
/// other additional records (and all CNAME/RRSIG records) are dropped.
pub fn collapse_cname_chain(packet: &[u8], question_end: usize) -> Option<Vec<u8>> {
    if packet.len() < 12 || question_end < 16 || question_end > packet.len() {
        return None;
    }
    if super::is_truncated(packet) {
        return None;
    }
    // QTYPE is the two bytes preceding QCLASS at the end of the question.
    let qtype = u16::from_be_bytes([packet[question_end - 4], packet[question_end - 3]]);
    if qtype != 1 && qtype != 28 {
        return None;
    }

    let an = u16::from_be_bytes([packet[6], packet[7]]) as usize;
    let ns = u16::from_be_bytes([packet[8], packet[9]]) as usize;
    let ar = u16::from_be_bytes([packet[10], packet[11]]) as usize;
    if an == 0 {
        return None;
    }

    let mut pos = question_end;
    let mut saw_cname = false;
    // (ttl, class, rdata_start, rdata_end) for each address record of the queried type.
    let mut kept: SmallVec<[(u32, u16, usize, usize); 4]> = SmallVec::new();
    for _ in 0..an {
        let (rr_type, class, ttl, rdata_start, rr_end) = parse_rr(packet, pos)?;
        if rr_type == 5 {
            saw_cname = true;
        } else if rr_type == qtype {
            kept.push((ttl, class, rdata_start, rr_end));
        }
        pos = rr_end;
    }
    // Only collapse a genuine chain: a CNAME must have been present and resolved to
    // at least one address of the queried type.
    if !saw_cname || kept.is_empty() {
        return None;
    }

    // Skip the authority section, then locate the EDNS OPT record to preserve it.
    for _ in 0..ns {
        pos = parse_rr(packet, pos)?.4;
    }
    let mut opt: Option<&[u8]> = None;
    for _ in 0..ar {
        let rr_start = pos;
        let (rr_type, _, _, _, rr_end) = parse_rr(packet, pos)?;
        if rr_type == 41 {
            // OPT owner is always root and its RDATA holds no domain names, so the
            // record is self-contained and safe to copy verbatim.
            opt = Some(&packet[rr_start..rr_end]);
        }
        pos = rr_end;
    }

    // Rebuild: header + question, then the collapsed address records, then OPT.
    let arcount: u16 = opt.is_some() as u16;
    let mut out =
        Vec::with_capacity(question_end + kept.len() * 28 + opt.map_or(0, |o| o.len()));
    out.extend_from_slice(&packet[..question_end]);
    out[6..8].copy_from_slice(&(kept.len() as u16).to_be_bytes()); // ANCOUNT
    out[8..10].copy_from_slice(&0u16.to_be_bytes()); // NSCOUNT
    out[10..12].copy_from_slice(&arcount.to_be_bytes()); // ARCOUNT
    for (ttl, class, rdata_start, rdata_end) in kept {
        out.extend_from_slice(&[0xC0, 0x0C]); // owner = pointer to QNAME at offset 12
        out.extend_from_slice(&qtype.to_be_bytes());
        out.extend_from_slice(&class.to_be_bytes());
        out.extend_from_slice(&ttl.to_be_bytes());
        out.extend_from_slice(&((rdata_end - rdata_start) as u16).to_be_bytes());
        out.extend_from_slice(&packet[rdata_start..rdata_end]);
    }
    if let Some(o) = opt {
        out.extend_from_slice(o);
    }
    Some(out)
}

/// Compute the effective cache TTL and per-RR TTL offsets for a DNS response.
///
/// Returns `(entry_ttl, offset_ttl_pairs)` where:
/// - `entry_ttl`: minimum clamped TTL across answer-section RRs (or the SOA-derived value for
///   NODATA/NXDOMAIN); governs when the cache entry expires.
/// - `offset_ttl_pairs`: `(byte_offset_of_ttl_field, clamped_rr_ttl)` for every non-OPT RR in
///   all sections.  At serve time each RR is patched to `clamped_rr_ttl - elapsed` so that
///   clients receive an accurate countdown rather than the uniform minimum.
///
/// `min_ttl`/`max_ttl` are applied per-RR; `nodata_ttl` is the fallback when no SOA is present.
/// Negative (NXDOMAIN/NODATA) TTLs are additionally capped at 10800 s per RFC 2308 §5.
pub fn effective_ttl_and_offsets(
    packet: &[u8],
    question_end: usize,
    nodata_ttl: u32,
    min_ttl: u32,
    max_ttl: u32,
) -> Option<(u32, TtlOffsets)> {
    if !is_good_reply(packet) {
        return None;
    }

    let an = u16::from_be_bytes([packet[6], packet[7]]) as usize;
    let ns = u16::from_be_bytes([packet[8], packet[9]]) as usize;
    let ar = u16::from_be_bytes([packet[10], packet[11]]) as usize;
    let (offset_ttl_pairs, an_offsets, soa_ttl) =
        ttl_offsets_and_soa(packet, question_end, an, ns, ar)?;

    // Apply per-RR min/max clamping.
    let clamp = |raw: u32| -> u32 {
        let v = raw.max(min_ttl);
        if max_ttl > 0 {
            v.min(max_ttl)
        } else {
            v
        }
    };

    if an == 0 {
        // NODATA / NXDOMAIN: RFC 2308 §5 mandates min(SOA_TTL, SOA_MINIMUM), capped at 10800 s.
        let soa = soa_ttl.unwrap_or(nodata_ttl).min(10800);
        let effective = clamp(soa);
        // All RRs in the authority/additional sections share the SOA-derived TTL.
        let offsets = offset_ttl_pairs
            .iter()
            .map(|&(off, _)| (off, effective))
            .collect();
        Some((effective, offsets))
    } else {
        // Positive response: clamp each RR independently.
        let offsets: TtlOffsets = offset_ttl_pairs
            .iter()
            .map(|&(off, raw)| (off, clamp(raw)))
            .collect();
        // Entry lifetime is driven by the minimum of the answer-section TTLs.
        let entry_ttl = offsets[..an_offsets]
            .iter()
            .map(|&(_, t)| t)
            .min()
            .unwrap_or(nodata_ttl);
        Some((entry_ttl, offsets))
    }
}

/// Patch each RR's TTL field to `original_clamped_ttl − elapsed_secs` (per-RR countdown).
/// Used for fresh cache entries so clients see an accurate remaining-lifetime for every RR.
pub fn patch_ttls_at(packet: &mut [u8], offsets: &[(u32, u32)], elapsed: u32) {
    for &(offset, original_ttl) in offsets {
        let remaining = original_ttl.saturating_sub(elapsed);
        let offset = offset as usize;
        if offset + 4 <= packet.len() {
            packet[offset..offset + 4].copy_from_slice(&remaining.to_be_bytes());
        }
    }
}

/// Single pass over all RR sections.
/// Returns `None` if any RR is malformed or truncated (so callers reject the whole response).
/// On success returns:
/// - `offset_ttl_pairs`: `(ttl_byte_offset, raw_rr_ttl)` for all non-OPT records (all sections).
/// - `an_offsets`: how many of those pairs belong to the answer section.
/// - `soa_ttl`: when the authority section has a SOA, `min(SOA_TTL, SOA_MINIMUM)` per RFC 2308.
fn ttl_offsets_and_soa(
    packet: &[u8],
    question_end: usize,
    an: usize,
    ns: usize,
    ar: usize,
) -> Option<(TtlOffsets, usize, Option<u32>)> {
    let total = an + ns + ar;
    let mut offsets: TtlOffsets = SmallVec::new();
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
        let rr_ttl = u32::from_be_bytes([
            packet[fixed + 4],
            packet[fixed + 5],
            packet[fixed + 6],
            packet[fixed + 7],
        ]);
        let rdlen = u16::from_be_bytes([packet[fixed + 8], packet[fixed + 9]]) as usize;
        let rdata = fixed + 10;
        let rdata_end = rdata + rdlen;
        if rdata_end > packet.len() {
            return None;
        }

        // OPT (type 41): its TTL field encodes EDNS version + extended RCODE, not a real TTL.
        if rr_type != 41 {
            offsets.push(((fixed + 4) as u32, rr_ttl));
            if i < an {
                an_offsets += 1;
            }
        }

        // SOA in the authority section: extract min(rr_ttl, MINIMUM) for RFC 2308 NODATA/NXDOMAIN.
        if rr_type == 6 && soa_ttl.is_none() && i >= an && i < an + ns {
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

#[cfg(test)]
#[path = "tests/ttl.rs"]
mod collapse_tests;
