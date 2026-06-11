//! DNS packet parsing, construction, and TTL patching.
//!
//! Responsibilities are split into focused submodules:
//! - [`query`]: query parsing, qname extraction, fast query info
//! - [`builder`]: response construction (empty, NXDOMAIN, A/AAAA/CNAME/rewrite)
//! - [`scan`]: TTL scanning / patching, SOA negative-TTL, answer IP extraction
//! - [`ecs`]: EDNS Client Subnet stripping and injection

mod builder;
mod ecs;
mod query;
mod scan;

// Shared types.

#[derive(Debug, Clone)]
pub struct QueryInfo {
    pub id: u16,
    pub qname: std::sync::Arc<str>,
    pub qtype: u16,
    pub question_end: usize,
}

#[derive(Debug, Clone, Copy)]
pub struct FastQueryInfo {
    pub id: u16,
    pub qtype: u16,
    pub question_end: usize,
}

// Re-exports.

pub use builder::{empty_reply, notimp_opcode_reply, notimp_reply, servfail_reply};
pub use ecs::{inject_or_replace_ecs, strip_edns_ecs};
pub use query::{get_id, is_reply, is_truncated, parse_query_fast, parse_query_from_fast, set_id};
pub use scan::{answer_ips, effective_ttl_and_offsets, patch_ttls_at, rcode};

// ── Query variant ──────────────────────────────────────────────────────────

/// The EDNS properties of a DNS query that determine which cached response can
/// be used to answer it.
///
/// Two queries with identical QNAME/QTYPE/QCLASS **and** identical `QueryVariant`
/// may share a cache entry.  Properties that do not change response content —
/// client DNS ID, EDNS UDP payload size, EDNS PADDING — are excluded.
///
/// ECS source subnet is included so that `ecs=forward` clients from different
/// subnets receive subnet-specific responses rather than sharing a cache entry.
/// This causes one cache entry per unique client subnet for `ecs=strip` upstreams;
/// ECS-mode-aware normalisation (keying by the stripped variant) is a Phase 2 item.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct QueryVariant {
    /// Client presented an EDNS OPT record.
    pub has_opt: bool,
    /// DNSSEC OK bit — the client wants DNSSEC RRs in the response.
    pub do_bit: bool,
    /// EDNS version declared by the client.
    pub edns_version: u8,
    /// RD (recursion desired) bit from the query flags.
    pub rd: bool,
    /// AD (authenticated data) bit from the query flags.
    pub ad: bool,
    /// CD (checking disabled) bit from the query flags.
    pub cd: bool,
    /// Normalised ECS source network from the client query, or `None` when no
    /// ECS option was present.
    pub ecs_src: Option<EcsSrc>,
}

/// Normalised ECS source network extracted from a client query.
///
/// Bits beyond `prefix_len` are zeroed so that structurally different but
/// semantically identical ECS options (e.g. trailing zero bytes) compare equal.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct EcsSrc {
    /// Network address as a 128-bit integer (IPv4 occupies the low 32 bits).
    pub addr: u128,
    /// Source prefix length.
    pub prefix_len: u8,
}

impl QueryVariant {
    fn no_edns(rd: bool, ad: bool, cd: bool) -> Self {
        Self { has_opt: false, do_bit: false, edns_version: 0, rd, ad, cd, ecs_src: None }
    }
}

/// Extract the [`QueryVariant`] from a DNS query packet.
///
/// Returns a default (no-EDNS) variant for malformed or undersized packets.
/// The `question_end` argument must point to the byte immediately after the
/// question section (QNAME + QTYPE + QCLASS).
pub fn extract_variant(packet: &[u8], question_end: usize) -> QueryVariant {
    if packet.len() < 12 {
        return QueryVariant::no_edns(false, false, false);
    }
    // Byte 2: QR(1) Opcode(4) AA(1) TC(1) RD(1)
    // Byte 3: RA(1) Z(1) AD(1) CD(1) RCODE(4)
    let rd = (packet[2] & 0x01) != 0;
    let ad = (packet[3] & 0x20) != 0;
    let cd = (packet[3] & 0x10) != 0;

    let arcount = u16::from_be_bytes([packet[10], packet[11]]) as usize;
    if arcount == 0 || question_end >= packet.len() {
        return QueryVariant::no_edns(rd, ad, cd);
    }

    // Walk additional records looking for OPT (type 41).
    let mut pos = question_end;
    for _ in 0..arcount {
        let Some(name_end) = skip_name(packet, pos) else { break };
        // OPT fixed header: type(2) class(2) ttl(4) rdlen(2) = 10 bytes
        if name_end + 10 > packet.len() {
            break;
        }
        let rr_type = u16::from_be_bytes([packet[name_end], packet[name_end + 1]]);
        let rdlen = u16::from_be_bytes([packet[name_end + 8], packet[name_end + 9]]) as usize;
        let rdata_start = name_end + 10;
        let Some(rdata_end) = rdata_start.checked_add(rdlen).filter(|&e| e <= packet.len()) else {
            break;
        };

        if rr_type == 41 {
            // OPT TTL layout: ext-rcode(1) version(1) flags(2); DO is bit 15 of flags.
            let edns_version = packet[name_end + 5];
            let do_bit = (packet[name_end + 6] & 0x80) != 0;
            let ecs_src = extract_ecs_src(packet.get(rdata_start..rdata_end).unwrap_or(&[]));
            return QueryVariant { has_opt: true, do_bit, edns_version, rd, ad, cd, ecs_src };
        }

        pos = rdata_end;
    }

    QueryVariant::no_edns(rd, ad, cd)
}

/// Scan OPT RDATA for the ECS option (code 0x000b) and return its normalised
/// source network.  Returns `None` when ECS is absent or malformed.
fn extract_ecs_src(rdata: &[u8]) -> Option<EcsSrc> {
    let mut pos = 0usize;
    while pos + 4 <= rdata.len() {
        let code = u16::from_be_bytes([rdata[pos], rdata[pos + 1]]);
        let opt_len = u16::from_be_bytes([rdata[pos + 2], rdata[pos + 3]]) as usize;
        pos += 4;
        let end = pos + opt_len;
        if end > rdata.len() {
            break;
        }
        if code == 0x000b && opt_len >= 4 {
            // ECS OPTION-DATA: FAMILY(2) SOURCE-PREFIX-LENGTH(1) SCOPE-PREFIX-LENGTH(1) ADDRESS(var)
            let family = u16::from_be_bytes([rdata[pos], rdata[pos + 1]]);
            let prefix_len = rdata[pos + 2];
            let addr_data = rdata.get(pos + 4..end).unwrap_or(&[]);
            let (addr, prefix_len) = match family {
                1 => {
                    let mut buf = [0u8; 4];
                    let n = addr_data.len().min(4);
                    buf[..n].copy_from_slice(&addr_data[..n]);
                    let plen = prefix_len.min(32);
                    let raw = u32::from_be_bytes(buf);
                    let mask = if plen == 0 { 0u32 } else { !0u32 << (32 - plen) };
                    (u128::from(raw & mask), plen)
                }
                2 => {
                    let mut buf = [0u8; 16];
                    let n = addr_data.len().min(16);
                    buf[..n].copy_from_slice(&addr_data[..n]);
                    let plen = prefix_len.min(128);
                    let raw = u128::from_be_bytes(buf);
                    let mask = if plen == 0 { 0u128 } else { !0u128 << (128 - plen) };
                    (raw & mask, plen)
                }
                _ => return None,
            };
            return Some(EcsSrc { addr, prefix_len });
        }
        pos = end;
    }
    None
}

/// Return the byte offset immediately after the question section (QNAME + QTYPE + QCLASS).
/// Works on both query and response packets.  Returns `None` for malformed input.
pub fn question_end(packet: &[u8]) -> Option<usize> {
    if packet.len() < 12 {
        return None;
    }
    let end = skip_name(packet, 12)?;
    if end + 4 > packet.len() {
        return None;
    }
    Some(end + 4)
}

/// Case-insensitive comparison of two DNS question wire-byte slices (`packet[12..question_end]`).
/// Label bytes are compared case-insensitively; QTYPE and QCLASS (last 4 bytes) are exact.
pub fn questions_match(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() || a.len() < 4 {
        return false;
    }
    // QTYPE + QCLASS must match exactly.
    if a[a.len() - 4..] != b[b.len() - 4..] {
        return false;
    }
    // Walk QNAME labels with case-insensitive byte comparison.
    let mut pos = 0usize;
    let qname_end = a.len() - 4;
    loop {
        if pos > qname_end {
            return false;
        }
        let la = match a.get(pos) {
            Some(&v) => v,
            None => return false,
        };
        let lb = match b.get(pos) {
            Some(&v) => v,
            None => return false,
        };
        if la != lb {
            return false;
        }
        pos += 1;
        if la == 0 {
            return true;
        }
        let label_len = la as usize;
        for _ in 0..label_len {
            let ba = match a.get(pos) {
                Some(&v) => v,
                None => return false,
            };
            let bb = match b.get(pos) {
                Some(&v) => v,
                None => return false,
            };
            if !ba.eq_ignore_ascii_case(&bb) {
                return false;
            }
            pos += 1;
        }
    }
}

// Shared internal helpers.

/// Walk a compressed or uncompressed DNS name starting at `pos`.
/// Returns the byte offset immediately after the name, or `None` on malformed input.
fn skip_name(packet: &[u8], mut pos: usize) -> Option<usize> {
    loop {
        let len = *packet.get(pos)?;
        pos += 1;
        if len == 0 {
            return Some(pos);
        }
        if len & 0xc0 == 0xc0 {
            packet.get(pos)?;
            return Some(pos + 1);
        }
        if len & 0xc0 != 0 {
            return None;
        }
        pos += len as usize;
        if pos > packet.len() {
            return None;
        }
    }
}
