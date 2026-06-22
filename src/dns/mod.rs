//! DNS packet parsing, construction, and TTL patching.
//!
//! Responsibilities are split into focused submodules:
//! - [`query`]: query parsing, qname extraction, fast query info
//! - [`builder`]: response construction (empty, NXDOMAIN, A/AAAA/CNAME/rewrite)
//! - [`ttl`]: TTL scanning / patching, SOA negative-TTL, answer IP extraction
//! - [`ecs`]: EDNS Client Subnet stripping and injection

mod builder;
mod ecs;
mod query;
mod ttl;

use crate::hasher::Fnv1a;
use bytes::{Bytes, BytesMut};
use smallvec::SmallVec;

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

pub use builder::{a_reply, aaaa_reply, cname_reply, cname_with_chase_reply, empty_reply, encode_dns_name, notimp_opcode_reply, notimp_reply, rcode_reply, servfail_reply, synthetic_query};
pub use ecs::{inject_or_replace_ecs, strip_edns_ecs, strip_opt_rdata};
pub use query::{get_id, is_reply, is_truncated, parse_query_fast, parse_query_from_fast, set_id};
pub use ttl::{answer_ips, collapse_cname_chain, effective_ttl_and_offsets, patch_ttls_at, rcode};

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
///
/// `extra_opts_hash` covers every other EDNS option code (e.g. COOKIE=10,
/// NSID=3, DAU/DHU/N3U=5/6/7, CHAIN=13) whose presence or absence may cause
/// the upstream to return a different response.  Two queries with different
/// non-ECS/non-PADDING option sets are placed in different cache buckets.
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
    /// FNV-1a hash of the sorted set of non-ECS, non-PADDING EDNS option codes
    /// present in the query.  Zero when no such options exist.
    pub extra_opts_hash: u64,
}

/// Normalised ECS source network extracted from a client query.
///
/// Bits beyond `prefix_len` are zeroed so that structurally different but
/// semantically identical ECS options (e.g. trailing zero bytes) compare equal.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct EcsSrc {
    /// Network address as big-endian bytes (IPv4 uses the low 4 bytes: bytes 12–15).
    pub addr: [u8; 16],
    /// Source prefix length.
    pub prefix_len: u8,
}

impl QueryVariant {
    fn no_edns(rd: bool, ad: bool, cd: bool) -> Self {
        Self {
            has_opt: false,
            do_bit: false,
            edns_version: 0,
            rd,
            ad,
            cd,
            ecs_src: None,
            extra_opts_hash: 0,
        }
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
        let Some(name_end) = skip_name(packet, pos) else {
            break;
        };
        // OPT fixed header: type(2) class(2) ttl(4) rdlen(2) = 10 bytes
        if name_end + 10 > packet.len() {
            break;
        }
        let rr_type = u16::from_be_bytes([packet[name_end], packet[name_end + 1]]);
        let rdlen = u16::from_be_bytes([packet[name_end + 8], packet[name_end + 9]]) as usize;
        let rdata_start = name_end + 10;
        let Some(rdata_end) = rdata_start
            .checked_add(rdlen)
            .filter(|&e| e <= packet.len())
        else {
            break;
        };

        if rr_type == 41 {
            // OPT TTL layout: ext-rcode(1) version(1) flags(2); DO is bit 15 of flags.
            let edns_version = packet[name_end + 5];
            let do_bit = (packet[name_end + 6] & 0x80) != 0;
            let (ecs_src, extra_opts_hash) =
                extract_opt_data(packet.get(rdata_start..rdata_end).unwrap_or(&[]));
            return QueryVariant {
                has_opt: true,
                do_bit,
                edns_version,
                rd,
                ad,
                cd,
                ecs_src,
                extra_opts_hash,
            };
        }

        pos = rdata_end;
    }

    QueryVariant::no_edns(rd, ad, cd)
}

/// Walk OPT RDATA; return the normalised ECS source network and a hash of any
/// other option codes that influence the upstream response.
///
/// The hash is FNV-1a over the sorted set of option codes, excluding:
/// - ECS (`0x000b`) — handled separately via `ecs_src`
/// - PADDING (`12`) — does not affect response content
///
/// Zero is returned when no such options are present.
fn extract_opt_data(rdata: &[u8]) -> (Option<EcsSrc>, u64) {
    let mut ecs_src = None;
    // Keep the common case allocation-free while still hashing every option code
    // so unusually option-heavy queries cannot collide after a fixed cutoff.
    let mut codes = SmallVec::<[u16; 8]>::new();

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
            ecs_src = parse_ecs_src(&rdata[pos..end]);
        } else if code != 12 {
            // Collect unknown/non-padding option codes.
            codes.push(code);
        }
        pos = end;
    }

    let extra_opts_hash = if codes.is_empty() {
        0
    } else {
        codes.sort_unstable();
        let mut h = Fnv1a::new();
        for &c in &codes {
            h.write(&c.to_le_bytes());
        }
        h.finish()
    };

    (ecs_src, extra_opts_hash)
}

/// Parse the ECS OPTION-DATA (everything after the 4-byte option header).
/// OPTION-DATA layout: FAMILY(2) SOURCE-PREFIX-LENGTH(1) SCOPE-PREFIX-LENGTH(1) ADDRESS(var)
fn parse_ecs_src(opt_data: &[u8]) -> Option<EcsSrc> {
    if opt_data.len() < 4 {
        return None;
    }
    let family = u16::from_be_bytes([opt_data[0], opt_data[1]]);
    let prefix_len = opt_data[2];
    let addr_data = &opt_data[4..];
    let (addr, prefix_len) = match family {
        1 => {
            let mut raw = [0u8; 4];
            let n = addr_data.len().min(4);
            raw[..n].copy_from_slice(&addr_data[..n]);
            let plen = prefix_len.min(32);
            let masked = u32::from_be_bytes(raw)
                & if plen == 0 {
                    0u32
                } else {
                    !0u32 << (32 - plen)
                };
            let mut addr = [0u8; 16];
            addr[12..].copy_from_slice(&masked.to_be_bytes());
            (addr, plen)
        }
        2 => {
            let mut raw = [0u8; 16];
            let n = addr_data.len().min(16);
            raw[..n].copy_from_slice(&addr_data[..n]);
            let plen = prefix_len.min(128);
            let masked = u128::from_be_bytes(raw)
                & if plen == 0 {
                    0u128
                } else {
                    !0u128 << (128 - plen)
                };
            (masked.to_be_bytes(), plen)
        }
        _ => return None,
    };
    Some(EcsSrc { addr, prefix_len })
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

/// Returns the maximum UDP response size this client will accept.
///
/// For non-EDNS clients (no OPT record), the RFC 1035 default of 512 bytes applies.
/// For EDNS clients the value is the UDP payload size field from their OPT record,
/// clamped to a minimum of 512 so a misconfigured zero never produces an empty stub.
pub fn client_udp_payload_size(packet: &[u8], question_end: usize) -> u16 {
    const MIN: u16 = 512;
    if packet.len() < 12 {
        return MIN;
    }
    let arcount = u16::from_be_bytes([packet[10], packet[11]]) as usize;
    if arcount == 0 || question_end >= packet.len() {
        return MIN;
    }
    let mut pos = question_end;
    for _ in 0..arcount {
        let Some(name_end) = skip_name(packet, pos) else {
            break;
        };
        if name_end + 10 > packet.len() {
            break;
        }
        let rr_type = u16::from_be_bytes([packet[name_end], packet[name_end + 1]]);
        let rdlen = u16::from_be_bytes([packet[name_end + 8], packet[name_end + 9]]) as usize;
        let Some(rdata_end) = (name_end + 10)
            .checked_add(rdlen)
            .filter(|&e| e <= packet.len())
        else {
            break;
        };
        if rr_type == 41 {
            // OPT CLASS field encodes the sender's UDP payload size.
            let size = u16::from_be_bytes([packet[name_end + 2], packet[name_end + 3]]);
            return size.max(MIN);
        }
        pos = rdata_end;
    }
    MIN
}

/// If `resp` fits within the client's UDP payload limit it is returned unchanged (zero-copy).
/// If it exceeds the limit, returns a minimal TC=1 stub containing only the DNS header and
/// question section so the client retries over TCP (RFC 1035 §4.2.1).
///
/// `resp` must already have the correct client ID and original question case applied;
/// those bytes are carried into the TC stub as-is.
pub fn maybe_truncate_for_udp(resp: Bytes, query: &[u8]) -> Bytes {
    let qe = match question_end(query) {
        Some(v) => v,
        None => return resp, // malformed query — can't determine limit, pass through
    };
    let max = client_udp_payload_size(query, qe) as usize;
    if resp.len() <= max {
        return resp; // fast path: no truncation needed
    }
    // Response exceeds the client's UDP limit.  Build a TC=1 stub by keeping
    // only the header and question section (dropping all resource records).
    if resp.len() < qe || qe < 12 {
        return resp; // unexpected state — don't corrupt
    }
    let mut stub = BytesMut::with_capacity(qe);
    stub.extend_from_slice(&resp[..qe]);
    stub[2] |= 0x02; // set TC (truncated) bit
    stub[6] = 0;
    stub[7] = 0; // ANCOUNT = 0
    stub[8] = 0;
    stub[9] = 0; // NSCOUNT = 0
    stub[10] = 0;
    stub[11] = 0; // ARCOUNT = 0
    stub.freeze()
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

/// Apply random QNAME case mixing to an outgoing query (DNS-0x20).
/// `seed` is mixed from upstream TXID + generation counter for per-request uniqueness.
pub fn mix_qname_case(pkt: &mut [u8], question_end: usize, seed: u64) {
    if pkt.len() < 13 || question_end <= 12 {
        return;
    }
    let mut pos = 12usize;
    let mut rng = seed.wrapping_add(0x9e37_79b9_7f4a_7c15);
    while pos + 1 < question_end.saturating_sub(4) {
        let b = match pkt.get(pos) {
            Some(&v) => v,
            None => return,
        };
        pos += 1;
        let len = b as usize;
        if len == 0 {
            break;
        }
        if len & 0xc0 != 0 {
            return;
        }
        for _ in 0..len {
            rng ^= rng << 13;
            rng ^= rng >> 7;
            rng ^= rng << 17;
            if pos < question_end {
                let byte = pkt[pos];
                if byte.is_ascii_alphabetic() && rng & 1 != 0 {
                    pkt[pos] ^= 0x20;
                }
            }
            pos += 1;
        }
    }
}

/// Verify that the QNAME in the response question section case-matches what we sent.
/// Returns `true` (accept) when QNAME bytes match exactly OR response is all-lowercase.
/// Returns `false` (reject) when the response has mixed case that does NOT match ours.
pub fn verify_qname_case_echo(
    sent: &[u8],
    sent_qend: usize,
    recv: &[u8],
    recv_qend: usize,
) -> bool {
    let sent_q = match sent.get(12..sent_qend.saturating_sub(4)) {
        Some(s) => s,
        None => return true,
    };
    let recv_q = match recv.get(12..recv_qend.saturating_sub(4)) {
        Some(s) => s,
        None => return true,
    };
    if sent_q.len() != recv_q.len() {
        return true;
    }

    let mut pos = 0usize;
    while let Some(&v) = sent_q.get(pos) {
        let len = v as usize;
        if len == 0 {
            break;
        }
        if len & 0xc0 != 0 {
            break;
        }
        pos += 1;
        for i in 0..len {
            let s = match sent_q.get(pos + i) {
                Some(&v) => v,
                None => return true,
            };
            let r = match recv_q.get(pos + i) {
                Some(&v) => v,
                None => return true,
            };
            if s != r && r != s.to_ascii_lowercase() {
                return false;
            }
        }
        pos += len;
    }
    true
}

/// Extract answer records from a DNS response.
/// Returns a list of (record_type, ttl, rdata_bytes) for each answer record.
/// Silently stops at the first parse error.
pub fn extract_answer_records(resp: &[u8], question_end: usize) -> Vec<(u16, u32, Vec<u8>)> {
    if resp.len() < 12 || question_end > resp.len() {
        return vec![];
    }
    let ancount = u16::from_be_bytes([resp[6], resp[7]]) as usize;
    let mut results = Vec::with_capacity(ancount.min(16));
    let mut offset = question_end;
    for _ in 0..ancount {
        let Some(after_name) = skip_name(resp, offset) else {
            break;
        };
        if after_name + 10 > resp.len() {
            break;
        }
        let rtype = u16::from_be_bytes([resp[after_name], resp[after_name + 1]]);
        // skip CLASS at [+2..+4]
        let ttl = u32::from_be_bytes([
            resp[after_name + 4],
            resp[after_name + 5],
            resp[after_name + 6],
            resp[after_name + 7],
        ]);
        let rdlen = u16::from_be_bytes([resp[after_name + 8], resp[after_name + 9]]) as usize;
        let rdata_start = after_name + 10;
        let rdata_end = rdata_start + rdlen;
        if rdata_end > resp.len() {
            break;
        }
        results.push((rtype, ttl, resp[rdata_start..rdata_end].to_vec()));
        offset = rdata_end;
    }
    results
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

#[cfg(test)]
#[path = "tests/dns.rs"]
mod tests;
