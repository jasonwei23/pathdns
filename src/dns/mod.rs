//! DNS packet parsing, construction, and TTL patching.
//!
//! Responsibilities are split into focused submodules:
//! - [`query`]: query parsing, qname extraction, fast query info
//! - [`builder`]: response construction (empty, NXDOMAIN, A/AAAA/rewrite)
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
    /// The routing qname (lowercased, dot-separated), materialized lazily.
    /// `None` until a consumer that needs the *string* form asks for it —
    /// routing that inspects the name, a cache store, or a querylog event.
    /// A constant-route, cache-off, querylog-off forward never builds it,
    /// saving the `String`→`Arc<str>` allocation per query. Use
    /// `QueryContext::qname_owned`/`ensure_qname` (which fall back to
    /// `dns::qname_from_question`) rather than reading this directly.
    pub qname: Option<std::sync::Arc<str>>,
    pub qtype: u16,
    pub question_end: usize,
    /// Carried over from [`FastQueryInfo`] (see its field docs): lets the
    /// slow-path cache-key computation
    /// (`cache::cache_key_with_variant_from_qname_hash`) resume from the hash
    /// the initial validation scan already produced.
    pub(crate) qname_wire_hash: Fnv1a,
    /// See [`FastQueryInfo::qname_wire_hash_end`].
    pub(crate) qname_wire_hash_end: usize,
    /// This query's [`QueryVariant`], already computed once by the fast path
    /// (`DnsCache::get_into_with_ecs_fallback`, during the cache-miss check
    /// that precedes slow-path dispatch). Carried through here so the slow
    /// path (`exchange_with_dedupe`) can reuse it instead of re-parsing the
    /// same EDNS/ECS bytes a second time.
    pub variant: QueryVariant,
    /// Cache key(s) the fast-path probe already computed
    /// (`cache::CacheProbe`: `(regular_key, stripped_key)`), carried into the
    /// slow path so `exchange_with_dedupe` reuses them instead of recomputing
    /// the key-tail hash. `None` when this `QueryInfo` wasn't produced via the
    /// fast-path miss route, in which case the slow path recomputes. Stored as
    /// raw `u64` (= `cache::CacheKey`) to avoid a `dns`→`cache` type dependency.
    pub(crate) precomputed_cache_keys: Option<(u64, Option<u64>)>,
}

#[derive(Debug, Clone, Copy)]
pub struct FastQueryInfo {
    pub id: u16,
    pub qtype: u16,
    pub question_end: usize,
    /// `Fnv1a::write_qname_wire`-equivalent hash of this query's wire-format
    /// QNAME (lowercased), computed as a byproduct of
    /// `parse_query_fast`'s validation walk over the same bytes. Every
    /// query's cache-key derivation (fast path *and* slow path) resumes from
    /// this hash via `cache::cache_key_with_variant_from_qname_hash`, so the
    /// QNAME is scanned exactly once per query instead of once to validate
    /// and again to hash.
    pub(crate) qname_wire_hash: Fnv1a,
    /// Offset in the query's question section (i.e. into
    /// `packet[12..question_end]`) just past `qname_wire_hash`'s coverage —
    /// where QTYPE/QCLASS begins.
    pub(crate) qname_wire_hash_end: usize,
}

// Re-exports.

pub use builder::{
    a_reply, aaaa_reply, empty_reply, encode_dns_name, notimp_opcode_reply, notimp_reply,
    rcode_reply, servfail_reply, synthetic_query,
};
pub use ecs::{inject_or_replace_ecs, strip_edns_ecs, strip_opt_rdata};
pub use query::{
    get_id, is_reply, is_truncated, parse_query_fast, parse_query_from_fast, qname_from_question,
    set_id,
};
pub use ttl::{
    answer_ips, answer_rr_types, effective_ttl_and_offsets, patch_ttls_at, question_qclass, rcode,
};

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

    let Some((name_end, rdata_start, rdata_end)) = find_opt_record(packet, question_end) else {
        return QueryVariant::no_edns(rd, ad, cd);
    };

    // OPT TTL layout: ext-rcode(1) version(1) flags(2); DO is bit 15 of flags.
    let edns_version = packet[name_end + 5];
    let do_bit = (packet[name_end + 6] & 0x80) != 0;
    let (ecs_src, extra_opts_hash) =
        extract_opt_data(packet.get(rdata_start..rdata_end).unwrap_or(&[]));
    QueryVariant {
        has_opt: true,
        do_bit,
        edns_version,
        rd,
        ad,
        cd,
        ecs_src,
        extra_opts_hash,
    }
}

/// Find the EDNS OPT record (type 41) in `packet`'s additional section, if any.
/// Returns `(name_end, rdata_start, rdata_end)`: `name_end` is where the OPT
/// RR's fixed header (TYPE/CLASS/TTL/RDLENGTH, `name_end..name_end+10`) starts,
/// and `rdata_start..rdata_end` bounds its RDATA. Shared by every OPT-record
/// consumer below so the additional-section walk and its bounds-checks are
/// implemented — and kept correct — in exactly one place.
fn find_opt_record(packet: &[u8], question_end: usize) -> Option<(usize, usize, usize)> {
    if packet.len() < 12 {
        return None;
    }
    let arcount = u16::from_be_bytes([packet[10], packet[11]]) as usize;
    if arcount == 0 || question_end >= packet.len() {
        return None;
    }
    let mut pos = question_end;
    for _ in 0..arcount {
        let name_end = skip_name(packet, pos)?;
        // OPT fixed header: type(2) class(2) ttl(4) rdlen(2) = 10 bytes
        if name_end + 10 > packet.len() {
            return None;
        }
        let rr_type = u16::from_be_bytes([packet[name_end], packet[name_end + 1]]);
        let rdlen = u16::from_be_bytes([packet[name_end + 8], packet[name_end + 9]]) as usize;
        let rdata_start = name_end + 10;
        let rdata_end = rdata_start
            .checked_add(rdlen)
            .filter(|&e| e <= packet.len())?;
        if rr_type == 41 {
            return Some((name_end, rdata_start, rdata_end));
        }
        pos = rdata_end;
    }
    None
}

/// Walk OPT RDATA; return the normalised ECS source network and a hash of any
/// other option codes that influence the upstream response.
///
/// The hash is FNV-1a over the sorted set of option codes, excluding:
/// - ECS (`8`) — handled separately via `ecs_src`
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
        if code == ecs::ECS_OPTION_CODE && opt_len >= 4 {
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
    match find_opt_record(packet, question_end) {
        // OPT CLASS field encodes the sender's UDP payload size.
        Some((name_end, _, _)) => {
            u16::from_be_bytes([packet[name_end + 2], packet[name_end + 3]]).max(MIN)
        }
        None => MIN,
    }
}

/// Whether `packet`'s additional section carries an EDNS OPT record (type 41).
/// Used to decide whether a truncated reply must echo an OPT (RFC 6891 §7).
fn has_opt_record(packet: &[u8], question_end: usize) -> bool {
    find_opt_record(packet, question_end).is_some()
}

/// Minimal EDNS OPT RR to attach to a truncated reply: root name, type 41,
/// a conservative 1232-byte advertised UDP size, extended-RCODE/version/flags 0,
/// no rdata. 1232 follows the DNS flag-day recommendation for the safe payload size.
const TC_OPT_RR: [u8; 11] = [
    0x00, // root name
    0x00, 0x29, // TYPE = 41 (OPT)
    0x04, 0xD0, // CLASS = advertised UDP payload size = 1232
    0x00, 0x00, 0x00, 0x00, // TTL = extended-RCODE(0) | version(0) | flags(0)
    0x00, 0x00, // RDLEN = 0
];

/// If `resp` fits within the client's UDP payload limit it is returned unchanged (zero-copy).
/// If it exceeds the limit, returns a minimal TC=1 stub containing only the DNS header and
/// question section so the client retries over TCP (RFC 1035 §4.2.1).
///
/// When the client used EDNS, the stub also carries a minimal OPT record so the client
/// learns the server is EDNS-capable (RFC 6891 §7).
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
    let client_edns = has_opt_record(query, qe);
    let cap = if client_edns {
        qe + TC_OPT_RR.len()
    } else {
        qe
    };
    let mut stub = BytesMut::with_capacity(cap);
    stub.extend_from_slice(&resp[..qe]);
    stub[2] |= 0x02; // set TC (truncated) bit
    stub[6] = 0;
    stub[7] = 0; // ANCOUNT = 0
    stub[8] = 0;
    stub[9] = 0; // NSCOUNT = 0
    if client_edns {
        stub.extend_from_slice(&TC_OPT_RR);
        stub[10] = 0;
        stub[11] = 1; // ARCOUNT = 1 (OPT)
    } else {
        stub[10] = 0;
        stub[11] = 0; // ARCOUNT = 0
    }
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
        let Some((rtype, _class, ttl, rdata_start, rr_end)) = ttl::parse_rr(resp, offset) else {
            break;
        };
        results.push((rtype, ttl, resp[rdata_start..rr_end].to_vec()));
        offset = rr_end;
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
mod tests {
    use super::*;

    /// Build a NOERROR response for `query` carrying `n` A records (each with
    /// `ttl`), using the same pointer-to-question name compression a_reply uses.
    fn response_with_answers(query: &[u8], question_end: usize, n: u16, ttl: u32) -> Vec<u8> {
        let mut resp = query[..question_end].to_vec();
        resp[2] = 0x80; // QR=1
        resp[6..8].copy_from_slice(&n.to_be_bytes()); // ANCOUNT
        for i in 0..n {
            resp.extend_from_slice(&[0xC0, 0x0C]); // NAME → question
            resp.extend_from_slice(&[0x00, 0x01]); // TYPE A
            resp.extend_from_slice(&[0x00, 0x01]); // CLASS IN
            resp.extend_from_slice(&ttl.to_be_bytes());
            resp.extend_from_slice(&[0x00, 0x04]); // RDLENGTH
            resp.extend_from_slice(&[10, 0, (i >> 8) as u8, i as u8]);
        }
        resp
    }

    /// Append a minimal OPT RR advertising `payload` to `query` and bump ARCOUNT.
    fn with_opt(query: &[u8], payload: u16) -> Vec<u8> {
        let mut q = query.to_vec();
        q.push(0); // root name
        q.extend_from_slice(&41u16.to_be_bytes());
        q.extend_from_slice(&payload.to_be_bytes());
        q.extend_from_slice(&0u32.to_be_bytes());
        q.extend_from_slice(&0u16.to_be_bytes());
        q[11] = 1; // ARCOUNT = 1
        q
    }

    #[test]
    fn truncate_passes_small_responses_through_unchanged() {
        let (query, qe) = synthetic_query("example.com", 1).unwrap();
        let resp = response_with_answers(&query, qe, 2, 300);
        let out = maybe_truncate_for_udp(Bytes::from(resp.clone()), &query);
        assert_eq!(out.as_ref(), resp.as_slice());
    }

    #[test]
    fn truncate_builds_tc_stub_for_non_edns_client() {
        let (query, qe) = synthetic_query("example.com", 1).unwrap();
        // 40 A records ≈ 12 + 17 + 40*16 = 669 bytes > the 512 non-EDNS limit.
        let resp = response_with_answers(&query, qe, 40, 300);
        assert!(resp.len() > 512);
        let out = maybe_truncate_for_udp(Bytes::from(resp), &query);
        assert_eq!(out.len(), qe, "stub is header + question only");
        assert!(is_truncated(&out), "TC bit set");
        assert_eq!(&out[..2], &query[..2], "client ID preserved");
        assert_eq!(&out[12..qe], &query[12..qe], "question echoed");
        for counts in [&out[6..8], &out[8..10], &out[10..12]] {
            assert_eq!(counts, &[0, 0], "AN/NS/AR counts zeroed");
        }
    }

    #[test]
    fn truncate_honours_edns_advertised_size_and_echoes_opt() {
        let (query, qe) = synthetic_query("example.com", 1).unwrap();
        let big_query = with_opt(&query, 4096);
        let resp = response_with_answers(&query, qe, 40, 300);
        // Fits the advertised 4096: passes through unchanged.
        let out = maybe_truncate_for_udp(Bytes::from(resp.clone()), &big_query);
        assert_eq!(out.len(), resp.len());

        // A 512-advertising EDNS client gets a TC stub that carries an OPT
        // (RFC 6891 §7) so it learns the server is EDNS-capable.
        let small_query = with_opt(&query, 512);
        let out = maybe_truncate_for_udp(Bytes::from(resp), &small_query);
        assert!(is_truncated(&out));
        assert_eq!(out[10..12], [0, 1], "ARCOUNT = 1 for the OPT");
        assert_eq!(out.len(), qe + TC_OPT_RR.len());
        // OPT RR type 41 right after the root name terminating the stub.
        assert_eq!(&out[qe + 1..qe + 3], &41u16.to_be_bytes());
    }

    #[test]
    fn effective_ttl_uses_minimum_answer_ttl_and_clamps() {
        let (query, qe) = synthetic_query("example.com", 1).unwrap();
        let mut resp = response_with_answers(&query, qe, 2, 300);
        // Rewrite the second record's TTL to 50: offset of record i's TTL is
        // qe + i*16 + 6.
        let second_ttl = qe + 16 + 6;
        resp[second_ttl..second_ttl + 4].copy_from_slice(&50u32.to_be_bytes());

        let (entry_ttl, offsets) = effective_ttl_and_offsets(&resp, qe, 0, 0, 0).unwrap();
        assert_eq!(entry_ttl, 50, "entry lifetime is the minimum answer TTL");
        assert_eq!(offsets.len(), 2);
        assert_eq!(offsets[0], ((qe + 6) as u32, 300));
        assert_eq!(offsets[1], (second_ttl as u32, 50));

        // min-ttl raises both records; entry follows.
        let (entry_ttl, offsets) = effective_ttl_and_offsets(&resp, qe, 0, 60, 0).unwrap();
        assert_eq!(entry_ttl, 60);
        assert_eq!(offsets[0].1, 300);
        assert_eq!(offsets[1].1, 60);

        // max-ttl caps the larger record.
        let (entry_ttl, offsets) = effective_ttl_and_offsets(&resp, qe, 0, 0, 100).unwrap();
        assert_eq!(entry_ttl, 50);
        assert_eq!(offsets[0].1, 100);
    }

    #[test]
    fn effective_ttl_negative_response_uses_soa_capped_at_rfc2308_limit() {
        let (query, qe) = synthetic_query("nx.example.com", 1).unwrap();
        let mut resp = query[..qe].to_vec();
        resp[2] = 0x80;
        resp[3] = 0x03; // NXDOMAIN
        resp[8..10].copy_from_slice(&1u16.to_be_bytes()); // NSCOUNT = 1
        // SOA RR in the authority section: TTL 90000, MINIMUM 60.
        resp.extend_from_slice(&[0xC0, 0x0C]); // NAME
        resp.extend_from_slice(&[0x00, 0x06]); // TYPE SOA
        resp.extend_from_slice(&[0x00, 0x01]); // CLASS IN
        resp.extend_from_slice(&90_000u32.to_be_bytes());
        resp.extend_from_slice(&22u16.to_be_bytes()); // RDLENGTH (1+1 root names + 5 u32s)
        resp.push(0); // MNAME = root
        resp.push(0); // RNAME = root
        resp.extend_from_slice(&1u32.to_be_bytes()); // SERIAL
        resp.extend_from_slice(&2u32.to_be_bytes()); // REFRESH
        resp.extend_from_slice(&3u32.to_be_bytes()); // RETRY
        resp.extend_from_slice(&4u32.to_be_bytes()); // EXPIRE
        resp.extend_from_slice(&60u32.to_be_bytes()); // MINIMUM

        let (entry_ttl, offsets) = effective_ttl_and_offsets(&resp, qe, 0, 0, 0).unwrap();
        assert_eq!(entry_ttl, 60, "min(SOA TTL, MINIMUM) per RFC 2308");
        // The SOA's own TTL field is rewritten to the effective negative TTL.
        assert_eq!(offsets.len(), 1);
        assert_eq!(offsets[0].1, 60);

        // With MINIMUM above the RFC 2308 cap, the cap wins.
        let minimum_off = resp.len() - 4;
        resp[minimum_off..].copy_from_slice(&50_000u32.to_be_bytes());
        let (entry_ttl, _) = effective_ttl_and_offsets(&resp, qe, 0, 0, 0).unwrap();
        assert_eq!(entry_ttl, 10_800);
    }

    #[test]
    fn servfail_and_queries_are_never_ttl_scanned() {
        let (query, qe) = synthetic_query("example.com", 1).unwrap();
        // A query (QR=0) is not a good reply.
        assert!(effective_ttl_and_offsets(&query, qe, 0, 0, 0).is_none());
        let mut servfail = response_with_answers(&query, qe, 1, 300);
        servfail[3] = 0x02;
        assert!(effective_ttl_and_offsets(&servfail, qe, 0, 0, 0).is_none());
    }

    #[test]
    fn patch_ttls_writes_remaining_ttl_per_record() {
        let (query, qe) = synthetic_query("example.com", 1).unwrap();
        let mut resp = response_with_answers(&query, qe, 2, 300);
        let (_, offsets) = effective_ttl_and_offsets(&resp, qe, 0, 0, 0).unwrap();
        patch_ttls_at(&mut resp, &offsets, 40);
        let ttl0 = u32::from_be_bytes(resp[qe + 6..qe + 10].try_into().unwrap());
        assert_eq!(ttl0, 260);
        // Elapsed beyond the TTL saturates to zero rather than wrapping.
        patch_ttls_at(&mut resp, &offsets, 1000);
        let ttl0 = u32::from_be_bytes(resp[qe + 6..qe + 10].try_into().unwrap());
        assert_eq!(ttl0, 0);
    }
}
