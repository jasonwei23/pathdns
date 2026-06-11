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

use bytes::{Bytes, BytesMut};

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
pub use scan::{answer_ips, effective_ttl_and_offsets, patch_ttls_at, patch_ttls_uniform, rcode};

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
        let Some(name_end) = skip_name(packet, pos) else { break };
        if name_end + 10 > packet.len() {
            break;
        }
        let rr_type = u16::from_be_bytes([packet[name_end], packet[name_end + 1]]);
        let rdlen = u16::from_be_bytes([packet[name_end + 8], packet[name_end + 9]]) as usize;
        let Some(rdata_end) =
            (name_end + 10).checked_add(rdlen).filter(|&e| e <= packet.len())
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
    stub[2] |= 0x02;                   // set TC (truncated) bit
    stub[6] = 0; stub[7] = 0;          // ANCOUNT = 0
    stub[8] = 0; stub[9] = 0;          // NSCOUNT = 0
    stub[10] = 0; stub[11] = 0;        // ARCOUNT = 0
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
    loop {
        let len = match sent_q.get(pos) {
            Some(&v) => v as usize,
            None => break,
        };
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
            if s != r {
                if r != s.to_ascii_lowercase() {
                    return false;
                }
            }
        }
        pos += len;
    }
    true
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

    /// Minimal DNS query for "test.example" type A, no EDNS.
    fn plain_query() -> (Vec<u8>, usize) {
        let qname: &[u8] = b"\x04test\x07example\x00";
        let mut q = vec![
            0x00, 0x01, // ID
            0x01, 0x00, // QR=0 RD=1
            0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // counts
        ];
        q.extend_from_slice(qname);
        q.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]); // QTYPE A, QCLASS IN
        let qe = q.len();
        (q, qe)
    }

    /// Same query with an EDNS OPT record advertising `payload_size`.
    fn edns_query(payload_size: u16) -> (Vec<u8>, usize) {
        let (mut q, qe) = plain_query();
        q[11] = 1; // ARCOUNT = 1
        let [hi, lo] = payload_size.to_be_bytes();
        q.extend_from_slice(&[
            0x00,       // root owner name
            0x00, 0x29, // type OPT (41)
            hi, lo,     // UDP payload size
            0x00, 0x00, // ext-rcode, version
            0x00, 0x00, // flags
            0x00, 0x00, // RDLEN = 0
        ]);
        (q, qe)
    }

    /// Fake response with enough bytes to trigger truncation.
    fn large_response(query: &[u8], question_end: usize, extra: usize) -> Bytes {
        let mut r = vec![0u8; question_end + extra];
        r[..query.len().min(question_end)].copy_from_slice(&query[..query.len().min(question_end)]);
        r[2] = 0x81; // QR=1 RD=1
        r[3] = 0x80; // RA=1
        Bytes::from(r)
    }

    #[test]
    fn non_edns_client_limit_is_512() {
        let (q, qe) = plain_query();
        assert_eq!(client_udp_payload_size(&q, qe), 512);
    }

    #[test]
    fn edns_client_limit_from_opt_payload_field() {
        let (q, qe) = edns_query(4096);
        assert_eq!(client_udp_payload_size(&q, qe), 4096);
    }

    #[test]
    fn edns_payload_size_floored_at_512() {
        let (q, qe) = edns_query(200);
        assert_eq!(client_udp_payload_size(&q, qe), 512);
    }

    #[test]
    fn small_response_passes_through_unchanged() {
        let (q, qe) = plain_query();
        let resp = large_response(&q, qe, 0); // exactly question_end bytes, well under 512
        let original_ptr = resp.as_ptr();
        let out = maybe_truncate_for_udp(resp, &q);
        // Zero-copy: same underlying allocation.
        assert_eq!(out.as_ptr(), original_ptr);
    }

    #[test]
    fn oversized_non_edns_response_becomes_tc_stub() {
        let (q, qe) = plain_query();
        // Build a response larger than 512 bytes.
        let resp = large_response(&q, qe, 600);
        assert!(resp.len() > 512);
        let stub = maybe_truncate_for_udp(resp, &q);
        // Stub length equals question_end.
        assert_eq!(stub.len(), qe);
        // TC bit must be set (byte 2, bit 1).
        assert_ne!(stub[2] & 0x02, 0, "TC bit not set");
        // Record counts must be zeroed.
        assert_eq!(&stub[6..12], &[0, 0, 0, 0, 0, 0], "record counts not zeroed");
    }

    #[test]
    fn oversized_edns_response_becomes_tc_stub() {
        let payload = 1232u16;
        let (q, qe) = edns_query(payload);
        // Build a response larger than the declared EDNS payload size.
        let resp = large_response(&q, qe, (payload as usize) + 100);
        assert!(resp.len() > payload as usize);
        let stub = maybe_truncate_for_udp(resp, &q);
        assert_eq!(stub.len(), qe);
        assert_ne!(stub[2] & 0x02, 0, "TC bit not set");
        assert_eq!(&stub[6..12], &[0, 0, 0, 0, 0, 0]);
    }

    #[test]
    fn response_within_edns_limit_passes_through() {
        let (q, qe) = edns_query(4096);
        let resp = large_response(&q, qe, 500); // question_end + 500 < 4096
        let original_ptr = resp.as_ptr();
        let out = maybe_truncate_for_udp(resp, &q);
        assert_eq!(out.as_ptr(), original_ptr);
    }

    #[test]
    fn mix_qname_case_toggles_some_letters() {
        let (mut q, qe) = plain_query();
        let original = q[12..qe].to_vec();
        mix_qname_case(&mut q, qe, 12345678u64);
        // At least some bytes in the QNAME should differ from original
        let changed = q[12..qe].iter().zip(original.iter()).any(|(a, b)| a != b);
        assert!(changed, "mix_qname_case should toggle at least some letters");
    }

    #[test]
    fn verify_qname_case_echo_exact_match_accepted() {
        let (q, qe) = plain_query();
        let mut sent = q.clone();
        mix_qname_case(&mut sent, qe, 99999u64);
        // Exact echo: accepted
        assert!(verify_qname_case_echo(&sent, qe, &sent, qe));
    }

    #[test]
    fn verify_qname_case_echo_lowercase_response_accepted() {
        let (q, qe) = plain_query();
        let mut sent = q.clone();
        // Set sent to uppercase in QNAME
        for b in &mut sent[12..qe - 4] {
            if b.is_ascii_alphabetic() {
                *b = b.to_ascii_uppercase();
            }
        }
        // Lowercase response is tolerated
        let mut recv = q.clone();
        for b in &mut recv[12..qe - 4] {
            if b.is_ascii_alphabetic() {
                *b = b.to_ascii_lowercase();
            }
        }
        assert!(verify_qname_case_echo(&sent, qe, &recv, qe));
    }

    #[test]
    fn verify_qname_case_echo_spoofed_case_rejected() {
        let (q, qe) = plain_query();
        let mut sent = q.clone();
        mix_qname_case(&mut sent, qe, 42u64);
        // Attacker sends back a different case pattern (all-uppercase)
        let mut spoofed = q.clone();
        for b in &mut spoofed[12..qe - 4] {
            if b.is_ascii_alphabetic() {
                *b = b.to_ascii_uppercase();
            }
        }
        // If the sent had at least one lowercase letter, this should fail
        let has_lowercase_in_sent = sent[12..qe - 4].iter().any(|b| b.is_ascii_lowercase());
        if has_lowercase_in_sent {
            assert!(
                !verify_qname_case_echo(&sent, qe, &spoofed, qe),
                "spoofed uppercase case should be rejected when sent had lowercase"
            );
        }
    }
}
