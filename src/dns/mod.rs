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

pub use builder::{empty_reply, servfail_reply};
pub use ecs::{inject_or_replace_ecs, strip_edns_ecs};
pub use query::{get_id, is_reply, is_truncated, parse_query_fast, parse_query_from_fast, set_id};
pub use scan::{answer_ips, effective_ttl_and_offsets, patch_ttls_at, rcode};

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
