use anyhow::{anyhow, Result};
use std::sync::Arc;

use super::{FastQueryInfo, QueryInfo, QueryVariant};
use crate::hasher::Fnv1a;

pub fn get_id(packet: &[u8]) -> Result<u16> {
    if packet.len() < 2 {
        return Err(anyhow!("invalid dns packet: too short"));
    }
    Ok(u16::from_be_bytes([packet[0], packet[1]]))
}

pub fn set_id(packet: &mut [u8], id: u16) -> Result<()> {
    if packet.len() < 2 {
        return Err(anyhow!("invalid dns packet: too short"));
    }
    let [hi, lo] = id.to_be_bytes();
    packet[0] = hi;
    packet[1] = lo;
    Ok(())
}

fn is_query(packet: &[u8]) -> bool {
    packet.len() >= 12 && (packet[2] & 0x80) == 0
}

pub fn is_reply(packet: &[u8]) -> bool {
    packet.len() >= 12 && (packet[2] & 0x80) != 0
}

pub fn is_truncated(packet: &[u8]) -> bool {
    packet.len() >= 4 && (packet[2] & 0x02) != 0
}

/// Build a [`QueryInfo`] from the already-validated [`FastQueryInfo`]. The
/// routing qname string is **not** built here — it is materialized lazily
/// (via [`qname_from_question`]) only when a consumer needs the string form,
/// so a constant-route, cache-off, querylog-off forward never allocates it.
/// `packet` is unused now but kept in the signature for API stability with
/// the fast-path callers and fuzz harness.
pub fn parse_query_from_fast(
    _packet: &[u8],
    fast: FastQueryInfo,
    variant: QueryVariant,
) -> Result<QueryInfo> {
    Ok(QueryInfo {
        id: fast.id,
        qname: None,
        qtype: fast.qtype,
        question_end: fast.question_end,
        qname_wire_hash: fast.qname_wire_hash,
        qname_wire_hash_end: fast.qname_wire_hash_end,
        variant,
        // Set by the fast-path miss route (`handle_packet_slow_preparsed`)
        // from the cache probe; `None` here so other callers recompute.
        precomputed_cache_keys: None,
    })
}

pub fn parse_query_fast(packet: &[u8]) -> Result<FastQueryInfo> {
    if !is_query(packet) {
        return Err(anyhow!("not a dns query"));
    }
    // Opcode must be standard QUERY (0); len >= 12 guaranteed by is_query.
    if (packet[2] >> 3) & 0x0f != 0 {
        return Err(anyhow!("non-QUERY opcode"));
    }
    // Must have exactly one question.
    if u16::from_be_bytes([packet[4], packet[5]]) != 1 {
        return Err(anyhow!("QDCOUNT must be 1"));
    }
    let (qend, qname_wire_hash, qname_wire_hash_end) = skip_query_question(packet, 12)?;
    let qtype = u16::from_be_bytes([packet[qend - 4], packet[qend - 3]]);
    Ok(FastQueryInfo {
        id: get_id(packet)?,
        qtype,
        question_end: qend,
        qname_wire_hash,
        qname_wire_hash_end,
    })
}

/// Validate the question's QNAME and, in the same pass, hash it for the cache
/// key. Returns `(question_end, qname_wire_hash, qname_wire_hash_end)`; the
/// hash-relevant lines (`h.write_byte`) mirror `Fnv1a::write_qname_wire`
/// byte-for-byte and in the same order (each length byte including the
/// terminator, then each label byte lowercased). They are a deliberate inline
/// duplicate rather than a call through that method, since this loop's
/// validation (compression/length/bounds checks, returning `Err` for a
/// malformed qname) doesn't compose with that method's intentionally
/// validation-free contract. `cache::tests` pins the two to stay in sync.
fn skip_query_question(packet: &[u8], mut pos: usize) -> Result<(usize, Fnv1a, usize)> {
    let start = pos;
    let mut h = Fnv1a::new();
    while pos < packet.len() {
        let len = packet[pos] as usize;
        h.write_byte(len as u8);
        pos += 1;
        if len == 0 {
            break;
        }
        if (len & 0xc0) != 0 {
            return Err(anyhow!("compressed qname is invalid in query question"));
        }
        if len > 63 || pos + len > packet.len() {
            return Err(anyhow!("invalid dns query question"));
        }
        for &b in &packet[pos..pos + len] {
            h.write_byte(b.to_ascii_lowercase());
        }
        pos += len;
        // RFC 1035 §2.3.4: full QNAME wire encoding must not exceed 255 bytes.
        if (pos - start) + 1 > 255 {
            return Err(anyhow!("qname exceeds 255-byte wire limit"));
        }
    }
    // Hash-coverage end relative to the question section (packet[12..]),
    // matching what `Fnv1a::write_qname_wire`'s return value means.
    let hash_end = pos - start;
    let qend = question_tail(packet, pos)?;
    Ok((qend, h, hash_end))
}

fn question_tail(packet: &[u8], pos: usize) -> Result<usize> {
    if pos + 4 > packet.len() {
        return Err(anyhow!("failed to parse dns query question"));
    }
    Ok(pos + 4)
}

/// Returns the routing qname (lowercased, dot-separated, no trailing dot).
/// The QNAME's cache-key hash is *not* computed here — `parse_query_fast`
/// already produced it during its validation walk (see
/// [`FastQueryInfo::qname_wire_hash`]) and `parse_query_from_fast` carries it
/// through. This is the lazy materializer the resolver calls the first time a
/// query's qname *string* is actually needed.
pub fn qname_from_question(packet: &[u8], question_end: usize) -> Result<Arc<str>> {
    if !is_query(packet) || question_end > packet.len() {
        return Err(anyhow!("invalid dns query"));
    }
    let mut pos = 12usize;
    let mut qname = String::with_capacity(question_end.saturating_sub(17));

    while pos < packet.len() && pos < question_end {
        let len = packet[pos] as usize;
        pos += 1;

        if len == 0 {
            break;
        }
        if (len & 0xc0) != 0 {
            return Err(anyhow!("compressed qname is invalid in query question"));
        }
        if len > 63 || pos + len > question_end {
            return Err(anyhow!("invalid dns query question"));
        }

        if !qname.is_empty() {
            qname.push('.');
        }
        let label = &packet[pos..pos + len];
        if label.is_ascii() {
            // Overwhelmingly common case: append lowercased bytes directly,
            // with no per-label temporary String allocation.
            for &b in label {
                qname.push(b.to_ascii_lowercase() as char);
            }
        } else {
            // `(b as char)` would widen each byte >= 0x80 into its own 2-byte UTF-8
            // sequence instead of preserving the wire byte, corrupting domain-based
            // routing/blocking comparisons for any label that isn't pure ASCII (e.g. a
            // raw UTF-8 IDN label). `from_utf8_lossy` is byte-faithful (zero-copy) for
            // the common case of a valid-UTF-8 label and only substitutes U+FFFD for
            // genuinely malformed byte sequences, which cannot match any real
            // (always-valid-UTF-8) configured domain pattern anyway.
            qname.push_str(&String::from_utf8_lossy(label).to_ascii_lowercase());
        }
        pos += len;
    }

    Ok(Arc::from(qname.as_str()))
}
