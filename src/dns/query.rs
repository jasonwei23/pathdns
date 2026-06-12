use anyhow::{anyhow, Result};
use std::sync::Arc;

use super::{FastQueryInfo, QueryInfo};

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

pub fn parse_query_from_fast(packet: &[u8], fast: FastQueryInfo) -> Result<QueryInfo> {
    Ok(QueryInfo {
        id: fast.id,
        qname: qname_from_question(packet, fast.question_end)?,
        qtype: fast.qtype,
        question_end: fast.question_end,
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
    let qend = skip_query_question(packet, 12)?;
    let qtype = u16::from_be_bytes([packet[qend - 4], packet[qend - 3]]);
    Ok(FastQueryInfo {
        id: get_id(packet)?,
        qtype,
        question_end: qend,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal DNS query with the given opcode and QDCOUNT.
    /// Each question is "a." A IN (7 bytes).
    fn make_query(opcode: u8, qdcount: u16) -> Vec<u8> {
        let mut p = vec![
            0x12,
            0x34, // ID
            opcode << 3,
            0x00, // flags: QR=0, Opcode, RD=0
            (qdcount >> 8) as u8,
            qdcount as u8, // QDCOUNT
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00, // ANCOUNT/NSCOUNT/ARCOUNT = 0
        ];
        for _ in 0..qdcount {
            p.extend_from_slice(&[0x01, b'a', 0x00, 0x00, 0x01, 0x00, 0x01]);
        }
        p
    }

    #[test]
    fn valid_single_question_query_accepted() {
        assert!(parse_query_fast(&make_query(0, 1)).is_ok());
    }

    #[test]
    fn qdcount_zero_rejected() {
        assert!(parse_query_fast(&make_query(0, 0)).is_err());
    }

    #[test]
    fn qdcount_two_rejected() {
        assert!(parse_query_fast(&make_query(0, 2)).is_err());
    }

    #[test]
    fn non_query_opcode_rejected() {
        // opcode=4 is NOTIFY
        assert!(parse_query_fast(&make_query(4, 1)).is_err());
    }

    #[test]
    fn qname_wire_length_limit_enforced() {
        // Build a query with a QNAME that fills exactly 255 bytes (valid) and one that exceeds it.
        // Wire format: each label is <len><bytes>, terminated by <0>.
        // 63-byte labels: <0x3f><63 bytes> = 64 bytes each; four labels = 256 bytes total which exceeds the limit.
        fn make_qname_query(num_labels: usize, label_len: usize) -> Vec<u8> {
            let mut p = vec![
                0x12, 0x34, // ID
                0x00, 0x00, // QR=0, Opcode=0, RD=0
                0x00, 0x01, // QDCOUNT=1
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            ];
            for _ in 0..num_labels {
                p.push(label_len as u8);
                p.extend(std::iter::repeat(b'a').take(label_len));
            }
            p.push(0); // root label
            p.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]); // type A, class IN
            p
        }

        // 3 × 63-byte labels = 3×64 = 192 bytes + root = 193 bytes — valid.
        let valid = make_qname_query(3, 63);
        assert!(
            parse_query_fast(&valid).is_ok(),
            "3-label query should be accepted"
        );

        // 4 × 63-byte labels = 4×64 = 256 bytes — exceeds 255.
        let too_long = make_qname_query(4, 63);
        assert!(
            parse_query_fast(&too_long).is_err(),
            "4×63-byte label query should be rejected"
        );
    }
}

fn skip_query_question(packet: &[u8], mut pos: usize) -> Result<usize> {
    let start = pos;
    while pos < packet.len() {
        let len = packet[pos] as usize;
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
        pos += len;
        // RFC 1035 §2.3.4: full QNAME wire encoding must not exceed 255 bytes.
        if (pos - start) + 1 > 255 {
            return Err(anyhow!("qname exceeds 255-byte wire limit"));
        }
    }
    question_tail(packet, pos)
}

fn question_tail(packet: &[u8], pos: usize) -> Result<usize> {
    if pos + 4 > packet.len() {
        return Err(anyhow!("failed to parse dns query question"));
    }
    Ok(pos + 4)
}

fn qname_from_question(packet: &[u8], question_end: usize) -> Result<Arc<str>> {
    if !is_query(packet) || question_end > packet.len() {
        return Err(anyhow!("invalid dns query"));
    }
    let mut pos = 12usize;
    let mut qname = String::new();

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
        for &b in &packet[pos..pos + len] {
            qname.push((b as char).to_ascii_lowercase());
        }
        pos += len;
    }

    Ok(Arc::from(qname.as_str()))
}
