use anyhow::{anyhow, Result};
use std::net::{Ipv4Addr, Ipv6Addr};

struct ResponseBuilder {
    buf: Vec<u8>,
}

impl ResponseBuilder {
    fn from_query(query: &[u8], question_end: usize) -> Result<Self> {
        // `question_end < 12` is not reachable today (every caller sources it from
        // `parse_query_fast`, which always returns >= 17), but the header rewrite
        // below indexes `buf[..12]` unconditionally, so this guards against a
        // future caller passing a smaller value causing an out-of-bounds panic
        // instead of a clean error.
        if query.len() < 12 || question_end < 12 || question_end > query.len() {
            return Err(anyhow!("invalid dns query"));
        }
        let mut buf = query[..question_end].to_vec();
        buf[2] = 0x80 | (query[2] & 0x01); // QR=1, RD=copied; clear AA, TC, OPCODE
        buf[3] = 0x00; // RA=0, AD=0, CD=0, RCODE=0
        buf[4] = 0x00;
        buf[5] = 0x01; // QDCOUNT=1
        buf[6] = 0x00;
        buf[7] = 0x00; // ANCOUNT=0
        buf[8] = 0x00;
        buf[9] = 0x00; // NSCOUNT=0
        buf[10] = 0x00;
        buf[11] = 0x00; // ARCOUNT=0
        Ok(Self { buf })
    }

    fn set_ra(&mut self) -> &mut Self {
        self.buf[3] |= 0x80;
        self
    }

    fn set_rcode(&mut self, rcode: u8) -> &mut Self {
        self.buf[3] = (self.buf[3] & 0xf0) | (rcode & 0x0f);
        self
    }

    fn finish(self) -> Vec<u8> {
        self.buf
    }
}

/// NOERROR response with no answer records (used for RCODE://NOERROR rules).
pub fn empty_reply(query: &[u8], question_end: usize) -> Result<Vec<u8>> {
    let mut b = ResponseBuilder::from_query(query, question_end)?;
    b.set_ra();
    Ok(b.finish())
}

/// Response with an arbitrary RCODE and no answer records.
pub fn rcode_reply(query: &[u8], question_end: usize, rcode: u8) -> Result<Vec<u8>> {
    let mut b = ResponseBuilder::from_query(query, question_end)?;
    b.set_ra().set_rcode(rcode);
    Ok(b.finish())
}

/// SERVFAIL response: RCODE=2, RA=1.
pub fn servfail_reply(query: &[u8], question_end: usize) -> Result<Vec<u8>> {
    let mut b = ResponseBuilder::from_query(query, question_end)?;
    b.set_ra().set_rcode(2);
    Ok(b.finish())
}

/// NOTIMP response for a QUERY-opcode packet (question section is echoed back).
pub fn notimp_reply(query: &[u8], question_end: usize) -> Result<Vec<u8>> {
    let mut b = ResponseBuilder::from_query(query, question_end)?;
    b.set_ra().set_rcode(4);
    Ok(b.finish())
}

/// NOTIMP response for non-QUERY opcodes. Only the transaction ID and OPCODE
/// are echoed; the question section is omitted because non-QUERY opcode formats
/// are not guaranteed to follow RFC 1035 question layout.
pub fn notimp_opcode_reply(query: &[u8]) -> Vec<u8> {
    if query.len() < 12 {
        return vec![];
    }
    let mut buf = [0u8; 12];
    buf[0] = query[0];
    buf[1] = query[1];
    buf[2] = 0x80 | (query[2] & 0x79); // QR=1, OPCODE and RD copied, AA=0, TC=0
    buf[3] = 0x84; // RA=1, RCODE=4 (NOTIMP)
    buf.to_vec()
}

/// NOERROR response with a single A record answer.
pub fn a_reply(query: &[u8], question_end: usize, addr: Ipv4Addr, ttl: u32) -> Result<Vec<u8>> {
    let mut b = ResponseBuilder::from_query(query, question_end)?;
    b.set_ra();
    b.buf[7] = 1; // ANCOUNT = 1
    b.buf.extend_from_slice(&[0xC0, 0x0C]); // NAME = pointer to question at offset 12
    b.buf.extend_from_slice(&[0x00, 0x01]); // TYPE = A
    b.buf.extend_from_slice(&[0x00, 0x01]); // CLASS = IN
    b.buf.extend_from_slice(&ttl.to_be_bytes());
    b.buf.extend_from_slice(&[0x00, 0x04]); // RDLENGTH = 4
    b.buf.extend_from_slice(&addr.octets());
    Ok(b.finish())
}

/// NOERROR response with a single AAAA record answer.
pub fn aaaa_reply(query: &[u8], question_end: usize, addr: Ipv6Addr, ttl: u32) -> Result<Vec<u8>> {
    let mut b = ResponseBuilder::from_query(query, question_end)?;
    b.set_ra();
    b.buf[7] = 1; // ANCOUNT = 1
    b.buf.extend_from_slice(&[0xC0, 0x0C]); // NAME = pointer to question at offset 12
    b.buf.extend_from_slice(&[0x00, 0x1C]); // TYPE = AAAA
    b.buf.extend_from_slice(&[0x00, 0x01]); // CLASS = IN
    b.buf.extend_from_slice(&ttl.to_be_bytes());
    b.buf.extend_from_slice(&[0x00, 0x10]); // RDLENGTH = 16
    b.buf.extend_from_slice(&addr.octets());
    Ok(b.finish())
}

/// NOERROR response with a single CNAME record answer.
pub fn cname_reply(query: &[u8], question_end: usize, target: &str, ttl: u32) -> Result<Vec<u8>> {
    let rdata = encode_dns_name(target)?;
    let mut b = ResponseBuilder::from_query(query, question_end)?;
    b.set_ra();
    b.buf[7] = 1; // ANCOUNT = 1
    b.buf.extend_from_slice(&[0xC0, 0x0C]); // NAME = pointer to question at offset 12
    b.buf.extend_from_slice(&[0x00, 0x05]); // TYPE = CNAME
    b.buf.extend_from_slice(&[0x00, 0x01]); // CLASS = IN
    b.buf.extend_from_slice(&ttl.to_be_bytes());
    let rdlen = rdata.len() as u16;
    b.buf.extend_from_slice(&rdlen.to_be_bytes());
    b.buf.extend_from_slice(&rdata);
    Ok(b.finish())
}

/// Build a minimal DNS query packet for `name` with the given `qtype`.
///
/// Returns `(packet_bytes, question_end)` where `question_end` is the byte
/// offset immediately after the question section.
pub fn synthetic_query(name: &str, qtype: u16) -> Result<(Vec<u8>, usize)> {
    let mut buf = vec![
        0x00, 0x00, // ID = 0
        0x01, 0x00, // QR=0, OPCODE=0, RD=1
        0x00, 0x01, // QDCOUNT=1
        0x00, 0x00, // ANCOUNT=0
        0x00, 0x00, // NSCOUNT=0
        0x00, 0x00, // ARCOUNT=0
    ];
    buf.extend_from_slice(&encode_dns_name(name)?);
    buf.extend_from_slice(&qtype.to_be_bytes());
    buf.extend_from_slice(&[0x00, 0x01]); // QCLASS=IN
    let question_end = buf.len();
    Ok((buf, question_end))
}

/// NOERROR response combining a CNAME record for `query`→`target` with additional
/// A or AAAA records for `target`.
///
/// `extra_records` is a slice of (qtype, ttl, rdata_bytes) for records to append
/// with `target` as their owner name.
pub fn cname_with_chase_reply(
    query: &[u8],
    question_end: usize,
    target: &str,
    cname_ttl: u32,
    extra_records: &[(u16, u32, Vec<u8>)],
) -> Result<Vec<u8>> {
    let rdata = encode_dns_name(target)?;
    let mut b = ResponseBuilder::from_query(query, question_end)?;
    b.set_ra();

    // CNAME record: NAME=ptr to Q's name at offset 12
    b.buf.extend_from_slice(&[0xC0, 0x0C]);
    b.buf.extend_from_slice(&[0x00, 0x05]); // TYPE = CNAME
    b.buf.extend_from_slice(&[0x00, 0x01]); // CLASS = IN
    b.buf.extend_from_slice(&cname_ttl.to_be_bytes());
    b.buf.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
    // Record where T's name starts so we can point at it from A/AAAA records
    let target_name_offset = b.buf.len();
    b.buf.extend_from_slice(&rdata);

    // Additional A/AAAA records: NAME = pointer to target name in CNAME RDATA.
    // Only emitted when the pointer fits a 14-bit compression offset (not
    // possible in practice, since question_end is always sourced from
    // `parse_query_fast`'s 255-byte-capped QNAME). ANCOUNT is computed from
    // `extras_fit` below so it always matches what's actually appended, instead
    // of being written up front and left overstated if the extras are dropped.
    let extras_fit = target_name_offset <= 0x3FFF;
    if extras_fit {
        let ptr = [
            0xC0u8 | ((target_name_offset >> 8) as u8),
            (target_name_offset & 0xFF) as u8,
        ];
        for (qtype, ttl, rdata_bytes) in extra_records {
            b.buf.extend_from_slice(&ptr);
            b.buf.extend_from_slice(&qtype.to_be_bytes());
            b.buf.extend_from_slice(&[0x00, 0x01]); // CLASS = IN
            b.buf.extend_from_slice(&ttl.to_be_bytes());
            b.buf
                .extend_from_slice(&(rdata_bytes.len() as u16).to_be_bytes());
            b.buf.extend_from_slice(rdata_bytes);
        }
    }

    let ancount = 1u16 + if extras_fit { extra_records.len() as u16 } else { 0 };
    let total_count = ancount.to_be_bytes();
    b.buf[6] = total_count[0];
    b.buf[7] = total_count[1]; // ANCOUNT

    Ok(b.finish())
}

/// Encode a domain name into DNS wire-format labels (RFC 1035 §3.1).
pub fn encode_dns_name(name: &str) -> Result<Vec<u8>> {
    let name = name.trim_end_matches('.');
    let mut out = Vec::new();
    if name.is_empty() {
        out.push(0);
        return Ok(out);
    }
    let mut total = 1usize; // root label
    for label in name.split('.') {
        let len = label.len();
        if len == 0 {
            return Err(anyhow!("DNS name contains an empty label: '{name}'"));
        }
        if len > 63 {
            return Err(anyhow!("DNS label too long ({len} bytes): '{label}'"));
        }
        total += 1 + len;
        if total > 255 {
            return Err(anyhow!("DNS name exceeds 255-byte wire limit: '{name}'"));
        }
        out.push(len as u8);
        out.extend_from_slice(label.as_bytes());
    }
    out.push(0);
    Ok(out)
}
