use anyhow::{anyhow, Result};
use std::net::{Ipv4Addr, Ipv6Addr};

struct ResponseBuilder {
    buf: Vec<u8>,
}

impl ResponseBuilder {
    fn from_query(query: &[u8], question_end: usize) -> Result<Self> {
        if query.len() < 12 || question_end > query.len() {
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
    let total_count = (1u16 + extra_records.len() as u16).to_be_bytes();
    b.buf[6] = total_count[0];
    b.buf[7] = total_count[1]; // ANCOUNT

    // CNAME record: NAME=ptr to D's name at offset 12
    b.buf.extend_from_slice(&[0xC0, 0x0C]);
    b.buf.extend_from_slice(&[0x00, 0x05]); // TYPE = CNAME
    b.buf.extend_from_slice(&[0x00, 0x01]); // CLASS = IN
    b.buf.extend_from_slice(&cname_ttl.to_be_bytes());
    b.buf.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
    // Record where T's name starts so we can point at it from A/AAAA records
    let target_name_offset = b.buf.len();
    b.buf.extend_from_slice(&rdata);

    // Additional A/AAAA records: NAME = pointer to target name in CNAME RDATA
    if target_name_offset <= 0x3FFF {
        let ptr = [
            0xC0u8 | ((target_name_offset >> 8) as u8),
            (target_name_offset & 0xFF) as u8,
        ];
        for (qtype, ttl, rdata_bytes) in extra_records {
            b.buf.extend_from_slice(&ptr);
            b.buf.extend_from_slice(&qtype.to_be_bytes());
            b.buf.extend_from_slice(&[0x00, 0x01]); // CLASS = IN
            b.buf.extend_from_slice(&ttl.to_be_bytes());
            b.buf.extend_from_slice(&(rdata_bytes.len() as u16).to_be_bytes());
            b.buf.extend_from_slice(rdata_bytes);
        }
    }
    // (if target_name_offset > 0x3FFF the extras are silently dropped; not possible in practice)

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

#[cfg(test)]
mod tests {
    use super::*;

    /// Minimal A-query for "example.com" used across builder tests.
    fn a_query() -> (Vec<u8>, usize) {
        let mut q = vec![
            0xAB, 0xCD, // ID
            0x01, 0x00, // QR=0 RD=1
            0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        q.extend_from_slice(b"\x07example\x03com\x00");
        q.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]); // QTYPE=A QCLASS=IN
        let qe = q.len();
        (q, qe)
    }

    #[test]
    fn a_reply_has_correct_structure() {
        let (q, qe) = a_query();
        let addr: Ipv4Addr = "1.2.3.4".parse().unwrap();
        let resp = a_reply(&q, qe, addr, 60).unwrap();

        assert_eq!(&resp[0..2], &q[0..2], "ID must be copied");
        assert_eq!(resp[2] & 0x80, 0x80, "QR must be 1");
        assert_eq!(resp[3] & 0x80, 0x80, "RA must be 1");
        assert_eq!(resp[3] & 0x0f, 0, "RCODE must be 0 (NOERROR)");
        assert_eq!(u16::from_be_bytes([resp[6], resp[7]]), 1, "ANCOUNT must be 1");

        // Answer section starts at question_end.
        let ans = &resp[qe..];
        assert_eq!(&ans[0..2], &[0xC0, 0x0C], "NAME must be a pointer to offset 12");
        assert_eq!(u16::from_be_bytes([ans[2], ans[3]]), 1, "TYPE must be A");
        assert_eq!(u16::from_be_bytes([ans[4], ans[5]]), 1, "CLASS must be IN");
        assert_eq!(u32::from_be_bytes([ans[6], ans[7], ans[8], ans[9]]), 60, "TTL");
        assert_eq!(u16::from_be_bytes([ans[10], ans[11]]), 4, "RDLENGTH must be 4");
        assert_eq!(&ans[12..16], &[1, 2, 3, 4], "RDATA must be the IPv4 address");
    }

    #[test]
    fn aaaa_reply_has_correct_structure() {
        let (q, qe) = a_query();
        let addr: Ipv6Addr = "2001:db8::1".parse().unwrap();
        let resp = aaaa_reply(&q, qe, addr, 300).unwrap();

        assert_eq!(u16::from_be_bytes([resp[6], resp[7]]), 1, "ANCOUNT must be 1");
        let ans = &resp[qe..];
        assert_eq!(u16::from_be_bytes([ans[2], ans[3]]), 28, "TYPE must be AAAA");
        assert_eq!(u16::from_be_bytes([ans[10], ans[11]]), 16, "RDLENGTH must be 16");
        assert_eq!(&ans[12..28], &addr.octets(), "RDATA must be the IPv6 address");
    }

    #[test]
    fn cname_reply_has_correct_structure() {
        let (q, qe) = a_query();
        let resp = cname_reply(&q, qe, "alias.example.com", 120).unwrap();

        assert_eq!(u16::from_be_bytes([resp[6], resp[7]]), 1, "ANCOUNT must be 1");
        let ans = &resp[qe..];
        assert_eq!(u16::from_be_bytes([ans[2], ans[3]]), 5, "TYPE must be CNAME");
        // RDATA: \x05alias\x07example\x03com\x00 = 5+1 + 7+1 + 3+1 + 1 = 19 bytes
        let expected_rdata = encode_dns_name("alias.example.com").unwrap();
        let rdlen = u16::from_be_bytes([ans[10], ans[11]]) as usize;
        assert_eq!(rdlen, expected_rdata.len(), "RDLENGTH mismatch");
        assert_eq!(&ans[12..12 + rdlen], expected_rdata.as_slice(), "RDATA mismatch");
    }

    #[test]
    fn synthetic_query_has_correct_question_end() {
        let (q, qe) = synthetic_query("example.com", 1).unwrap();
        // 12 header + 13 qname (\x07example\x03com\x00 = 1+7+1+3+1 = 13 bytes) + 4 (qtype+qclass)
        assert_eq!(qe, 12 + 13 + 4);
        assert_eq!(u16::from_be_bytes([q[4], q[5]]), 1, "QDCOUNT=1");
        assert_eq!(u16::from_be_bytes([q[6], q[7]]), 0, "ANCOUNT=0");
    }

    #[test]
    fn cname_with_chase_reply_produces_correct_multi_record_response() {
        let (q, qe) = a_query();
        let extra = vec![(1u16, 300u32, vec![1u8, 2, 3, 4])]; // A record 1.2.3.4
        let resp = cname_with_chase_reply(&q, qe, "alias.example.com", 60, &extra).unwrap();

        // ANCOUNT = 2 (CNAME + A)
        assert_eq!(u16::from_be_bytes([resp[6], resp[7]]), 2, "ANCOUNT must be 2");

        // First record: CNAME
        let ans = &resp[qe..];
        assert_eq!(&ans[0..2], &[0xC0, 0x0C], "CNAME NAME must be ptr to offset 12");
        assert_eq!(u16::from_be_bytes([ans[2], ans[3]]), 5, "first record TYPE must be CNAME");

        // CNAME RDATA encodes "alias.example.com"
        let rdlen = u16::from_be_bytes([ans[10], ans[11]]) as usize;
        let expected_rdata = encode_dns_name("alias.example.com").unwrap();
        assert_eq!(rdlen, expected_rdata.len());
        assert_eq!(&ans[12..12 + rdlen], expected_rdata.as_slice());

        // Second record: A record at ans[12 + rdlen..]
        let a_offset = 12 + rdlen;
        // NAME is a compression pointer
        assert_eq!(ans[a_offset] & 0xC0, 0xC0, "A record NAME must be a compression pointer");
        assert_eq!(
            u16::from_be_bytes([ans[a_offset + 2], ans[a_offset + 3]]),
            1,
            "A record TYPE must be 1"
        );
        assert_eq!(
            &ans[a_offset + 12..a_offset + 16],
            &[1, 2, 3, 4],
            "A record RDATA must be IP"
        );
    }

    #[test]
    fn encode_dns_name_produces_correct_wire_format() {
        let wire = encode_dns_name("example.com").unwrap();
        assert_eq!(wire, b"\x07example\x03com\x00");
    }

    #[test]
    fn encode_dns_name_strips_trailing_dot() {
        assert_eq!(
            encode_dns_name("example.com.").unwrap(),
            encode_dns_name("example.com").unwrap()
        );
    }

    #[test]
    fn encode_dns_name_root_is_single_zero_byte() {
        assert_eq!(encode_dns_name(".").unwrap(), b"\x00");
        assert_eq!(encode_dns_name("").unwrap(), b"\x00");
    }

    #[test]
    fn encode_dns_name_rejects_empty_label() {
        assert!(encode_dns_name("foo..bar").is_err());
    }

    #[test]
    fn encode_dns_name_rejects_label_over_63_bytes() {
        let long_label = "a".repeat(64);
        assert!(encode_dns_name(&long_label).is_err());
    }
}
