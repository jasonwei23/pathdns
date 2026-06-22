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
    assert_eq!(
        u16::from_be_bytes([resp[6], resp[7]]),
        1,
        "ANCOUNT must be 1"
    );

    // Answer section starts at question_end.
    let ans = &resp[qe..];
    assert_eq!(
        &ans[0..2],
        &[0xC0, 0x0C],
        "NAME must be a pointer to offset 12"
    );
    assert_eq!(u16::from_be_bytes([ans[2], ans[3]]), 1, "TYPE must be A");
    assert_eq!(u16::from_be_bytes([ans[4], ans[5]]), 1, "CLASS must be IN");
    assert_eq!(
        u32::from_be_bytes([ans[6], ans[7], ans[8], ans[9]]),
        60,
        "TTL"
    );
    assert_eq!(
        u16::from_be_bytes([ans[10], ans[11]]),
        4,
        "RDLENGTH must be 4"
    );
    assert_eq!(
        &ans[12..16],
        &[1, 2, 3, 4],
        "RDATA must be the IPv4 address"
    );
}

#[test]
fn aaaa_reply_has_correct_structure() {
    let (q, qe) = a_query();
    let addr: Ipv6Addr = "2001:db8::1".parse().unwrap();
    let resp = aaaa_reply(&q, qe, addr, 300).unwrap();

    assert_eq!(
        u16::from_be_bytes([resp[6], resp[7]]),
        1,
        "ANCOUNT must be 1"
    );
    let ans = &resp[qe..];
    assert_eq!(
        u16::from_be_bytes([ans[2], ans[3]]),
        28,
        "TYPE must be AAAA"
    );
    assert_eq!(
        u16::from_be_bytes([ans[10], ans[11]]),
        16,
        "RDLENGTH must be 16"
    );
    assert_eq!(
        &ans[12..28],
        &addr.octets(),
        "RDATA must be the IPv6 address"
    );
}

#[test]
fn cname_reply_has_correct_structure() {
    let (q, qe) = a_query();
    let resp = cname_reply(&q, qe, "alias.example.com", 120).unwrap();

    assert_eq!(
        u16::from_be_bytes([resp[6], resp[7]]),
        1,
        "ANCOUNT must be 1"
    );
    let ans = &resp[qe..];
    assert_eq!(
        u16::from_be_bytes([ans[2], ans[3]]),
        5,
        "TYPE must be CNAME"
    );
    // RDATA: \x05alias\x07example\x03com\x00 = 5+1 + 7+1 + 3+1 + 1 = 19 bytes
    let expected_rdata = encode_dns_name("alias.example.com").unwrap();
    let rdlen = u16::from_be_bytes([ans[10], ans[11]]) as usize;
    assert_eq!(rdlen, expected_rdata.len(), "RDLENGTH mismatch");
    assert_eq!(
        &ans[12..12 + rdlen],
        expected_rdata.as_slice(),
        "RDATA mismatch"
    );
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
    assert_eq!(
        u16::from_be_bytes([resp[6], resp[7]]),
        2,
        "ANCOUNT must be 2"
    );

    // First record: CNAME
    let ans = &resp[qe..];
    assert_eq!(
        &ans[0..2],
        &[0xC0, 0x0C],
        "CNAME NAME must be ptr to offset 12"
    );
    assert_eq!(
        u16::from_be_bytes([ans[2], ans[3]]),
        5,
        "first record TYPE must be CNAME"
    );

    // CNAME RDATA encodes "alias.example.com"
    let rdlen = u16::from_be_bytes([ans[10], ans[11]]) as usize;
    let expected_rdata = encode_dns_name("alias.example.com").unwrap();
    assert_eq!(rdlen, expected_rdata.len());
    assert_eq!(&ans[12..12 + rdlen], expected_rdata.as_slice());

    // Second record: A record at ans[12 + rdlen..]
    let a_offset = 12 + rdlen;
    // NAME is a compression pointer
    assert_eq!(
        ans[a_offset] & 0xC0,
        0xC0,
        "A record NAME must be a compression pointer"
    );
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
