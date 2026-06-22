use super::*;

/// Build a response: question `www.example.com <qtype>`, answer = CNAME chain
/// (one CNAME, owner via compression pointer) then one A record `95.100.196.60`
/// with TTL 18.  Returns `(packet, question_end)`.
fn chain_response(qtype: u16) -> (Vec<u8>, usize) {
    let mut p = Vec::new();
    p.extend_from_slice(&[0x12, 0x34]); // ID
    p.extend_from_slice(&[0x81, 0x80]); // flags: QR, RD, RA
    p.extend_from_slice(&[0x00, 0x01]); // QDCOUNT
    p.extend_from_slice(&[0x00, 0x02]); // ANCOUNT = CNAME + A
    p.extend_from_slice(&[0x00, 0x00]); // NSCOUNT
    p.extend_from_slice(&[0x00, 0x00]); // ARCOUNT
    p.extend_from_slice(b"\x03www\x07example\x03com\x00");
    p.extend_from_slice(&qtype.to_be_bytes()); // QTYPE
    p.extend_from_slice(&[0x00, 0x01]); // QCLASS IN
    let question_end = p.len();

    let target: &[u8] = b"\x03cdn\x07example\x03net\x00";
    // RR1 CNAME, owner = pointer to QNAME (offset 12)
    p.extend_from_slice(&[0xC0, 0x0C]);
    p.extend_from_slice(&[0x00, 0x05]); // TYPE CNAME
    p.extend_from_slice(&[0x00, 0x01]); // CLASS IN
    p.extend_from_slice(&[0x00, 0x00, 0x0B, 0x94]); // TTL 2964
    p.extend_from_slice(&(target.len() as u16).to_be_bytes());
    p.extend_from_slice(target);
    // RR2 A, owner = literal target name
    p.extend_from_slice(target);
    p.extend_from_slice(&[0x00, 0x01]); // TYPE A
    p.extend_from_slice(&[0x00, 0x01]); // CLASS IN
    p.extend_from_slice(&[0x00, 0x00, 0x00, 0x12]); // TTL 18
    p.extend_from_slice(&[0x00, 0x04]); // RDLEN
    p.extend_from_slice(&[95, 100, 196, 60]);
    (p, question_end)
}

#[test]
fn collapses_chain_to_single_record() {
    let (packet, qend) = chain_response(1); // A
    let out = collapse_cname_chain(&packet, qend).expect("should collapse");
    // One answer, no authority/additional.
    assert_eq!(u16::from_be_bytes([out[6], out[7]]), 1); // ANCOUNT
    assert_eq!(u16::from_be_bytes([out[8], out[9]]), 0); // NSCOUNT
    assert_eq!(u16::from_be_bytes([out[10], out[11]]), 0); // ARCOUNT
                                                           // Question section preserved (header counts differ, as expected).
    assert_eq!(&out[12..qend], &packet[12..qend]);
    // The single record: owner pointer 0xC00C, A/IN, TTL 18, the original IP.
    let rr = &out[qend..];
    assert_eq!(&rr[..2], &[0xC0, 0x0C]);
    assert_eq!(u16::from_be_bytes([rr[2], rr[3]]), 1); // A
    assert_eq!(u32::from_be_bytes([rr[6], rr[7], rr[8], rr[9]]), 18); // TTL kept
    assert_eq!(
        answer_ips(&out, qend).as_slice(),
        [std::net::IpAddr::from([95, 100, 196, 60])]
    );
}

#[test]
fn no_cname_is_left_untouched() {
    // ANCOUNT=1, just an A record (no CNAME) → nothing to collapse.
    let mut p = Vec::new();
    p.extend_from_slice(&[
        0x12, 0x34, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
    ]);
    p.extend_from_slice(b"\x03www\x07example\x03com\x00");
    p.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]);
    let qend = p.len();
    p.extend_from_slice(&[
        0xC0, 0x0C, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x12, 0x00, 0x04, 1, 2, 3, 4,
    ]);
    assert!(collapse_cname_chain(&p, qend).is_none());
}

#[test]
fn non_address_query_is_left_untouched() {
    let (packet, qend) = chain_response(15); // MX — RDATA may carry compressed names
    assert!(collapse_cname_chain(&packet, qend).is_none());
}

#[test]
fn chain_without_matching_address_is_left_untouched() {
    // AAAA query but the chain ends in an A record → no AAAA to keep.
    let (packet, qend) = chain_response(28);
    assert!(collapse_cname_chain(&packet, qend).is_none());
}
