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
            p.extend(std::iter::repeat_n(b'a', label_len));
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
