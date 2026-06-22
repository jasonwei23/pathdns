use super::*;

/// "a." A IN — 7 bytes
fn q() -> Bytes {
    Bytes::from(vec![0x01, b'a', 0x00, 0x00, 0x01, 0x00, 0x01])
}

/// Build a DNS response with the given upstream ID, opcode, and QDCOUNT.
/// When qdcount > 0, `question` is repeated that many times in the question section.
fn build_response(
    upstream_id: u16,
    opcode: u8,
    qdcount: u16,
    question: &[u8],
) -> (BytesMut, usize) {
    let mut pkt = BytesMut::new();
    pkt.extend_from_slice(&upstream_id.to_be_bytes());
    pkt.extend_from_slice(&[0x80 | (opcode << 3), 0x80]); // QR=1, opcode, RA=1
    pkt.extend_from_slice(&qdcount.to_be_bytes());
    pkt.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x00, 0x00]); // AN/NS/AR=0
    for _ in 0..qdcount {
        pkt.extend_from_slice(question);
    }
    let len = pkt.len();
    (pkt, len)
}

#[test]
fn valid_response_delivered() {
    let reg = InflightRegistry::new(0);
    let question = q();
    let (uid, _rx, _guard) = reg.register("t", 0x9999, question.clone()).unwrap();
    let (mut buf, len) = build_response(uid, 0, 1, &question);
    assert!(matches!(reg.complete(&mut buf, len), Completion::Delivered));
}

#[test]
fn response_qdcount_zero_rejected() {
    let reg = InflightRegistry::new(0);
    let question = q();
    let (uid, _rx, _guard) = reg.register("t", 0x9999, question.clone()).unwrap();
    let (mut buf, len) = build_response(uid, 0, 0, &question);
    assert!(matches!(reg.complete(&mut buf, len), Completion::NoWaiter));
}

#[test]
fn response_qdcount_two_rejected() {
    let reg = InflightRegistry::new(0);
    let question = q();
    let (uid, _rx, _guard) = reg.register("t", 0x9999, question.clone()).unwrap();
    let (mut buf, len) = build_response(uid, 0, 2, &question);
    assert!(matches!(reg.complete(&mut buf, len), Completion::NoWaiter));
}

#[test]
fn response_non_query_opcode_rejected() {
    let reg = InflightRegistry::new(0);
    let question = q();
    let (uid, _rx, _guard) = reg.register("t", 0x9999, question.clone()).unwrap();
    // opcode=4 (NOTIFY)
    let (mut buf, len) = build_response(uid, 4, 1, &question);
    assert!(matches!(reg.complete(&mut buf, len), Completion::NoWaiter));
}

#[test]
fn inflight_cap_blocks_and_releases() {
    let reg = InflightRegistry::new(2);
    let q = q();
    let r1 = reg.register("t", 1, q.clone()).unwrap();
    let r2 = reg.register("t", 2, q.clone()).unwrap();
    // Cap reached: third registration must fail.
    assert!(reg.register("t", 3, q.clone()).is_err());
    // Drop one guard; capacity is returned atomically.
    drop(r1);
    let _r3 = reg.register("t", 4, q.clone()).unwrap();
    // Still at cap: another must fail.
    assert!(reg.register("t", 5, q.clone()).is_err());
    drop(r2);
    drop(_r3);
    // All released: should accept again.
    assert!(reg.register("t", 6, q.clone()).is_ok());
}
