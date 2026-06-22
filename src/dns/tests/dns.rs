use super::*;

#[test]
fn query_variant_layout_stays_compact() {
    assert!(std::mem::size_of::<EcsSrc>() <= 17);
    assert!(std::mem::size_of::<Option<EcsSrc>>() <= 18);
    assert!(std::mem::size_of::<QueryVariant>() <= 32);
}

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
        0x00, // root owner name
        0x00, 0x29, // type OPT (41)
        hi, lo, // UDP payload size
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
    assert_eq!(
        &stub[6..12],
        &[0, 0, 0, 0, 0, 0],
        "record counts not zeroed"
    );
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
    assert!(
        changed,
        "mix_qname_case should toggle at least some letters"
    );
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

#[test]
fn extract_answer_records_parses_a_record() {
    use crate::dns::builder;
    // Build a query for "example.com" type A
    let (q, qe) = {
        let mut q = vec![
            0xAB, 0xCD, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        q.extend_from_slice(b"\x07example\x03com\x00");
        q.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]);
        let qe = q.len();
        (q, qe)
    };
    let resp = builder::a_reply(&q, qe, "1.2.3.4".parse().unwrap(), 300).unwrap();
    let records = extract_answer_records(&resp, qe);
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].0, 1); // type A
    assert_eq!(records[0].1, 300); // ttl
    assert_eq!(records[0].2, vec![1, 2, 3, 4]);
}

#[test]
fn query_variant_hash_includes_more_than_eight_extra_options() {
    fn opt_rdata(codes: &[u16]) -> Vec<u8> {
        let mut out = Vec::new();
        for &code in codes {
            out.extend_from_slice(&code.to_be_bytes());
            out.extend_from_slice(&0u16.to_be_bytes());
        }
        out
    }

    let base = opt_rdata(&[1, 3, 5, 6, 7, 8, 9, 10]);
    let with_ninth = opt_rdata(&[1, 3, 5, 6, 7, 8, 9, 10, 13]);
    let (_, base_hash) = extract_opt_data(&base);
    let (_, with_ninth_hash) = extract_opt_data(&with_ninth);

    assert_ne!(
        base_hash, with_ninth_hash,
        "EDNS option codes after the eighth must affect cache variants"
    );
}
