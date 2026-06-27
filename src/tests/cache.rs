use super::*;
use crate::config::{CacheConfig, RuleCachePolicy};

fn base_cache_config() -> CacheConfig {
    CacheConfig {
        capacity: 256,
        min_ttl: 0,
        max_ttl: 0,
    }
}

fn no_override_policy() -> RuleCachePolicy {
    RuleCachePolicy {
        skip: false,
        min_ttl: None,
        max_ttl: None,
    }
}

/// Build a minimal DNS A-record response + matching query for "test.local".
/// Returns (response_packet, query_packet, question_end).
fn make_test_packets(ttl: u32) -> (Vec<u8>, Vec<u8>, usize) {
    // qname: \x04test\x05local\x00 (12 bytes)
    let qname: &[u8] = b"\x04test\x05local\x00";

    let mut query = vec![
        0x00, 0x01, // ID = 1
        0x01, 0x00, // QR=0, RD=1
        0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];
    query.extend_from_slice(qname);
    query.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]); // type A, class IN
    let question_end = query.len(); // 12 + 12 + 4 = 28

    let mut response = vec![
        0x00, 0x01, // ID = 1
        0x81, 0x80, // QR=1, RD=1, RA=1, RCODE=0
        0x00, 0x01, // QDCOUNT = 1
        0x00, 0x01, // ANCOUNT = 1
        0x00, 0x00, 0x00, 0x00,
    ];
    // Question section
    response.extend_from_slice(qname);
    response.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]);
    // Answer RR: name + type + class + TTL + rdlength + rdata
    // TTL offset in this packet = 28 (question_end) + 12 (qname) + 4 (type+class) = 44
    response.extend_from_slice(qname);
    response.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]);
    response.extend_from_slice(&ttl.to_be_bytes());
    response.extend_from_slice(&[0x00, 0x04, 1, 2, 3, 4]);

    (response, query, question_end)
}

/// Read the wire TTL from the first answer record of a packet produced by
/// `make_test_packets`. The TTL sits at offset 44 in that layout.
fn read_wire_ttl(pkt: &[u8]) -> u32 {
    u32::from_be_bytes(pkt[44..48].try_into().unwrap())
}

/// Look up via the production `_into` path and return the response packet, so
/// tests exercise the same lookup code as the live UDP fast path.
fn lookup_packet(
    cache: &DnsCache,
    query: &[u8],
    question_end: usize,
    client_id: u16,
) -> Option<Bytes> {
    let mut buf = BytesMut::new();
    cache.get_into_with_ecs_fallback(query, question_end, client_id, &mut buf)?;
    Some(buf.freeze())
}

fn add_to_cache(cache: &DnsCache, ttl: u32, policy: Option<&RuleCachePolicy>) -> (Vec<u8>, usize) {
    let (response, query, question_end) = make_test_packets(ttl);
    let key = cache_key(&query, question_end);
    let resolved = cache.resolve_policy(policy);
    cache.add(
        CacheInsert {
            key,
            qname: Arc::from("test.local"),
            question_end,
            query: &query,
            packet: &response,
        },
        &resolved,
        0u16,
    );
    (query, question_end)
}

#[test]
fn per_rule_min_ttl_raises_wire_ttl() {
    let cache = DnsCache::new(&base_cache_config());
    let policy = RuleCachePolicy {
        min_ttl: Some(60),
        ..no_override_policy()
    };
    let (query, question_end) = add_to_cache(&cache, 10, Some(&policy));
    let pkt = lookup_packet(&cache, &query, question_end, 1).expect("expected cache hit");
    // DNS said 10s, rule min_ttl=60 → wire TTL must be at least 60.
    assert_eq!(read_wire_ttl(&pkt), 60);
}

#[test]
fn per_rule_max_ttl_caps_wire_ttl() {
    let cache = DnsCache::new(&base_cache_config());
    let policy = RuleCachePolicy {
        max_ttl: Some(300),
        ..no_override_policy()
    };
    let (query, question_end) = add_to_cache(&cache, 3600, Some(&policy));
    let pkt = lookup_packet(&cache, &query, question_end, 1).expect("expected cache hit");
    // DNS said 3600s, rule max_ttl=300 → wire TTL must not exceed 300.
    assert_eq!(read_wire_ttl(&pkt), 300);
}

#[test]
fn global_min_ttl_applied_as_fallback() {
    let mut cfg = base_cache_config();
    cfg.min_ttl = 45;
    let cache = DnsCache::new(&cfg);
    let (query, question_end) = add_to_cache(&cache, 5, None);
    let pkt = lookup_packet(&cache, &query, question_end, 1).expect("expected cache hit");
    assert_eq!(read_wire_ttl(&pkt), 45);
}

#[test]
fn global_max_ttl_applied_as_fallback() {
    let mut cfg = base_cache_config();
    cfg.max_ttl = 120;
    let cache = DnsCache::new(&cfg);
    let (query, question_end) = add_to_cache(&cache, 86400, None);
    let pkt = lookup_packet(&cache, &query, question_end, 1).expect("expected cache hit");
    assert_eq!(read_wire_ttl(&pkt), 120);
}

#[test]
fn per_rule_policy_overrides_global_min_ttl() {
    // Global min=30, rule min=5. Rule should win: wire TTL = max(ttl, 5) not max(ttl, 30).
    let mut cfg = base_cache_config();
    cfg.min_ttl = 30;
    let cache = DnsCache::new(&cfg);
    let policy = RuleCachePolicy {
        min_ttl: Some(5),
        ..no_override_policy()
    };
    let (query, question_end) = add_to_cache(&cache, 10, Some(&policy));
    let pkt = lookup_packet(&cache, &query, question_end, 1).expect("expected cache hit");
    // With rule min_ttl=5 taking precedence, wire TTL = 10 (the DNS TTL, since 10 > 5).
    assert_eq!(read_wire_ttl(&pkt), 10);
}

#[test]
fn edns_variant_does_not_share_cache_entry() {
    let cache = DnsCache::new(&base_cache_config());
    let (response, query, question_end) = make_test_packets(100);
    let resolved = cache.resolve_policy(None);
    cache.add(
        CacheInsert {
            key: cache_key(&query, question_end),
            qname: Arc::from("test.local"),
            question_end,
            query: &query,
            packet: &response,
        },
        &resolved,
        0,
    );

    let mut edns_query = query.clone();
    edns_query[11] = 1; // ARCOUNT = 1
    edns_query.extend_from_slice(&[
        0x00, // root owner name
        0x00, 0x29, // OPT
        0x10, 0x00, // UDP payload size
        0x00, 0x00, 0x80, 0x00, // DO flag
        0x00, 0x00, // RDLEN
    ]);

    assert!(lookup_packet(&cache, &edns_query, question_end, 2).is_none());
}

/// Build a query packet that includes an EDNS OPT record.
fn make_edns_query(do_bit: bool) -> (Vec<u8>, usize) {
    let (_, mut query, question_end) = make_test_packets(100);
    query[11] = 1; // ARCOUNT = 1
    let do_byte: u8 = if do_bit { 0x80 } else { 0x00 };
    query.extend_from_slice(&[
        0x00, // root owner name
        0x00, 0x29, // type OPT (41)
        0x10, 0x00, // UDP payload size = 4096
        0x00, 0x00, // ext-rcode, EDNS version 0
        do_byte, 0x00, // flags — DO bit in high byte
        0x00, 0x00, // RDLEN = 0
    ]);
    (query, question_end)
}

/// Build a query with an EDNS OPT record containing an ECS option.
/// `src_ip_last_octet` varies the source address (/24 prefix).
fn make_ecs_query(src_ip_last_octet: u8) -> (Vec<u8>, usize) {
    let (_, mut query, question_end) = make_test_packets(100);
    // ECS OPTION-DATA: FAMILY=1 (IPv4), SOURCE-PREFIX-LENGTH=24, SCOPE=0, ADDRESS=1.2.X.0
    let ecs_data: [u8; 7] = [
        0x00,
        0x01, // FAMILY = 1
        24,   // SOURCE-PREFIX-LENGTH
        0x00, // SCOPE-PREFIX-LENGTH
        1,
        2,
        src_ip_last_octet, // Address — 3 bytes for /24
    ];
    let opt_rdata_len: u16 = 4 + ecs_data.len() as u16; // code(2) + len(2) + data
    query[11] = 1; // ARCOUNT = 1
    query.extend_from_slice(&[
        0x00, // root owner name
        0x00, 0x29, // type OPT
        0x10, 0x00, // UDP payload size
        0x00, 0x00, // ext-rcode, version
        0x00, 0x00, // flags
    ]);
    query.extend_from_slice(&opt_rdata_len.to_be_bytes()); // RDLEN
    query.extend_from_slice(&[0x00, 0x08]); // OPTION-CODE = 8 (ECS, RFC 7871)
    query.extend_from_slice(&(ecs_data.len() as u16).to_be_bytes()); // OPTION-LENGTH
    query.extend_from_slice(&ecs_data);
    (query, question_end)
}

#[test]
fn do_bit_zero_and_one_use_separate_cache_entries() {
    let cache = DnsCache::new(&base_cache_config());
    let (response, _, _) = make_test_packets(100);
    let resolved = cache.resolve_policy(None);

    // Cache a response under a DO=0 EDNS query.
    let (query_do0, question_end) = make_edns_query(false);
    cache.add(
        CacheInsert {
            key: cache_key(&query_do0, question_end),
            qname: Arc::from("test.local"),
            question_end,
            query: &query_do0,
            packet: &response,
        },
        &resolved,
        0,
    );

    // A DO=1 query must not hit the DO=0 entry.
    let (query_do1, _) = make_edns_query(true);
    assert!(
        lookup_packet(&cache, &query_do1, question_end, 1).is_none(),
        "DO=1 query must not share a DO=0 cache entry"
    );

    // After caching a DO=1 response, that same DO=1 query must hit.
    cache.add(
        CacheInsert {
            key: cache_key(&query_do1, question_end),
            qname: Arc::from("test.local"),
            question_end,
            query: &query_do1,
            packet: &response,
        },
        &resolved,
        0,
    );
    assert!(
        lookup_packet(&cache, &query_do1, question_end, 1).is_some(),
        "DO=1 query must hit its own cache entry"
    );
}

#[test]
fn ecs_source_subnet_isolates_cache_entries() {
    let cache = DnsCache::new(&base_cache_config());
    let (response, _, _) = make_test_packets(100);
    let resolved = cache.resolve_policy(None);

    // Cache a response for ECS subnet 1.2.3.0/24.
    let (query_a, question_end) = make_ecs_query(3);
    cache.add(
        CacheInsert {
            key: cache_key(&query_a, question_end),
            qname: Arc::from("test.local"),
            question_end,
            query: &query_a,
            packet: &response,
        },
        &resolved,
        0,
    );

    // A query from a different /24 subnet must miss.
    let (query_b, _) = make_ecs_query(4);
    assert!(
        lookup_packet(&cache, &query_b, question_end, 1).is_none(),
        "ECS 1.2.4.0/24 must not share an entry cached for 1.2.3.0/24"
    );

    // The original subnet must still hit.
    assert!(
        lookup_packet(&cache, &query_a, question_end, 1).is_some(),
        "ECS 1.2.3.0/24 query must still hit its own entry"
    );
}

#[test]
fn cache_key_strip_ecs_matches_no_ecs_query() {
    // With no ECS, strip_ecs key should equal normal key
    let (_, query, question_end) = make_test_packets(100);
    assert_eq!(
        cache_key(&query, question_end),
        cache_key_strip_ecs(&query, question_end)
    );
}

#[test]
fn ecs_fallback_lookup_finds_strip_ecs_entry() {
    let cache = DnsCache::new(&base_cache_config());
    let (response, _, _) = make_test_packets(100);
    let resolved = cache.resolve_policy(None);

    // Cache a response with an ECS query from one subnet, using strip_ecs key
    let (query_a, question_end) = make_ecs_query(3);
    let stripped = dns::strip_edns_ecs(&query_a).unwrap();
    let key = cache_key_strip_ecs(&query_a, question_end);
    cache.add(
        CacheInsert {
            key,
            qname: Arc::from("test.local"),
            question_end,
            query: &stripped,
            packet: &response,
        },
        &resolved,
        0,
    );

    // A different ECS subnet should find the strip_ecs cached entry via fallback
    let (query_b, _) = make_ecs_query(77);
    let mut buf = BytesMut::new();
    assert!(
        cache
            .get_into_with_ecs_fallback(&query_b, question_end, 1, &mut buf)
            .is_some(),
        "ECS fallback should find the strip-ecs cached entry"
    );
}

#[test]
fn cache_hit_restores_current_question_case() {
    let cache = DnsCache::new(&base_cache_config());
    let (query, question_end) = add_to_cache(&cache, 100, None);
    let mut mixed_case_query = query;
    mixed_case_query[13..17].copy_from_slice(b"TeSt");
    mixed_case_query[18..23].copy_from_slice(b"LoCaL");

    let pkt = lookup_packet(&cache, &mixed_case_query, question_end, 2)
        .expect("expected case-insensitive cache hit");

    assert_eq!(&pkt[12..question_end], &mixed_case_query[12..question_end]);
}

// Run with: cargo test --release hot_path_bench -- --ignored --nocapture
#[test]
#[ignore]
fn hot_path_bench() {
    use std::hint::black_box;
    use std::time::Instant;

    fn report(label: &str, t: Instant, iters: usize) {
        let ns = t.elapsed().as_nanos() as f64 / iters as f64;
        eprintln!("  {label:42} {ns:8.1} ns/op");
    }

    // Realistic client query: EDNS OPT present (the additional section extract_variant
    // must scan), no ECS.
    let mut q = vec![
        0x00, 0x01, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
    ];
    q.extend_from_slice(b"\x04test\x05local\x00");
    q.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]); // A IN
    let qe = q.len();
    // OPT RR: root name, type 41, udpsize 4096, ext-rcode/flags 0, rdlen 0
    q.extend_from_slice(&[
        0x00, 0x00, 0x29, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ]);

    let (response, _plain_q, _plain_qe) = make_test_packets(300);
    let cache = DnsCache::new(&base_cache_config());
    let variant = dns::extract_variant(&q, qe);
    let key = cache_key_with_variant(&q, qe, &variant, false);
    cache.add(
        CacheInsert {
            key,
            qname: Arc::from("test.local"),
            question_end: qe,
            query: &q,
            packet: &response,
        },
        &cache.resolve_policy(None),
        0u16,
    );
    assert!(
        lookup_packet(&cache, &q, qe, 1234).is_some(),
        "must be a cache hit"
    );

    let iters = 5_000_000usize;

    eprintln!("\n== cache-HIT hot path (EDNS query, 'test.local' A) ==");
    {
        let mut buf = BytesMut::with_capacity(512);
        let t = Instant::now();
        for _ in 0..iters {
            buf.clear();
            black_box(cache.get_into_with_ecs_fallback(black_box(&q), qe, 1234, &mut buf));
        }
        report("get_into_with_ecs_fallback (full)", t, iters);
    }
    {
        let t = Instant::now();
        for _ in 0..iters {
            black_box(dns::extract_variant(black_box(&q), qe));
        }
        report("└ dns::extract_variant", t, iters);
    }
    {
        let v = dns::extract_variant(&q, qe);
        let t = Instant::now();
        for _ in 0..iters {
            black_box(cache_key_with_variant(black_box(&q), qe, &v, false));
        }
        report("└ cache_key_with_variant", t, iters);
    }
    {
        let t = Instant::now();
        for _ in 0..iters {
            let _ = black_box(dns::parse_query_fast(black_box(&q)));
        }
        report("dns::parse_query_fast (separate)", t, iters);
    }
    {
        // Raw Moka get of the entry by key (isolates the concurrent-cache cost from
        // the variant/key/compare/copy work around it).
        let inner = cache.cache.as_ref().unwrap();
        let t = Instant::now();
        for _ in 0..iters {
            black_box(inner.get(black_box(&key)));
        }
        report("└ raw Moka cache.get(key)", t, iters);
    }
    eprintln!();
}
