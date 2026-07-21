#![no_main]

//! Fuzzes the pure DNS wire-format parsers in `pathdns::dns`.
//!
//! `data` stands in for either direction of untrusted wire bytes this crate
//! parses: a query arriving from a client, or a response arriving from an
//! upstream — both go through this same parsing surface (see `resolver.rs`
//! and `cache.rs`) before anything else is trusted. None of these functions
//! should ever panic or allocate unboundedly, no matter how malformed `data`
//! is; they only return `None`/`Err`/empty on bad input.

use libfuzzer_sys::fuzz_target;
use pathdns::config::EcsSubnet;
use pathdns::dns;
use std::net::{IpAddr, Ipv4Addr};

fuzz_target!(|data: &[u8]| {
    let _ = dns::is_reply(data);
    let _ = dns::is_truncated(data);
    let _ = dns::rcode(data);
    let _ = dns::get_id(data);
    let _ = dns::strip_opt_rdata(data);
    let _ = dns::strip_edns_ecs(data);

    let subnet = EcsSubnet {
        addr: IpAddr::V4(Ipv4Addr::new(203, 0, 113, 0)),
        prefix_len: 24,
    };
    let _ = dns::inject_or_replace_ecs(data, &subnet);

    if let Some(qend) = dns::question_end(data) {
        let _ = dns::extract_variant(data, qend);
        let _ = dns::client_udp_payload_size(data, qend);
        let _ = dns::answer_ips(data, qend);
        let _ = dns::answer_rr_types(data, qend);
        let _ = dns::question_qclass(data, qend);
        let _ = dns::extract_answer_records(data, qend);

        let question = data.get(12..qend).unwrap_or(&[]);
        let _ = dns::questions_match(question, question);

        // Same (nodata_ttl, min_ttl, max_ttl) shapes real call sites can pass
        // (see `cache.rs::ResolvedCachePolicy`), including the "no max" case.
        for (nodata_ttl, min_ttl, max_ttl) in [(0, 0, 0), (30, 0, 3600), (0, 60, 60)] {
            if let Some((_, offsets)) =
                dns::effective_ttl_and_offsets(data, qend, nodata_ttl, min_ttl, max_ttl)
            {
                // patch_ttls_at mutates in place; run on an owned copy so the
                // borrowed `data` fuzz input itself stays untouched.
                let mut owned = data.to_vec();
                dns::patch_ttls_at(&mut owned, &offsets, 1);
            }
        }
    }

    if let Ok(fast) = dns::parse_query_fast(data) {
        let variant = dns::extract_variant(data, fast.question_end);
        let _ = dns::parse_query_from_fast(data, fast, variant);
    }

    let _ = dns::maybe_truncate_for_udp(bytes::Bytes::copy_from_slice(data), data);
});
