use super::bootstrap::{build_bootstrap_query, skip_dns_name};
use super::upstream_url::parse_upstream;
use super::*;

fn parse(input: &str) -> Result<Config> {
    let json: JsonConfig = serde_json::from_str(input)?;
    Config::from_json(json)
}

// Shorthand used in many tests: minimal valid config (one rule, final omitted
// so the rule is also the fallback).
fn min_cfg() -> &'static str {
    r#"{"route":{"rules":[{"name":"r","upstream":["1.1.1.1"]}]}}"#
}

#[test]
fn answer_map_omitted_is_empty() {
    let cfg = parse(min_cfg()).unwrap();
    assert!(cfg.answer_map.is_empty());
}

#[test]
fn answer_map_parses_mixed_answer_types() {
    let cfg = parse(
        r#"{"route":{"rules":[{"name":"r","upstream":["1.1.1.1"]}],"answer":{
                "a.example.com": "CNAME://target-a.com",
                "b.example.com": ["A://1.2.3.4", "AAAA://::1"],
                "ads.example.com": "RCODE://NXDOMAIN"
            }}}"#,
    )
    .unwrap();
    assert_eq!(cfg.answer_map.len(), 3);
    // Suffix match (bare key) covers subdomains.
    assert!(cfg.answer_map.lookup("www.a.example.com", None).is_some());
    let b = cfg.answer_map.lookup("b.example.com", None).unwrap();
    assert_eq!(b.fixed_answers.len(), 2);
    let ads = cfg.answer_map.lookup("ads.example.com", None).unwrap();
    assert!(ads.fixed_rcode.is_some());
}

#[test]
fn answer_map_accepts_tag_keys() {
    let cfg = parse(
        r#"{"route":{"geosite":["x.dat"],"rules":[{"name":"r","upstream":["1.1.1.1"]}],"answer":{
                "tag:ads,!whitelist": "RCODE://NXDOMAIN"
            }}}"#,
    )
    .unwrap();
    assert_eq!(cfg.answer_map.len(), 1);
    let tags: std::collections::HashSet<&str> = cfg.answer_map.referenced_tags().collect();
    assert!(tags.contains("ads"));
    assert!(tags.contains("whitelist"));
}

#[test]
fn answer_map_rejects_real_upstream() {
    assert!(parse(
        r#"{"route":{"rules":[{"name":"r","upstream":["1.1.1.1"]}],"answer":{"a.com":"8.8.8.8"}}}"#
    )
    .is_err());
}

#[test]
fn answer_map_rejects_mixing_rcode_and_fixed() {
    assert!(parse(
            r#"{"route":{"rules":[{"name":"r","upstream":["1.1.1.1"]}],"answer":{"a.com":["A://1.2.3.4","RCODE://NXDOMAIN"]}}}"#
        )
        .is_err());
}

#[test]
fn answer_map_rejects_cname_with_a() {
    assert!(parse(
            r#"{"route":{"rules":[{"name":"r","upstream":["1.1.1.1"]}],"answer":{"a.com":["CNAME://t.com","A://1.2.3.4"]}}}"#
        )
        .is_err());
}

#[test]
fn omitted_dashboard_is_fully_disabled() {
    let cfg = parse(min_cfg()).unwrap();
    assert!(!cfg.dashboard.enabled);
    assert_eq!(cfg.dashboard.memory, 0);
    assert!(cfg.dashboard.bind.is_empty());
    assert!(cfg.dashboard.file.is_none());
}

#[test]
fn present_dashboard_uses_safe_defaults() {
    let cfg = parse(r#"{"route":{"rules":[{"name":"r","upstream":["1.1.1.1"]}]},"dashboard":{}}"#)
        .unwrap();
    assert!(cfg.dashboard.enabled);
    assert_eq!(cfg.dashboard.memory, 1000);
    assert_eq!(cfg.dashboard.channel, 4096);
    assert!(!cfg.dashboard.answer_ips);
}

#[test]
fn tcp_defaults_are_protective() {
    let cfg = parse(min_cfg()).unwrap();
    assert_eq!(cfg.tcp_max_connections, 1024);
    assert_eq!(cfg.tcp_read_timeout_ms, 5000);
    assert_eq!(cfg.tcp_idle_timeout_ms, 30_000);
}

#[test]
fn tcp_zero_means_unlimited_or_disabled() {
    let cfg = parse(
        r#"{"route":{"rules":[{"name":"r","upstream":["1.1.1.1"]}]},
                "runtime":{"tcp-max-connections":0,
                          "tcp-read-timeout-ms":0,
                          "tcp-idle-timeout-ms":0}}"#,
    )
    .unwrap();
    assert_eq!(cfg.tcp_max_connections, 0);
    assert_eq!(cfg.tcp_read_timeout_ms, 0);
    assert_eq!(cfg.tcp_idle_timeout_ms, 0);
}

#[test]
fn tcp_custom_values_are_accepted() {
    let cfg = parse(
        r#"{"route":{"rules":[{"name":"r","upstream":["1.1.1.1"]}]},
                "runtime":{"tcp-max-connections":256,
                          "tcp-read-timeout-ms":2000,
                          "tcp-idle-timeout-ms":10000}}"#,
    )
    .unwrap();
    assert_eq!(cfg.tcp_max_connections, 256);
    assert_eq!(cfg.tcp_read_timeout_ms, 2000);
    assert_eq!(cfg.tcp_idle_timeout_ms, 10_000);
}

#[test]
fn invalid_dashboard_limits_are_rejected() {
    assert!(parse(
        r#"{"route":{"rules":[{"name":"r","upstream":["1.1.1.1"]}]},"dashboard":{"channel":0}}"#
    )
    .is_err());
    assert!(parse(r#"{"route":{"rules":[{"name":"r","upstream":["1.1.1.1"]}]},"dashboard":{"file":{"max-mb":0}}}"#).is_err());
    assert!(parse(r#"{"route":{"rules":[{"name":"r","upstream":["1.1.1.1"]}]},"dashboard":{"file":{"max-segments":0}}}"#).is_err());
}

#[test]
fn bind_object_with_proto_udp() {
    let cfg = parse(r#"{"route":{"rules":[{"name":"r","upstream":["1.1.1.1"]}]},"bind":{"addr":"0.0.0.0","port":53,"proto":"udp"}}"#).unwrap();
    assert_eq!(cfg.bind.len(), 1);
    assert!(cfg.bind[0].udp);
    assert!(!cfg.bind[0].tcp);
}

#[test]
fn bind_object_dual_stack() {
    let cfg = parse(
        r#"{"route":{"rules":[{"name":"r","upstream":["1.1.1.1"]}]},
                "bind":{"addr":["0.0.0.0","::"],"port":53}}"#,
    )
    .unwrap();
    assert_eq!(cfg.bind.len(), 2);
    assert!(cfg.bind[0].addr.is_ipv4());
    assert!(cfg.bind[0].udp);
    assert!(cfg.bind[0].tcp);
    assert!(cfg.bind[1].addr.is_ipv6());
    assert!(cfg.bind[1].udp);
    assert!(cfg.bind[1].tcp);
}

#[test]
fn bind_object_rejects_invalid_proto() {
    assert!(parse(
        r#"{"route":{"rules":[{"name":"r","upstream":["1.1.1.1"]}]},"bind":{"proto":"bogus"}}"#
    )
    .is_err());
}

#[test]
fn bind_object_rejects_duplicate_addr() {
    assert!(parse(r#"{"route":{"rules":[{"name":"r","upstream":["1.1.1.1"]}]},"bind":{"addr":["0.0.0.0","0.0.0.0"],"port":53}}"#).is_err());
}

#[test]
fn bind_object_addr_with_port_is_rejected() {
    assert!(parse(r#"{"route":{"rules":[{"name":"r","upstream":["1.1.1.1"]}]},"bind":{"addr":"0.0.0.0:53","port":53}}"#).is_err());
}

#[test]
fn route_final_omitted_uses_last_rule() {
    let cfg = parse(
        r#"{"route":{"rules":[
                  {"name":"a","upstream":["1.1.1.1"]},
                  {"name":"b","upstream":["8.8.8.8"]}]}}"#,
    )
    .unwrap();
    assert!(matches!(&cfg.fallback.target, FallbackTarget::Rule(g) if g == "b"));
}

#[test]
fn route_final_omitted_with_empty_rules_rejected() {
    assert!(parse(r#"{"route":{}}"#).is_err());
}

#[test]
fn route_final_null_is_just_a_missing_rule() {
    // There is no special "null" fallback; it's treated as a (nonexistent) rule name.
    assert!(
        parse(r#"{"route":{"rules":[{"name":"a","upstream":["1.1.1.1"]}],"final":"null"}}"#)
            .is_err()
    );
}

#[test]
fn route_final_string_rule() {
    let cfg =
        parse(r#"{"route":{"rules":[{"name":"a","upstream":["1.1.1.1"]}],"final":"a"}}"#).unwrap();
    assert!(matches!(&cfg.fallback.target, FallbackTarget::Rule(g) if g == "a"));
}

#[test]
fn route_final_unknown_rule_rejected() {
    assert!(parse(r#"{"route":{"final":"nope"}}"#).is_err());
}

#[test]
fn route_final_ipset_test_mode() {
    let cfg = parse(
        r#"{"route":{"rules":[
                  {"name":"a","upstream":["1.1.1.1"]},
                  {"name":"b","upstream":["8.8.8.8"]}],
                "final":{"primary":"a","secondary":"b",
                         "ipset4":"chnroute","ipset6":"chnroute6"}}}"#,
    )
    .unwrap();
    assert!(matches!(
        &cfg.fallback.target,
        FallbackTarget::Dual { primary, secondary, ipset: Some(_) }
            if primary == "a" && secondary == "b"
    ));
}

#[test]
fn route_final_ipset_test_requires_ipset() {
    assert!(parse(
        r#"{"route":{"rules":[
                  {"name":"a","upstream":["1.1.1.1"]},
                  {"name":"b","upstream":["8.8.8.8"]}],
                "final":{"primary":"a","secondary":"b"}}}"#,
    )
    .is_err());
}

#[test]
fn route_final_empty_object_rejected() {
    assert!(parse(r#"{"route":{"final":{}}}"#).is_err());
}

#[test]
fn route_final_verdict_cache_parsed() {
    let cfg = parse(
        r#"{"route":{"rules":[
                  {"name":"a","upstream":["1.1.1.1"]},
                  {"name":"b","upstream":["8.8.8.8"]}],
                "final":{"primary":"a","secondary":"b",
                         "ipset4":"r",
                         "verdict-cache":{"size":100,"ttl":60}}}}"#,
    )
    .unwrap();
    let vc = cfg.verdict_cache.as_ref().expect("verdict_cache present");
    assert_eq!(vc.capacity, 100);
    assert_eq!(vc.ttl.as_secs(), 60);
}

#[test]
fn dashboard_port_derives_from_bind_addresses() {
    let cfg = parse(
        r#"{"route":{"rules":[{"name":"r","upstream":["1.1.1.1"]}]},
                "bind":{"addr":["127.0.0.1","[::1]"],"port":53},
                "dashboard":{"port":8080}}"#,
    )
    .unwrap();
    assert_eq!(cfg.dashboard.bind.len(), 2);
    assert_eq!(cfg.dashboard.bind[0].0.port(), 8080);
    assert!(cfg.dashboard.bind[0].0.ip().is_loopback());
    assert!(cfg.dashboard.bind[0].1.is_none()); // no interface
    assert_eq!(cfg.dashboard.bind[1].0.port(), 8080);
}

#[test]
fn dashboard_port_with_interface_adds_so_bindtodevice() {
    let cfg = parse(
        r#"{"route":{"rules":[{"name":"r","upstream":["1.1.1.1"]}]},
                "bind":{"addr":"0.0.0.0","port":53,"interface":["br-lan"]},
                "dashboard":{"port":8080}}"#,
    )
    .unwrap();
    assert_eq!(cfg.dashboard.bind.len(), 1);
    assert_eq!(cfg.dashboard.bind[0].0.port(), 8080);
    assert_eq!(cfg.dashboard.bind[0].1.as_deref(), Some("br-lan"));
}

#[test]
fn dashboard_port_zero_is_rejected() {
    assert!(parse(
        r#"{"route":{"rules":[{"name":"r","upstream":["1.1.1.1"]}]},"dashboard":{"port":0}}"#
    )
    .is_err());
}

#[test]
fn interface_omitted_defaults_to_all() {
    let cfg = parse(min_cfg()).unwrap();
    assert!(matches!(cfg.interface, InterfaceFilter::All));
}

#[test]
fn interface_empty_array_means_all() {
    let cfg = parse(
        r#"{"route":{"rules":[{"name":"r","upstream":["1.1.1.1"]}]},"bind":{"interface":[]}}"#,
    )
    .unwrap();
    assert!(matches!(cfg.interface, InterfaceFilter::All));
}

#[test]
fn interface_allow_list_parsed() {
    let cfg = parse(r#"{"route":{"rules":[{"name":"r","upstream":["1.1.1.1"]}]},"bind":{"interface":["eth0","br-lan"]}}"#).unwrap();
    match &cfg.interface {
        InterfaceFilter::Only(ifaces) => {
            assert_eq!(ifaces, &["eth0", "br-lan"]);
        }
        other => panic!("expected Only, got {other:?}"),
    }
}

#[test]
fn interface_deny_list_parsed() {
    let cfg = parse(r#"{"route":{"rules":[{"name":"r","upstream":["1.1.1.1"]}]},"bind":{"interface":["!wan","!eth1"]}}"#).unwrap();
    match &cfg.interface {
        InterfaceFilter::Except(excluded) => {
            assert_eq!(excluded, &["wan", "eth1"]);
        }
        other => panic!("expected Except, got {other:?}"),
    }
}

#[test]
fn interface_mixed_allow_deny_rejected() {
    assert!(parse(r#"{"route":{"rules":[{"name":"r","upstream":["1.1.1.1"]}]},"bind":{"interface":["eth0","!wan"]}}"#).is_err());
}

#[test]
fn interface_bare_bang_rejected() {
    assert!(parse(
        r#"{"route":{"rules":[{"name":"r","upstream":["1.1.1.1"]}]},"bind":{"interface":["!"]}}"#
    )
    .is_err());
}

#[test]
fn interface_empty_name_rejected() {
    assert!(parse(
        r#"{"route":{"rules":[{"name":"r","upstream":["1.1.1.1"]}]},"bind":{"interface":[""]}}"#
    )
    .is_err());
}

// ── bootstrap-addr tests ──────────────────────────────────────────────────

#[test]
fn parse_bootstrap_addr_accepts_ip_literals() {
    let a = parse_bootstrap_addr("8.8.8.8").unwrap();
    assert_eq!(a.port(), 53);
    let b = parse_bootstrap_addr("1.1.1.1:53").unwrap();
    assert_eq!(b.port(), 53);
    let c = parse_bootstrap_addr("[::1]:5353").unwrap();
    assert_eq!(c.port(), 5353);
}

#[test]
fn parse_bootstrap_addr_rejects_hostname() {
    let err = parse_bootstrap_addr("dns.google").unwrap_err();
    assert!(err.to_string().contains("?bootstrap="), "error: {err}");
}

#[test]
fn authority_port_returns_default_when_absent() {
    assert_eq!(authority_port("dns.google", 443), 443);
    assert_eq!(authority_port("8.8.8.8", 53), 53);
}

#[test]
fn authority_port_reads_explicit_port() {
    assert_eq!(authority_port("dns.google:853", 443), 853);
    assert_eq!(authority_port("[::1]:5353", 53), 5353);
}

#[test]
fn resolve_host_ip_literal_no_dns() {
    let addr = resolve_host("8.8.8.8", 53, &[]).unwrap();
    assert_eq!(addr.to_string(), "8.8.8.8:53");
    let addr6 = resolve_host("::1", 443, &[]).unwrap();
    assert_eq!(addr6.port(), 443);
}

#[test]
fn build_bootstrap_query_produces_valid_header() {
    let pkt = build_bootstrap_query("example.com", 1).unwrap();
    // Byte 2 = 0x01 (RD=1), byte 3 = 0x00, QDCOUNT big-endian = 1
    assert_eq!(pkt[2], 0x01);
    assert_eq!(pkt[5], 0x01);
    // QTYPE A at the end (before QCLASS)
    let qtype = u16::from_be_bytes([pkt[pkt.len() - 4], pkt[pkt.len() - 3]]);
    assert_eq!(qtype, 1);
}

#[test]
fn skip_dns_name_handles_root_label() {
    let buf = [0u8]; // single root label
    assert_eq!(skip_dns_name(&buf, 0).unwrap(), 1);
}

#[test]
fn skip_dns_name_handles_pointer() {
    let buf = [0xC0, 0x0C]; // pointer to offset 12
    assert_eq!(skip_dns_name(&buf, 0).unwrap(), 2);
}

#[test]
fn upstream_ip_literal_needs_no_bootstrap() {
    // IP-literal upstreams resolve without any ?bootstrap= parameter.
    let ep = parse_upstream("https://8.8.8.8/dns-query?sni=dns.google").unwrap();
    assert_eq!(ep.len(), 1);
    assert_eq!(ep[0].addr, "8.8.8.8:443".parse().unwrap());
    assert_eq!(ep[0].server_name.as_deref(), Some("dns.google"));
}

#[test]
fn upstream_hostname_without_bootstrap_is_error() {
    let err = parse_upstream("tls://dns.google").unwrap_err();
    // Use {err:#} to include the full error chain (outermost is the context wrapper).
    let msg = format!("{err:#}");
    assert!(
        msg.contains("?bootstrap="),
        "expected ?bootstrap= in: {msg}"
    );
}

#[test]
fn upstream_bootstrap_param_accepted_on_ip_literal() {
    // ?bootstrap= on an IP-literal upstream: param is validated but not used.
    let ep = parse_upstream("tls://8.8.8.8?bootstrap=223.5.5.5").unwrap();
    assert_eq!(ep.len(), 1);
    assert_eq!(ep[0].addr, "8.8.8.8:853".parse().unwrap());
}

#[test]
fn upstream_mark_param_parses_hex_and_decimal() {
    assert_eq!(
        parse_upstream("udp://1.1.1.1?mark=0x1").unwrap()[0].mark,
        Some(1)
    );
    assert_eq!(
        parse_upstream("tls://8.8.8.8?mark=0xff&bootstrap=223.5.5.5").unwrap()[0].mark,
        Some(0xff)
    );
    assert_eq!(
        parse_upstream("udp://1.1.1.1?mark=100").unwrap()[0].mark,
        Some(100)
    );
    // No ?mark= → unmarked.
    assert_eq!(parse_upstream("udp://1.1.1.1").unwrap()[0].mark, None);
    // Garbage value is rejected.
    let err = format!(
        "{:#}",
        parse_upstream("udp://1.1.1.1?mark=xyz").unwrap_err()
    );
    assert!(err.contains("mark"), "expected mark error, got: {err}");
}

// ── Rules reject fixed answers (those now live in route.answer) ───────────

fn rule_with_upstream(name: &str, upstream: &str) -> String {
    format!(
        r#"{{"route":{{"rules":[{{"name":"{name}","upstream":["{upstream}"]}}],"final":"{name}"}}}}"#
    )
}

#[test]
fn rules_reject_a_upstream() {
    assert!(parse(&rule_with_upstream("x", "A://0.0.0.0")).is_err());
}

#[test]
fn rules_reject_aaaa_upstream() {
    assert!(parse(&rule_with_upstream("x", "AAAA://::")).is_err());
}

#[test]
fn rules_reject_cname_upstream() {
    assert!(parse(&rule_with_upstream("x", "CNAME://safe.example.com")).is_err());
}

#[test]
fn rules_reject_rcode_upstream() {
    assert!(parse(&rule_with_upstream("x", "RCODE://NXDOMAIN")).is_err());
}

#[test]
fn rules_reject_fixed_answer_mixed_with_real_upstream() {
    assert!(parse(
        r#"{"route":{"rules":[{"name":"x","upstream":["A://0.0.0.0","1.1.1.1"]}],"final":"x"}}"#
    )
    .is_err());
}

// ── Fixed-answer value parsing (via route.answer) ─────────────────────────

#[test]
fn answer_cname_value_lowercased_and_trailing_dot_stripped() {
    let cfg = parse(
            r#"{"route":{"rules":[{"name":"r","upstream":["1.1.1.1"]}],"answer":{"full:redir.example.com":"CNAME://Safe.Example.Com."}}}"#,
        )
        .unwrap();
    let e = cfg.answer_map.lookup("redir.example.com", None).unwrap();
    match &e.fixed_answers[0] {
        FixedAnswer::Cname(target, _) => assert_eq!(target, "safe.example.com"),
        other => panic!("expected FixedAnswer::Cname, got {other:?}"),
    }
}

#[test]
fn answer_ttl_param_parsed() {
    let cfg = parse(
        r#"{"route":{"rules":[{"name":"r","upstream":["1.1.1.1"]}],"answer":{
                "a.example.com": "A://1.2.3.4?ttl=300",
                "b.example.com": "CNAME://t.com?ttl=120",
                "c.example.com": "RCODE://NXDOMAIN?ttl=600"
            }}}"#,
    )
    .unwrap();
    match &cfg
        .answer_map
        .lookup("a.example.com", None)
        .unwrap()
        .fixed_answers[0]
    {
        FixedAnswer::A(_, ttl) => assert_eq!(*ttl, 300),
        other => panic!("expected A, got {other:?}"),
    }
    match &cfg
        .answer_map
        .lookup("b.example.com", None)
        .unwrap()
        .fixed_answers[0]
    {
        FixedAnswer::Cname(_, ttl) => assert_eq!(*ttl, 120),
        other => panic!("expected CNAME, got {other:?}"),
    }
    assert_eq!(
        cfg.answer_map
            .lookup("c.example.com", None)
            .unwrap()
            .rcode_ttl,
        600
    );
}

#[test]
fn answer_ttl_defaults_to_60() {
    let cfg = parse(
            r#"{"route":{"rules":[{"name":"r","upstream":["1.1.1.1"]}],"answer":{"a.com":"A://1.2.3.4"}}}"#,
        )
        .unwrap();
    match &cfg.answer_map.lookup("a.com", None).unwrap().fixed_answers[0] {
        FixedAnswer::A(_, ttl) => assert_eq!(*ttl, 60),
        other => panic!("expected A, got {other:?}"),
    }
}

#[test]
fn answer_rejects_bad_ttl_and_unknown_param() {
    assert!(parse(
            r#"{"route":{"rules":[{"name":"r","upstream":["1.1.1.1"]}],"answer":{"a.com":"A://1.2.3.4?ttl=abc"}}}"#
        )
        .is_err());
    assert!(parse(
            r#"{"route":{"rules":[{"name":"r","upstream":["1.1.1.1"]}],"answer":{"a.com":"A://1.2.3.4?foo=1"}}}"#
        )
        .is_err());
}

#[test]
fn answer_a_value_invalid_address_rejected() {
    assert!(parse(
            r#"{"route":{"rules":[{"name":"r","upstream":["1.1.1.1"]}],"answer":{"x.com":"A://not-an-ip"}}}"#
        )
        .is_err());
}

#[test]
fn answer_cname_value_empty_target_rejected() {
    assert!(parse(
        r#"{"route":{"rules":[{"name":"r","upstream":["1.1.1.1"]}],"answer":{"x.com":"CNAME://"}}}"#
    )
    .is_err());
}

#[test]
fn answer_duplicate_a_value_rejected() {
    assert!(parse(
            r#"{"route":{"rules":[{"name":"r","upstream":["1.1.1.1"]}],"answer":{"x.com":["A://0.0.0.0","A://1.2.3.4"]}}}"#
        )
        .is_err());
}
