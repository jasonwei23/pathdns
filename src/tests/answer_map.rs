use super::*;
use std::net::Ipv4Addr;

fn a_entry(ip: &str) -> AnswerEntry {
    AnswerEntry {
        fixed_rcode: None,
        rcode_ttl: 60,
        fixed_answers: vec![FixedAnswer::A(ip.parse::<Ipv4Addr>().unwrap(), 60)],
    }
}

#[test]
fn full_match_is_exact_only() {
    let mut m = AnswerMap::default();
    m.insert("full:a.example.com", a_entry("1.1.1.1")).unwrap();
    assert!(m.lookup("a.example.com", None).is_some());
    assert!(m.lookup("x.a.example.com", None).is_none());
}

#[test]
fn bare_and_domain_prefix_are_suffix() {
    let mut m = AnswerMap::default();
    m.insert("example.com", a_entry("1.1.1.1")).unwrap();
    m.insert("domain:b.net", a_entry("2.2.2.2")).unwrap();
    assert!(m.lookup("example.com", None).is_some());
    assert!(m.lookup("www.example.com", None).is_some());
    assert!(m.lookup("b.net", None).is_some());
    assert!(m.lookup("x.y.b.net", None).is_some());
    assert!(m.lookup("notexample.com", None).is_none());
    assert!(m.lookup("b.net.a.b", None).is_none());
}

#[test]
fn most_specific_suffix_wins() {
    let mut m = AnswerMap::default();
    m.insert("example.com", a_entry("1.1.1.1")).unwrap();
    m.insert("api.example.com", a_entry("2.2.2.2")).unwrap();
    let got = m.lookup("api.example.com", None).unwrap();
    assert!(matches!(got.fixed_answers[0], FixedAnswer::A(a, _) if a == Ipv4Addr::new(2, 2, 2, 2)));
    let got = m.lookup("www.example.com", None).unwrap();
    assert!(matches!(got.fixed_answers[0], FixedAnswer::A(a, _) if a == Ipv4Addr::new(1, 1, 1, 1)));
}

#[test]
fn full_takes_priority_over_suffix() {
    let mut m = AnswerMap::default();
    m.insert("example.com", a_entry("1.1.1.1")).unwrap();
    m.insert("full:example.com", a_entry("9.9.9.9")).unwrap();
    let got = m.lookup("example.com", None).unwrap();
    assert!(matches!(got.fixed_answers[0], FixedAnswer::A(a, _) if a == Ipv4Addr::new(9, 9, 9, 9)));
}

#[test]
fn keyword_and_regex_match() {
    let mut m = AnswerMap::default();
    m.insert("keyword:ads", a_entry("1.1.1.1")).unwrap();
    m.insert("regexp:^track[0-9]+\\.net$", a_entry("2.2.2.2"))
        .unwrap();
    assert!(m.lookup("my-ads-server.com", None).is_some());
    assert!(m.lookup("track42.net", None).is_some());
    assert!(m.lookup("clean.example.org", None).is_none());
}

#[test]
fn empty_pattern_kinds_are_rejected() {
    let mut m = AnswerMap::default();
    assert!(m.insert("keyword:", a_entry("1.1.1.1")).is_err());
    assert!(m.insert("regexp:[", a_entry("1.1.1.1")).is_err());
    assert!(m.insert("full:", a_entry("1.1.1.1")).is_err());
}

#[test]
fn tag_expr_parsing() {
    let mut m = AnswerMap::default();
    m.insert("tag:cn,!gfw", a_entry("1.1.1.1")).unwrap();
    let tags: Vec<&str> = m.referenced_tags().collect();
    assert!(tags.contains(&"cn"));
    assert!(tags.contains(&"gfw"));
    // Without a GeoSite DB, tag entries never match.
    assert!(m.lookup("baidu.com", None).is_none());
}

#[test]
fn tag_expr_requires_an_include() {
    let mut m = AnswerMap::default();
    assert!(m.insert("tag:!gfw", a_entry("1.1.1.1")).is_err());
    assert!(m.insert("tag:", a_entry("1.1.1.1")).is_err());
}
