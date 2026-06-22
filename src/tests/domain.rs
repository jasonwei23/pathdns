use super::*;

fn suffix_set(suffixes: &[&str]) -> DomainMatcher<()> {
    let mut m = DomainMatcher::default();
    for &s in suffixes {
        m.insert_suffix(s.to_string(), ());
    }
    m
}

#[test]
fn suffix_matches_name_and_subdomains() {
    let m = suffix_set(&["example.com"]);
    assert!(m.lookup_specific("example.com").is_some());
    assert!(m.lookup_specific("www.example.com").is_some());
    assert!(m.lookup_specific("a.b.example.com").is_some());
    assert!(m.lookup_specific("notexample.com").is_none());
    assert!(m.lookup_specific("com").is_none());
}

#[test]
fn single_label_suffix_matches_only_trailing_label() {
    let m = suffix_set(&["local"]);
    assert!(m.lookup_specific("local").is_some());
    assert!(m.lookup_specific("test.local").is_some());
    assert!(m.lookup_specific("foo.bar.local").is_some());
    assert!(m.lookup_specific("local.a.b").is_none());
    assert!(m.lookup_specific("net").is_none());
}

#[test]
fn no_false_positives_across_tlds() {
    let m = suffix_set(&["google.com"]);
    assert!(m.lookup_specific("google.net").is_none());
    assert!(m.lookup_specific("notgoogle.com").is_none());
    assert!(m.lookup_specific("com").is_none());
}

#[test]
fn empty_matcher() {
    let m: DomainMatcher<()> = DomainMatcher::default();
    assert!(m.is_empty());
    assert!(m.lookup_specific("example.com").is_none());
    assert!(m.lookup_fuzzy("example.com").is_none());
}

#[test]
fn lookup_priority_full_then_suffix_then_fuzzy() {
    let mut m: DomainMatcher<u8> = DomainMatcher::default();
    m.insert_suffix("example.com".into(), 1);
    m.insert_full("api.example.com".into(), 2);
    m.insert_keyword("ads".into(), 3);
    // specific tier (full + suffix) is consulted before the fuzzy tier
    let combined = |m: &DomainMatcher<u8>, q: &str| -> Option<u8> {
        m.lookup_specific(q).or_else(|| m.lookup_fuzzy(q)).copied()
    };
    // full wins over suffix for the exact name
    assert_eq!(combined(&m, "api.example.com"), Some(2));
    // suffix covers other subdomains
    assert_eq!(combined(&m, "www.example.com"), Some(1));
    // specific tier (suffix) beats fuzzy (keyword) when both could match
    m.insert_suffix("ads.net".into(), 9);
    assert_eq!(combined(&m, "x.ads.net"), Some(9));
    // keyword only when nothing specific matches
    assert_eq!(combined(&m, "my-ads-host.org"), Some(3));
}

#[test]
fn normalize_domain_basic() {
    assert_eq!(normalize_domain("Example.COM."), Some("example.com".into()));
    assert_eq!(normalize_domain(""), None);
    assert_eq!(normalize_domain("."), None);
    assert_eq!(normalize_domain("a..b"), None);
    assert_eq!(normalize_domain("a"), Some("a".into()));
}
