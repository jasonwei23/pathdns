use super::*;

#[test]
fn split_tag_attr_no_at() {
    assert_eq!(split_tag_attr("cn"), ("cn", None));
}

#[test]
fn split_tag_attr_with_attr() {
    assert_eq!(split_tag_attr("steam@cn"), ("steam", Some("cn")));
}

#[test]
fn split_tag_attr_empty_attr_treated_as_no_filter() {
    // "steam@" — empty attr means split_once returns ("steam", ""), not Some("")
    assert_eq!(split_tag_attr("steam@"), ("steam@", None));
}

fn make_domain_bytes(suffix_value: &str, attr_key: Option<&str>) -> Vec<u8> {
    let mut bytes = vec![
        0x08, 0x02, // type = 2 (RootDomain/suffix)
    ];
    // value string
    let v = suffix_value.as_bytes();
    bytes.push(0x12);
    bytes.push(v.len() as u8);
    bytes.extend_from_slice(v);
    // optional attribute
    if let Some(key) = attr_key {
        let k = key.as_bytes();
        // Attribute { key: "cn" (field 1), bool_value: true (field 2) }
        let mut attr_msg = vec![0x0A, k.len() as u8];
        attr_msg.extend_from_slice(k);
        attr_msg.extend_from_slice(&[0x10, 0x01]); // bool_value = true
        bytes.push(0x1A); // field 3, wire type 2
        bytes.push(attr_msg.len() as u8);
        bytes.extend(attr_msg);
    }
    bytes
}

#[test]
fn attribute_filter_includes_only_matching_domains() {
    let with_cn = make_domain_bytes("google.com", Some("cn"));
    let without_attr = make_domain_bytes("bing.com", None);

    // No filter: both included.
    let mut m = TagMatchers::default();
    parse_domain_message(&mut m, &with_cn, None).unwrap();
    parse_domain_message(&mut m, &without_attr, None).unwrap();
    assert!(m.lookup_specific("google.com").is_some());
    assert!(m.lookup_specific("bing.com").is_some());

    // @cn filter: only google.com (which has @cn) included.
    let mut m_cn = TagMatchers::default();
    parse_domain_message(&mut m_cn, &with_cn, Some("cn")).unwrap();
    parse_domain_message(&mut m_cn, &without_attr, Some("cn")).unwrap();
    assert!(m_cn.lookup_specific("google.com").is_some());
    assert!(m_cn.lookup_specific("bing.com").is_none());
}

#[test]
fn attribute_filter_suffix_match_works() {
    let with_cn = make_domain_bytes("steam.com", Some("cn"));
    let mut m = TagMatchers::default();
    parse_domain_message(&mut m, &with_cn, Some("cn")).unwrap();
    // RootDomain = subdomain match: the domain itself and subdomains match.
    assert!(m.lookup_specific("store.steam.com").is_some());
    assert!(m.lookup_specific("steam.com").is_some());
    assert!(m.lookup_specific("notsteam.com").is_none());
}

// Run with: cargo test --release geosite_cache_bench -- --ignored --nocapture
#[test]
#[ignore]
fn geosite_cache_bench() {
    use moka::sync::Cache;

    // Pure-suffix tag (realistic: a geosite category is tens of thousands of rootdomains).
    let mut suffix_tag: DomainMatcher<()> = DomainMatcher::default();
    for i in 0..50_000u32 {
        suffix_tag.insert_suffix(format!("host{i}.site{}.com", i % 1009), ());
    }
    // Fuzzy tag: keyword + regex matchers (the only genuinely O(patterns) case).
    let mut fuzzy_tag: DomainMatcher<()> = DomainMatcher::default();
    for i in 0..24u32 {
        fuzzy_tag.insert_keyword(format!("kw{i}"), ());
    }
    for i in 0..8u32 {
        fuzzy_tag.insert_regex(
            Regex::new(&format!(r"track{i}[0-9]+\.example")).unwrap(),
            (),
        );
    }

    // Strategy bodies (replicate each caching policy over the public matcher API).
    let no_cache = |m: &DomainMatcher<()>, d: &str| -> bool {
        m.lookup_specific(d).is_some() || m.lookup_fuzzy(d).is_some()
    };
    let cache_all = |m: &DomainMatcher<()>, c: &Cache<String, bool>, d: &str| -> bool {
        let mut key = String::with_capacity(3 + d.len());
        key.push_str("t\0");
        key.push_str(d);
        if let Some(v) = c.get(key.as_str()) {
            return v;
        }
        let r = m.lookup_specific(d).is_some() || m.lookup_fuzzy(d).is_some();
        c.insert(key, r);
        r
    };
    // Rejected strategy: cache the fuzzy result (only ever applied to a fuzzy tag here).
    let fuzzy_only = |m: &DomainMatcher<()>, c: &Cache<String, bool>, d: &str| -> bool {
        if m.lookup_specific(d).is_some() {
            return true;
        }
        let mut key = String::with_capacity(3 + d.len());
        key.push_str("t\0");
        key.push_str(d);
        if let Some(v) = c.get(key.as_str()) {
            return v;
        }
        let r = m.lookup_fuzzy(d).is_some();
        c.insert(key, r);
        r
    };

    fn bench(label: &str, iters: usize, distinct: &[String], f: &mut dyn FnMut(&str) -> bool) {
        for d in distinct.iter().take(distinct.len().min(1000)) {
            std::hint::black_box(f(d));
        }
        let t = std::time::Instant::now();
        let mut acc = 0usize;
        for k in 0..iters {
            let d = &distinct[k % distinct.len()];
            if std::hint::black_box(f(d.as_str())) {
                acc += 1;
            }
        }
        let ns = t.elapsed().as_nanos() as f64 / iters as f64;
        eprintln!("  {label:30} {ns:8.1} ns/op  (truthy={acc})");
    }

    let iters = 2_000_000usize;
    // Repeated stream (high hit rate on any cache) — proxies traffic with a warm route cache absent.
    let repeated: Vec<String> = (0..5_000u32)
        .map(|i| format!("www.host{i}.site{}.com", i % 1009))
        .collect();
    // Cold stream: every query is a distinct, never-before-seen name (cache never hits).
    let cold: Vec<String> = (0..iters as u32)
        .map(|i| format!("x{i}.cold{}.test", i % 7919))
        .collect();

    eprintln!("\n== pure-suffix tag (50k entries) ==");
    eprintln!("-- repeated stream (5k distinct) --");
    bench("no-cache (==current)", iters, &repeated, &mut |d| {
        no_cache(&suffix_tag, d)
    });
    {
        let c = Cache::new(100_000);
        bench("cache-all (old)", iters, &repeated, &mut |d| {
            cache_all(&suffix_tag, &c, d)
        });
    }

    eprintln!("\n== fuzzy tag (24 keyword + 8 regex) ==");
    eprintln!("-- repeated stream (5k distinct, high repeat) --");
    bench("no-cache (delete)", iters, &repeated, &mut |d| {
        no_cache(&fuzzy_tag, d)
    });
    {
        let c = Cache::new(100_000);
        bench("fuzzy-cached (current)", iters, &repeated, &mut |d| {
            fuzzy_only(&fuzzy_tag, &c, d)
        });
    }
    eprintln!("-- cold stream (all-unique, cache never hits) --");
    bench("no-cache (delete)", iters, &cold, &mut |d| {
        no_cache(&fuzzy_tag, d)
    });
    {
        let c = Cache::new(100_000);
        bench("fuzzy-cached (current)", iters, &cold, &mut |d| {
            fuzzy_only(&fuzzy_tag, &c, d)
        });
    }
    eprintln!();
}
