//! Domain name utilities: normalization, subdomain/root-domain matching, and CSV tokenization.
//!
//! These helpers operate on domain *strings* rather than on DNS wire format.
//! They are shared by the GeoSite matcher, verdict cache, and config parser.
//! Wire-format packet utilities live in `dns`.

use regex::Regex;
use rustc_hash::FxHashMap;

// DomainMatcher.

/// Generic domain-pattern matcher carrying a value `V` per pattern, shared by the
/// GeoSite tag matchers (`V = ()`) and the `route.answer` map (`V = AnswerEntry`).
///
/// Patterns fall into four kinds, with this lookup priority:
/// 1. **full** — exact name (`HashMap`, O(1))
/// 2. **subdomain/root-domain** — the name and its dot-delimited subdomains, most specific wins
/// 3. **keyword** — substring match (insertion order)
/// 4. **regex** — regular-expression match (insertion order)
///
/// All stored names must be normalized (lowercase, no trailing dot).
#[derive(Debug, Clone)]
pub struct DomainMatcher<V> {
    full: FxHashMap<String, V>,
    suffix: FxHashMap<String, V>,
    keyword: Vec<(String, V)>,
    regex: Vec<(Regex, V)>,
}

impl<V> Default for DomainMatcher<V> {
    fn default() -> Self {
        Self {
            full: FxHashMap::default(),
            suffix: FxHashMap::default(),
            keyword: Vec::new(),
            regex: Vec::new(),
        }
    }
}

impl<V> DomainMatcher<V> {
    pub fn insert_full(&mut self, name: String, value: V) {
        self.full.insert(name, value);
    }
    pub fn insert_suffix(&mut self, name: String, value: V) {
        self.suffix.insert(name, value);
    }
    pub fn insert_keyword(&mut self, keyword: String, value: V) {
        self.keyword.push((keyword, value));
    }
    pub fn insert_regex(&mut self, regex: Regex, value: V) {
        self.regex.push((regex, value));
    }

    pub fn is_empty(&self) -> bool {
        self.full.is_empty()
            && self.suffix.is_empty()
            && self.keyword.is_empty()
            && self.regex.is_empty()
    }

    pub fn len(&self) -> usize {
        self.full.len() + self.suffix.len() + self.keyword.len() + self.regex.len()
    }


    /// Exact + subdomain/root-domain match (the "specific" tier); the most specific pattern wins.
    /// `qname` must already be normalized (lowercase, no trailing dot).
    pub fn lookup_specific(&self, qname: &str) -> Option<&V> {
        if let Some(v) = self.full.get(qname) {
            return Some(v);
        }
        if self.suffix.is_empty() {
            return None;
        }
        // Walk the query name's label-aligned right-hand segments and look each up by
        // equality: "a.b.example.com" → "b.example.com" → "example.com" → "com".
        // This scopes `domain:local` to `local` and `*.local` (an interior label like
        // `local.a.b` is never compared). The first hit is the longest segment, i.e.
        // the most specific pattern. O(labels) hash probes, independent of map size.
        let mut idx = 0;
        loop {
            if let Some(v) = self.suffix.get(&qname[idx..]) {
                return Some(v);
            }
            match qname[idx..].find('.') {
                Some(p) => idx += p + 1,
                None => return None,
            }
        }
    }

    /// Keyword + regex match (the "fuzzy" tier), checked in insertion order.
    pub fn lookup_fuzzy(&self, qname: &str) -> Option<&V> {
        for (kw, v) in &self.keyword {
            if qname.contains(kw.as_str()) {
                return Some(v);
            }
        }
        for (re, v) in &self.regex {
            if re.is_match(qname) {
                return Some(v);
            }
        }
        None
    }
}

// String helpers.

/// Iterate the non-empty, whitespace-trimmed tokens in a comma-separated string.
pub(crate) fn split_csv(s: &str) -> impl Iterator<Item = &str> {
    s.split(',').map(str::trim).filter(|s| !s.is_empty())
}

/// Canonical domain name normalization.
/// Trims whitespace and trailing dots, lowercases, rejects empty/over-long names
/// and labels. Does NOT validate label character set.
pub fn normalize_domain(name: &str) -> Option<String> {
    let name = name.trim().trim_end_matches('.').to_ascii_lowercase();
    if name.is_empty()
        || name.len() > 253
        || name
            .split('.')
            .any(|label| label.is_empty() || label.len() > 63)
    {
        return None;
    }
    Some(name)
}

// Tests.

#[cfg(test)]
mod tests {
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
}
