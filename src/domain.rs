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
#[path = "tests/domain.rs"]
mod tests;
