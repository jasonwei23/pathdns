//! Domain name utilities: normalization, subdomain/root-domain matching, and CSV tokenization.
//!
//! These helpers operate on domain *strings* rather than on DNS wire format.
//! They are shared by the ruleset matcher, verdict cache, and config parser.
//! Wire-format packet utilities live in `dns`.

use regex::Regex;
use rustc_hash::FxHashMap;

// DomainMatcher.

/// Generic domain-pattern matcher carrying a value `V` per pattern, shared by
/// the ruleset tag matchers and `route_index`'s rule matcher compilation
/// (both `V = ()`).
///
/// Patterns fall into three kinds, with this lookup priority:
/// 1. **full** — exact name (`HashMap`, O(1))
/// 2. **subdomain/root-domain** — the name and its dot-delimited subdomains, most specific wins
/// 3. **regex** — regular-expression match (insertion order); also how the single-label
///    `*.` wildcard is represented (see [`wildcard_domain_regex`])
///
/// All stored names must be normalized (lowercase, no trailing dot).
#[derive(Debug, Clone)]
pub struct DomainMatcher<V> {
    full: FxHashMap<String, V>,
    suffix: FxHashMap<String, V>,
    regex: Vec<(Regex, V)>,
}

impl<V> Default for DomainMatcher<V> {
    fn default() -> Self {
        Self {
            full: FxHashMap::default(),
            suffix: FxHashMap::default(),
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
    pub fn insert_regex(&mut self, regex: Regex, value: V) {
        self.regex.push((regex, value));
    }

    pub fn is_empty(&self) -> bool {
        self.full.is_empty() && self.suffix.is_empty() && self.regex.is_empty()
    }

    pub fn len(&self) -> usize {
        self.full.len() + self.suffix.len() + self.regex.len()
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
        // This scopes `+.local` to `local` and `*.local` (an interior label like
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

    /// Regex match (the "fuzzy" tier), checked in insertion order.
    pub fn lookup_fuzzy(&self, qname: &str) -> Option<&V> {
        for (re, v) in &self.regex {
            if re.is_match(qname) {
                return Some(v);
            }
        }
        None
    }
}

/// Build a regex for mihomo's single-label `*` wildcard convention: split `pattern`
/// on `.`, matching a segment that's exactly `*` against one non-empty, dot-free
/// label, and every other segment literally. `*.example.com` matches
/// `sub.example.com` but not `a.sub.example.com` or `example.com` itself — the
/// wildcard always consumes exactly one label, never zero or several.
///
/// Returns `None` if `pattern` contains no `*` (nothing to build a wildcard for).
pub fn wildcard_domain_regex(pattern: &str) -> Option<Regex> {
    if !pattern.contains('*') {
        return None;
    }
    let mut re = String::from("^");
    for (i, part) in pattern.split('.').enumerate() {
        if i > 0 {
            re.push_str(r"\.");
        }
        if part == "*" {
            re.push_str("[^.]+");
        } else {
            re.push_str(&regex::escape(&part.to_ascii_lowercase()));
        }
    }
    re.push('$');
    Regex::new(&re).ok()
}

/// The tier a domain pattern string belongs in, per the shared `route.ruleset`
/// (domain-behavior) / `rule.matcher` convention: `+.host`/`.host` (suffix),
/// `*.host` (single-label wildcard), bare `host` (exact). See [`classify_pattern`].
pub enum PatternKind {
    /// `+.host` or `.host` — insert via [`DomainMatcher::insert_suffix`].
    Suffix(String),
    /// Bare `host` — insert via [`DomainMatcher::insert_full`].
    Full(String),
    /// `*.host` — insert via [`DomainMatcher::insert_regex`].
    Wildcard(Regex),
    /// Didn't parse as a valid domain (empty/over-long label, etc).
    Invalid,
}

/// Classify one domain pattern string into the tier it belongs in. Shared by
/// `ruleset.rs`'s and `route_index.rs`'s pattern parsing, which otherwise each
/// reimplemented this same `+.`/`.`/wildcard/bare branch structure. Callers own
/// their own error handling and the actual `DomainMatcher` insertion (which
/// needs a caller-specific value `V`) — this only classifies and normalizes
/// the pattern string itself.
pub fn classify_pattern(pattern: &str) -> PatternKind {
    if let Some(rest) = pattern.strip_prefix("+.") {
        // The domain itself and all subdomains.
        return normalize_domain(rest).map_or(PatternKind::Invalid, PatternKind::Suffix);
    }
    if let Some(rest) = pattern.strip_prefix('.') {
        // Subdomains only, no apex — approximated as a suffix match (same as `+.`).
        return normalize_domain(rest).map_or(PatternKind::Invalid, PatternKind::Suffix);
    }
    if let Some(re) = wildcard_domain_regex(pattern) {
        return PatternKind::Wildcard(re);
    }
    normalize_domain(pattern).map_or(PatternKind::Invalid, PatternKind::Full)
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
