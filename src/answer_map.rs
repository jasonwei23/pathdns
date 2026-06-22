//! Domain → fixed-answer map, consulted before the routing rules.
//!
//! The `route.answer` config section maps domain patterns directly to fixed
//! responses (`A://`, `AAAA://`, `CNAME://`, `RCODE://`). Keys use the same
//! matching conventions as GeoSite `.json` entries, plus a `tag:` form that
//! references GeoSite tags:
//!
//! - `full:host`     — exact match (`HashMap` O(1))
//! - `domain:host`   — DLC subdomain rule (host itself and dot-delimited subdomains)
//! - bare `host`     — DLC subdomain rule (same as `domain:`)
//! - `tag:cn,!gfw`   — GeoSite tag expression (comma-separated include/`!`exclude)
//! - `keyword:str`   — substring match
//! - `regexp:re`     — regular expression match
//!
//! Lookup priority: full → subdomain/root-domain (most specific) → tag → keyword → regex. The
//! map is consulted before the routing table, so a matching entry short-circuits
//! rule evaluation entirely.

use crate::config::FixedAnswer;
use crate::domain::DomainMatcher;
use crate::geosite::GeoSiteDb;
use anyhow::{anyhow, Context, Result};
use regex::Regex;

/// A fixed response associated with a domain pattern. Exactly one of
/// `fixed_rcode` / `fixed_answers` is populated (validated at parse time).
#[derive(Debug, Clone)]
pub struct AnswerEntry {
    /// Fixed RCODE (`RCODE://`) to return without querying any upstream.
    pub fixed_rcode: Option<u8>,
    /// Cache TTL for the `RCODE://` / NODATA response. Only meaningful when
    /// `fixed_rcode` is `Some`; record TTLs for A/AAAA/CNAME live in `fixed_answers`.
    pub rcode_ttl: u32,
    /// Synthesised A/AAAA/CNAME records to return without querying any upstream.
    /// May hold at most one A and one AAAA combined; CNAME is exclusive with both.
    pub fixed_answers: Vec<FixedAnswer>,
}

/// A GeoSite tag expression: at least one include tag, plus optional excludes.
#[derive(Debug, Clone)]
struct TagExpr {
    include: Vec<String>,
    exclude: Vec<String>,
}

/// Compiled domain → fixed-answer map. Cheap to clone (cloned on each config build).
///
/// Inline domain patterns (`full:`/`domain:`/`keyword:`/`regexp:`/bare) live in a
/// shared `DomainMatcher`; `tag:` patterns are kept separately because they require
/// the GeoSite database at lookup time.
#[derive(Debug, Clone, Default)]
pub struct AnswerMap {
    inline: DomainMatcher<AnswerEntry>,
    tag: Vec<(TagExpr, AnswerEntry)>,
}

impl AnswerMap {
    pub fn is_empty(&self) -> bool {
        self.inline.is_empty() && self.tag.is_empty()
    }

    /// Number of patterns stored, across all match kinds.
    pub fn len(&self) -> usize {
        self.inline.len() + self.tag.len()
    }

    /// GeoSite tag names referenced by any `tag:` entry. Used to load the right
    /// subset of the GeoSite database at startup.
    pub fn referenced_tags(&self) -> impl Iterator<Item = &str> {
        self.tag
            .iter()
            .flat_map(|(expr, _)| expr.include.iter().chain(&expr.exclude))
            .map(String::as_str)
    }

    /// Insert one pattern → entry. `pattern` uses the GeoSite `.json` prefix
    /// conventions (`full:`, `domain:`, `keyword:`, `regexp:`, `tag:`, bare = subdomain).
    pub fn insert(&mut self, pattern: &str, entry: AnswerEntry) -> Result<()> {
        if let Some(rest) = pattern.strip_prefix("full:") {
            self.inline.insert_full(normalize(rest)?, entry);
        } else if let Some(rest) = pattern.strip_prefix("domain:") {
            self.inline.insert_suffix(normalize(rest)?, entry);
        } else if let Some(rest) = pattern.strip_prefix("tag:") {
            self.tag.push((parse_tag_expr(rest)?, entry));
        } else if let Some(rest) = pattern.strip_prefix("keyword:") {
            let kw = rest.trim().to_ascii_lowercase();
            if kw.is_empty() {
                return Err(anyhow!("keyword pattern cannot be empty"));
            }
            self.inline.insert_keyword(kw, entry);
        } else if let Some(rest) = pattern.strip_prefix("regexp:") {
            let re = Regex::new(rest).with_context(|| format!("invalid regexp '{rest}'"))?;
            self.inline.insert_regex(re, entry);
        } else {
            self.inline.insert_suffix(normalize(pattern)?, entry);
        }
        Ok(())
    }

    /// Look up the answer for a normalized query name (lowercase, no trailing dot).
    /// Priority: full (exact) → subdomain/root-domain (most specific) → tag → keyword → regex.
    /// `tag:` entries require the GeoSite database; when `geosite` is `None` they
    /// never match (an include tag cannot be confirmed without the DB).
    pub fn lookup(&self, qname: &str, geosite: Option<&GeoSiteDb>) -> Option<&AnswerEntry> {
        // Specific tier: exact + suffix.
        if let Some(e) = self.inline.lookup_specific(qname) {
            return Some(e);
        }
        // GeoSite tag tier.
        if let Some(gs) = geosite {
            for (expr, e) in &self.tag {
                if expr.include.iter().any(|t| gs.matches(t, qname))
                    && !expr.exclude.iter().any(|t| gs.matches(t, qname))
                {
                    return Some(e);
                }
            }
        }
        // Fuzzy tier: keyword + regex.
        self.inline.lookup_fuzzy(qname)
    }
}

fn normalize(name: &str) -> Result<String> {
    crate::domain::normalize_domain(name).ok_or_else(|| anyhow!("invalid domain '{name}'"))
}

/// Parse a `tag:` expression body (e.g. `"cn,!gfw"`) into include/exclude lists.
/// Requires at least one include tag.
fn parse_tag_expr(rest: &str) -> Result<TagExpr> {
    let mut include = Vec::new();
    let mut exclude = Vec::new();
    for token in crate::domain::split_csv(rest) {
        if let Some(name) = token.strip_prefix('!') {
            let name = name.trim();
            if name.is_empty() {
                return Err(anyhow!("tag exclusion cannot be empty"));
            }
            exclude.push(name.to_ascii_lowercase());
        } else {
            include.push(token.to_ascii_lowercase());
        }
    }
    if include.is_empty() {
        return Err(anyhow!("tag expression must include at least one tag"));
    }
    Ok(TagExpr { include, exclude })
}

#[cfg(test)]
mod tests {
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
        assert!(
            matches!(got.fixed_answers[0], FixedAnswer::A(a, _) if a == Ipv4Addr::new(2, 2, 2, 2))
        );
        let got = m.lookup("www.example.com", None).unwrap();
        assert!(
            matches!(got.fixed_answers[0], FixedAnswer::A(a, _) if a == Ipv4Addr::new(1, 1, 1, 1))
        );
    }

    #[test]
    fn full_takes_priority_over_suffix() {
        let mut m = AnswerMap::default();
        m.insert("example.com", a_entry("1.1.1.1")).unwrap();
        m.insert("full:example.com", a_entry("9.9.9.9")).unwrap();
        let got = m.lookup("example.com", None).unwrap();
        assert!(
            matches!(got.fixed_answers[0], FixedAnswer::A(a, _) if a == Ipv4Addr::new(9, 9, 9, 9))
        );
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
}
