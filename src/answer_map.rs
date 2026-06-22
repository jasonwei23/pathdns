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
#[path = "tests/answer_map.rs"]
mod tests;
