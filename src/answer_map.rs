//! Domain → fixed-answer map, consulted before the routing rules.
//!
//! The `route.answer` config section maps domain patterns directly to fixed
//! responses (`A://`, `AAAA://`, `CNAME://`, `RCODE://`). Domain keys use
//! exactly the same conventions as `route.ruleset`'s `domain`-behavior
//! patterns (see `crate::ruleset`'s module docs) — one convention across the
//! whole config, no separate "answer-map dialect" — plus a `tag:` form that
//! references `route.ruleset` tags:
//!
//! - bare `host`     — exact match only (`HashMap` O(1))
//! - `+.host`        — the host itself and all dot-delimited subdomains
//! - `.host`         — subdomains only, without the apex (rare; treated the
//!   same as `+.host`)
//! - `*.host`        — single-label wildcard (matches exactly one label in
//!   place of `*`, e.g. `*.example.com` matches `a.example.com` but not
//!   `example.com` or `a.b.example.com`)
//! - `tag:cn,!gfw`   — ruleset tag expression (comma-separated include/`!`exclude)
//!
//! Lookup priority: full → subdomain/root-domain (most specific) → tag → wildcard. The
//! map is consulted before the routing table, so a matching entry short-circuits
//! rule evaluation entirely.

use crate::config::FixedAnswer;
use crate::domain::DomainMatcher;
use crate::ruleset::RuleSetDb;
use anyhow::{anyhow, Result};

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

/// A ruleset tag expression: at least one include tag, plus optional excludes.
#[derive(Debug, Clone)]
struct TagExpr {
    include: Vec<String>,
    exclude: Vec<String>,
}

/// Compiled domain → fixed-answer map. Cheap to clone (cloned on each config build).
///
/// Inline domain patterns (bare/`+.`/`.`/`*.`) live in a shared `DomainMatcher`;
/// `tag:` patterns are kept separately because they require the ruleset database
/// at lookup time.
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

    /// Ruleset tag names referenced by any `tag:` entry. Used to load the right
    /// subset of the ruleset database at startup.
    pub fn referenced_tags(&self) -> impl Iterator<Item = &str> {
        self.tag
            .iter()
            .flat_map(|(expr, _)| expr.include.iter().chain(&expr.exclude))
            .map(String::as_str)
    }

    /// Insert one pattern → entry. `pattern` uses `route.ruleset`'s
    /// `domain`-behavior conventions (`+.`, `.`, `*.`, bare = exact), plus the
    /// answer-map-only `tag:` form.
    pub fn insert(&mut self, pattern: &str, entry: AnswerEntry) -> Result<()> {
        use crate::domain::PatternKind;
        // `tag:` is answer-map-only (not one of `classify_pattern`'s tiers,
        // which are shared with `route.ruleset`), so it's peeled off first.
        if let Some(rest) = pattern.strip_prefix("tag:") {
            self.tag.push((parse_tag_expr(rest)?, entry));
            return Ok(());
        }
        match crate::domain::classify_pattern(pattern) {
            PatternKind::Suffix(n) => self.inline.insert_suffix(n, entry),
            PatternKind::Full(n) => self.inline.insert_full(n, entry),
            PatternKind::Wildcard(re) => self.inline.insert_regex(re, entry),
            PatternKind::Invalid => return Err(anyhow!("invalid domain '{pattern}'")),
        }
        Ok(())
    }

    /// Look up the answer for a normalized query name (lowercase, no trailing dot).
    /// Priority: full (exact) → subdomain/root-domain (most specific) → tag → wildcard.
    /// `tag:` entries require the ruleset database; when `ruleset` is `None` they
    /// never match (an include tag cannot be confirmed without the DB).
    pub fn lookup(&self, qname: &str, ruleset: Option<&RuleSetDb>) -> Option<&AnswerEntry> {
        // Specific tier: exact + suffix.
        if let Some(e) = self.inline.lookup_specific(qname) {
            return Some(e);
        }
        // Ruleset tag tier. Memoize `rs.matches(tag, qname)` per distinct tag
        // name across this one lookup: entries commonly reuse the same
        // include/exclude tag (e.g. several answers all gated on `cn`), and
        // each entry's own include/exclude lists can repeat a tag too. A
        // linear Vec is used rather than a HashMap since the number of
        // distinct tags referenced by one `AnswerMap` is small — hashing
        // overhead would outweigh the lookup cost it avoids at this size.
        if let Some(rs) = ruleset {
            let mut memo: Vec<(String, bool)> = Vec::new();
            let mut matches_memoized = |tag: &str| -> bool {
                for (t, v) in &memo {
                    if t == tag {
                        return *v;
                    }
                }
                let v = rs.matches(tag, qname);
                memo.push((tag.to_string(), v));
                v
            };
            for (expr, e) in &self.tag {
                if expr.include.iter().any(|t| matches_memoized(t))
                    && !expr.exclude.iter().any(|t| matches_memoized(t))
                {
                    return Some(e);
                }
            }
        }
        // Wildcard tier.
        self.inline.lookup_fuzzy(qname)
    }
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
