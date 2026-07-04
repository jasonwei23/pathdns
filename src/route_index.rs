//! Compiled routing index for fast rule selection at query time.
//!
//! `RouteIndex` is built once at config load time from the finalized rule
//! list.  Rule matching is ruleset-tag-only, so the index stores two things:
//!
//! - **Ruleset entries**: rules with `ruleset_include` or `ruleset_exclude`,
//!   checked in ascending rule-index order with per-query tag memoization so
//!   each tag string is evaluated at most once per query.
//! - **Catch-all index**: the first rule with no positive matchers and no
//!   exclude rules; matches every domain unconditionally.
//!
//! The merge of these two streams preserves first-match semantics identical to
//! the old linear rule matching loop.

use crate::ruleset::RuleSetDb;
use crate::server::Rule;
use moka::sync::Cache as MokaCache;
use smallvec::SmallVec;
use std::collections::HashMap;
use std::sync::Arc;

// TagMemo.

/// Per-query memoization of `RuleSetDb::matches(tag_id, qname)`.
///
/// Uses two bits per tag, packed into 64-tag chunks. This avoids string
/// comparisons on the hot path while keeping cold-route initialization small.
#[derive(Clone, Copy, Default)]
struct TagMemoChunk {
    seen: u64,
    matched: u64,
}

struct TagMemo {
    chunks: SmallVec<[TagMemoChunk; 1]>,
}

impl TagMemo {
    fn new(num_tags: usize) -> Self {
        let mut chunks = SmallVec::new();
        chunks.resize(num_tags.div_ceil(64), TagMemoChunk::default());
        Self { chunks }
    }

    fn check(&mut self, rs: &RuleSetDb, tag_id: u16, tag_name: &str, qname: &str) -> bool {
        let idx = tag_id as usize;
        let chunk_idx = idx / 64;
        let bit = 1u64 << (idx % 64);
        if let Some(chunk) = self.chunks.get(chunk_idx) {
            if chunk.seen & bit != 0 {
                return chunk.matched & bit != 0;
            }
        }
        let v = rs.matches(tag_name, qname);
        if let Some(chunk) = self.chunks.get_mut(chunk_idx) {
            chunk.seen |= bit;
            if v {
                chunk.matched |= bit;
            }
        }
        v
    }
}

// RuleSetEntry.

/// A rule that requires Ruleset consultation at routing time.
struct RuleSetEntry {
    /// Index into `AppState::rules`.
    rule_idx: usize,
    /// Interned tag IDs for include tags.
    include_ids: SmallVec<[u16; 4]>,
    /// Interned tag IDs for exclude tags.
    exclude_ids: SmallVec<[u16; 4]>,
}

// RouteIndex.

/// Precompiled routing index.  Build once after rule construction; reuse for
/// every query. Immutable after `build`; thread-safe without locking.
pub struct RouteIndex {
    /// Rules with Ruleset rules, in ascending rule-index order.
    ruleset_entries: Vec<RuleSetEntry>,

    /// First true catch-all rule: no positive matchers and no ruleset_exclude.
    /// Matches every domain unconditionally.
    catch_all_idx: Option<usize>,

    /// Interned tag names: tag_id -> tag name string.
    tag_names: Vec<String>,

    /// Number of unique tags (for TagMemo sizing).
    num_tags: usize,

    /// L1 route cache: qname -> rule index (or usize::MAX for no match).
    route_cache: MokaCache<Arc<str>, usize>,
}

impl RouteIndex {
    /// Build the index from the finalized rule slice.
    ///
    /// Rules are partitioned into two non-overlapping streams:
    /// - **Ruleset rules**: have `ruleset_include` or `ruleset_exclude`;
    ///   stored in `ruleset_entries`.
    /// - **Catch-all**: no positive matchers and no Ruleset rules;
    ///   first one stored as `catch_all_idx`.
    pub fn build(rules: &[Rule]) -> Self {
        let mut tag_ids: HashMap<String, u16> = HashMap::new();
        let mut tag_names: Vec<String> = Vec::new();

        let mut intern = |name: &str| -> u16 {
            if let Some(&id) = tag_ids.get(name) {
                return id;
            }
            let id = tag_names.len() as u16;
            tag_names.push(name.to_string());
            tag_ids.insert(name.to_string(), id);
            id
        };

        let mut ruleset_entries: Vec<RuleSetEntry> = Vec::new();
        let mut catch_all_idx: Option<usize> = None;

        for (idx, rule) in rules.iter().enumerate() {
            if !rule.ruleset_include.is_empty() || !rule.ruleset_exclude.is_empty() {
                let include_ids = rule.ruleset_include.iter().map(|t| intern(t)).collect();
                let exclude_ids = rule.ruleset_exclude.iter().map(|t| intern(t)).collect();
                ruleset_entries.push(RuleSetEntry {
                    rule_idx: idx,
                    include_ids,
                    exclude_ids,
                });
            } else if catch_all_idx.is_none() {
                catch_all_idx = Some(idx);
            }
        }

        let num_tags = tag_names.len();
        let route_cache = MokaCache::builder().max_capacity(32_768).build();
        Self {
            ruleset_entries,
            catch_all_idx,
            tag_names,
            num_tags,
            route_cache,
        }
    }

    /// Find the first matching rule for `qname` using the precompiled index.
    ///
    /// The two streams, `ruleset_entries` and `catch_all_idx`, are advanced
    /// in ascending rule-index order, preserving first-match semantics.
    ///
    /// When `ruleset = None` the index is safe: include tags never match;
    /// exclude tags never block (can't confirm exclusion without the DB).
    pub fn route<'a>(
        &self,
        rules: &'a [Rule],
        qname: &str,
        ruleset: Option<&RuleSetDb>,
    ) -> Option<&'a Rule> {
        // L1 route cache: only cache when ruleset is available (or no ruleset needed).
        // We don't cache when ruleset is None but ruleset entries exist, because the
        // result might differ once the DB is loaded.
        let use_cache = ruleset.is_some() || self.ruleset_entries.is_empty();
        if use_cache {
            if let Some(idx) = self.route_cache.get(qname) {
                return if idx == usize::MAX {
                    None
                } else {
                    rules.get(idx)
                };
            }
            let idx = self.route_index_uncached(qname, ruleset);
            self.route_cache.insert(Arc::from(qname), idx);
            return rules.get(idx);
        }
        rules.get(self.route_index_uncached(qname, ruleset))
    }

    fn route_index_uncached(&self, qname: &str, ruleset: Option<&RuleSetDb>) -> usize {
        let catch_all = self.catch_all_idx.unwrap_or(usize::MAX);

        if self.ruleset_entries.is_empty() {
            return catch_all;
        }

        let mut tag_memo = TagMemo::new(self.num_tags);

        for entry in &self.ruleset_entries {
            // If the catch-all rule precedes this Ruleset entry, it wins first.
            if catch_all < entry.rule_idx {
                return catch_all;
            }
            if ruleset_entry_matches(entry, qname, ruleset, &mut tag_memo, &self.tag_names) {
                return entry.rule_idx;
            }
        }

        // All Ruleset entries exhausted; fall through to catch-all if present.
        catch_all
    }

    /// Find the first matching rule for `qname` with `rule_idx > after_idx` — used by
    /// a rule's `filter` `continue` action to resume matching from the next candidate.
    ///
    /// Always an uncached linear scan (unlike `route`): `continue` is a cold path, and
    /// caching per-`(qname, after_idx)` composite keys isn't worth the complexity.
    pub fn route_after<'a>(
        &self,
        rules: &'a [Rule],
        qname: &str,
        ruleset: Option<&RuleSetDb>,
        after_idx: usize,
    ) -> Option<&'a Rule> {
        let catch_all = self
            .catch_all_idx
            .filter(|&i| i > after_idx)
            .unwrap_or(usize::MAX);

        if self.ruleset_entries.is_empty() {
            return rules.get(catch_all);
        }

        let mut tag_memo = TagMemo::new(self.num_tags);

        for entry in &self.ruleset_entries {
            if entry.rule_idx <= after_idx {
                continue;
            }
            if catch_all < entry.rule_idx {
                return rules.get(catch_all);
            }
            if ruleset_entry_matches(entry, qname, ruleset, &mut tag_memo, &self.tag_names) {
                return rules.get(entry.rule_idx);
            }
        }

        rules.get(catch_all)
    }
}

fn ruleset_entry_matches(
    entry: &RuleSetEntry,
    qname: &str,
    ruleset: Option<&RuleSetDb>,
    memo: &mut TagMemo,
    tag_names: &[String],
) -> bool {
    // Positive check: if this entry has include tags, at least one must match.
    // If there are no include tags (exclude-only rule), every domain passes.
    let match_positive = if !entry.include_ids.is_empty() {
        ruleset.is_some_and(|rs| {
            entry
                .include_ids
                .iter()
                .any(|&id| memo.check(rs, id, &tag_names[id as usize], qname))
        })
    } else {
        true
    };

    if !match_positive {
        return false;
    }

    // Negative check.
    if entry.exclude_ids.is_empty() {
        return true;
    }
    match ruleset {
        Some(rs) => !entry
            .exclude_ids
            .iter()
            .any(|&id| memo.check(rs, id, &tag_names[id as usize], qname)),
        // Without a DB we can't confirm exclusion, so allow.
        None => true,
    }
}

// Tests.
