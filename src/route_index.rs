//! Compiled routing index for fast rule selection at query time.
//!
//! `RouteIndex` is built once at config load time from the finalized rule
//! list. Each rule's `matcher` (see `crate::config::RuleMatcher`) is either
//! empty (catch-all) or a list of domain patterns and/or `tag:` ruleset-tag
//! expressions, ANY of which matching makes the rule match. The index stores
//! two things:
//!
//! - **Match entries**: rules with a non-empty `matcher`, checked in
//!   ascending rule-index order. Each entry's domain patterns are compiled
//!   into a `DomainMatcher` (O(1)/O(labels) lookup, no ruleset needed) and
//!   its `tag:` expressions use per-query tag memoization so each tag string
//!   is evaluated at most once per query.
//! - **Catch-all index**: the first rule with an empty `matcher`; matches
//!   every domain unconditionally.
//!
//! The merge of these two streams preserves first-match semantics identical to
//! a linear top-to-bottom rule scan.
//!
//! A `TagMemo` is scoped to one qname and shared across every match entry
//! checked for that qname within one `route`/`route_with_memo` call, so a tag
//! string referenced by more than one rule is only evaluated against
//! `RuleSetDb::matches` once. A different qname always constructs its own memo.

use crate::config::RuleMatcher;
use crate::domain::DomainMatcher;
use crate::ruleset::RuleSetDb;
use crate::server::Rule;
use quick_cache::sync::{Cache, DefaultLifecycle};
use quick_cache::UnitWeighter;
use rustc_hash::FxBuildHasher;
use smallvec::SmallVec;
use std::collections::HashMap;
use std::sync::Arc;

/// Floor for the L1 route-decision cache's capacity, regardless of
/// `dns_cache_capacity` — see `RouteIndex::build`.
const ROUTE_CACHE_MIN_CAPACITY: u64 = 4_096;

// TagMemo.

/// Per-query memoization of `RuleSetDb::matches(tag_id, qname)`.
///
/// Uses two bits per tag, packed into 64-tag chunks. This avoids string
/// comparisons on the hot path while keeping cold-route initialization small.
/// Scoped to one qname: reusing an instance across two different qnames would
/// silently return stale results for the earlier qname's tag membership.
#[derive(Clone, Copy, Default)]
struct TagMemoChunk {
    seen: u64,
    matched: u64,
}

pub(crate) struct TagMemo {
    /// Inline capacity of 4 chunks = 256 tags before the memo itself needs a
    /// heap allocation; it is only constructed after an L1 route-cache miss,
    /// so even that allocation is off the cached hot path.
    chunks: SmallVec<[TagMemoChunk; 4]>,
}

impl TagMemo {
    pub(crate) fn new(num_tags: usize) -> Self {
        let mut chunks = SmallVec::new();
        chunks.resize(num_tags.div_ceil(64), TagMemoChunk::default());
        Self { chunks }
    }

    pub(crate) fn check(
        &mut self,
        rs: &RuleSetDb,
        tag_id: u16,
        tag_name: &str,
        qname: &str,
    ) -> bool {
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

// MatchEntry.

/// One `tag:` expression within a rule's `matcher` list.
struct TagGroup {
    /// Interned tag IDs for include tags. May be empty (exclude-only group).
    include_ids: SmallVec<[u16; 4]>,
    /// Interned tag IDs for exclude tags.
    exclude_ids: SmallVec<[u16; 4]>,
}

/// A rule with a non-empty `matcher`, compiled for routing-time lookup. The
/// rule matches if `qname` hits `domains` (no ruleset needed) OR satisfies
/// any `tags` group (ruleset-based, requires the DB to be loaded).
struct MatchEntry {
    /// Index into `AppState::rules`.
    rule_idx: usize,
    /// Compiled domain-pattern matchers from this rule's `matcher` list.
    domains: DomainMatcher<()>,
    /// Compiled `tag:` expressions from this rule's `matcher` list.
    tags: Vec<TagGroup>,
}

// RouteIndex.

/// Precompiled routing index.  Build once after rule construction; reuse for
/// every query. Immutable after `build`; thread-safe without locking.
pub struct RouteIndex {
    /// Rules with a non-empty `matcher`, in ascending rule-index order.
    match_entries: Vec<MatchEntry>,

    /// First true catch-all rule: empty `matcher`. Matches every domain
    /// unconditionally.
    catch_all_idx: Option<usize>,

    /// True when at least one `match_entries` entry has a `tag:` group — used
    /// to decide whether the L1 route cache is safe to use when `ruleset` is
    /// `None` (see `route`).
    needs_ruleset: bool,

    /// `Some(decision)` when every qname routes identically, so `route()` can
    /// answer without touching the route cache at all:
    /// - the first rule is a catch-all (everything after it is unreachable), or
    /// - there are no conditional match entries (the answer is the catch-all,
    ///   or `None` when there is no catch-all either).
    ///
    /// The inner `Option` is the constant answer (rule index or no-match).
    /// Pure-forwarding configs (one catch-all rule, or `route.final` only)
    /// otherwise pay a Moka lookup *and* an insert per distinct qname — and
    /// high-cardinality traffic churns the route cache with entries that all
    /// decode to the same answer.
    constant_route: Option<Option<usize>>,

    /// Interned tag names: tag_id -> tag name string.
    tag_names: Vec<String>,

    /// Number of unique tags (for TagMemo sizing).
    num_tags: usize,

    /// L1 route cache: qname -> rule index (or usize::MAX for no match).
    /// `FxBuildHasher` instead of the cache's default hasher: qnames are not
    /// attacker-controlled in a way that matters here (worst case is a
    /// slightly uneven cache distribution, not a DoS), so the cheaper
    /// non-cryptographic hasher is a pure win, matching `DnsCache`'s cache
    /// in `cache.rs`.
    route_cache: Cache<Arc<str>, usize, UnitWeighter, FxBuildHasher>,
}

impl RouteIndex {
    /// Build the index from the finalized rule slice.
    ///
    /// Rules are partitioned into two non-overlapping streams:
    /// - **Match entries**: rules with a non-empty `matcher`; stored in
    ///   `match_entries`, each compiled into a `DomainMatcher` (for `Domain`
    ///   entries) plus a list of `TagGroup`s (for `tag:` entries).
    /// - **Catch-all**: empty `matcher`; first one stored as `catch_all_idx`.
    ///
    /// `dns_cache_capacity` sizes the L1 route-decision cache: it tracks
    /// roughly the same domain cardinality as the full-response `DnsCache`
    /// (`cfg.cache_size`) rather than a fixed constant, so a deployment sized
    /// for a large/small distinct-domain working set gets a route cache that
    /// scales with it instead of silently thrashing (too small) or wasting
    /// memory (too large) relative to whatever `DnsCache` was actually
    /// configured for. `ROUTE_CACHE_MIN_CAPACITY` is a floor for configs that
    /// run with `DnsCache` disabled or tiny (`cache_size` near 0) — routing
    /// decisions still benefit from memoization even when responses aren't
    /// cached at all.
    pub fn build(rules: &[Rule], dns_cache_capacity: usize) -> Self {
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

        let mut match_entries: Vec<MatchEntry> = Vec::new();
        let mut catch_all_idx: Option<usize> = None;

        for (idx, rule) in rules.iter().enumerate() {
            if rule.matcher.is_empty() {
                if catch_all_idx.is_none() {
                    catch_all_idx = Some(idx);
                }
                continue;
            }
            let mut domains = DomainMatcher::default();
            let mut tags = Vec::new();
            for m in &rule.matcher {
                match m {
                    RuleMatcher::Domain(pattern) => {
                        // Config parsing already validated every pattern, so
                        // classification here can't produce `Invalid`.
                        match crate::domain::classify_pattern(pattern) {
                            crate::domain::PatternKind::Suffix(n) => domains.insert_suffix(n, ()),
                            crate::domain::PatternKind::Full(n) => domains.insert_full(n, ()),
                            crate::domain::PatternKind::Wildcard(re) => {
                                domains.insert_regex(re, ())
                            }
                            crate::domain::PatternKind::Invalid => {}
                        }
                    }
                    RuleMatcher::Tag { include, exclude } => {
                        tags.push(TagGroup {
                            include_ids: include.iter().map(|t| intern(t)).collect(),
                            exclude_ids: exclude.iter().map(|t| intern(t)).collect(),
                        });
                    }
                }
            }
            match_entries.push(MatchEntry {
                rule_idx: idx,
                domains,
                tags,
            });
        }

        let needs_ruleset = match_entries.iter().any(|e| !e.tags.is_empty());
        // A catch-all at index 0 shadows every later rule (first-match), and
        // with no conditional entries the outcome never depends on the qname.
        let constant_route =
            (catch_all_idx == Some(0) || match_entries.is_empty()).then_some(catch_all_idx);
        let num_tags = tag_names.len();
        let route_cache_capacity = (dns_cache_capacity as u64).max(ROUTE_CACHE_MIN_CAPACITY);
        let route_cache = Cache::with(
            route_cache_capacity as usize,
            route_cache_capacity,
            UnitWeighter,
            FxBuildHasher,
            DefaultLifecycle::default(),
        );
        Self {
            match_entries,
            catch_all_idx,
            needs_ruleset,
            constant_route,
            tag_names,
            num_tags,
            route_cache,
        }
    }

    /// Find the first matching rule for `qname` using the precompiled index.
    ///
    /// The two streams, `match_entries` and `catch_all_idx`, are advanced
    /// in ascending rule-index order, preserving first-match semantics.
    ///
    /// When `ruleset = None`, a `tag:` group's domain-pattern siblings within
    /// the same rule still match normally; the tag groups themselves never
    /// match (can't confirm inclusion or exclusion without the DB).
    ///
    /// `qname` is taken as `&Arc<str>` (the resolver already interned it while
    /// parsing the query) so a route-cache insert is a refcount bump rather
    /// than a fresh string allocation, and the per-query `TagMemo` is only
    /// constructed after an L1 route-cache miss — a cache hit does no
    /// memo/rule-scan work at all.
    /// When every qname routes identically (a leading catch-all, or no
    /// conditional rules at all), returns `Some(rule_index_or_none)` — the
    /// constant decision, needing no qname. `None` means routing is
    /// name-dependent and the caller must supply a qname to [`route`].
    ///
    /// Lets the resolver skip materializing the qname *string* on a pure
    /// constant-route forward (see `QueryContext::ensure_qname`).
    pub fn constant_target(&self) -> Option<Option<usize>> {
        self.constant_route
    }

    pub fn route<'a>(
        &self,
        rules: &'a [Rule],
        qname: &Arc<str>,
        ruleset: Option<&RuleSetDb>,
    ) -> Option<&'a Rule> {
        // Constant decision (catch-all first / no conditional rules): answer
        // immediately, skipping the route cache and the memo entirely.
        if let Some(constant) = self.constant_route {
            return constant.and_then(|idx| rules.get(idx));
        }
        // L1 route cache: only cache when ruleset is available (or no ruleset needed).
        // We don't cache when ruleset is None but some entry has a `tag:` group,
        // because the result might differ once the DB is loaded.
        let use_cache = ruleset.is_some() || !self.needs_ruleset;
        if use_cache {
            if let Some(idx) = self.route_cache.get(qname.as_ref()) {
                return if idx == usize::MAX {
                    None
                } else {
                    rules.get(idx)
                };
            }
        }
        let mut memo = TagMemo::new(self.num_tags);
        let idx = self.route_index_uncached(qname, ruleset, &mut memo);
        if use_cache {
            self.route_cache.insert(Arc::clone(qname), idx);
        }
        rules.get(idx)
    }

    fn route_index_uncached(
        &self,
        qname: &str,
        ruleset: Option<&RuleSetDb>,
        tag_memo: &mut TagMemo,
    ) -> usize {
        let catch_all = self.catch_all_idx.unwrap_or(usize::MAX);

        if self.match_entries.is_empty() {
            return catch_all;
        }

        for entry in &self.match_entries {
            // If the catch-all rule precedes this match entry, it wins first.
            if catch_all < entry.rule_idx {
                return catch_all;
            }
            if match_entry_matches(entry, qname, ruleset, tag_memo, &self.tag_names) {
                return entry.rule_idx;
            }
        }

        // All match entries exhausted; fall through to catch-all if present.
        catch_all
    }
}

/// Does `qname` match this rule's `matcher` list? True if it hits the
/// compiled domain patterns, or satisfies any `tag:` group (at least one
/// include tag matches, if any, and no exclude tag matches).
fn match_entry_matches(
    entry: &MatchEntry,
    qname: &str,
    ruleset: Option<&RuleSetDb>,
    memo: &mut TagMemo,
    tag_names: &[String],
) -> bool {
    if entry.domains.lookup_specific(qname).is_some() || entry.domains.lookup_fuzzy(qname).is_some()
    {
        return true;
    }
    let Some(rs) = ruleset else {
        return false;
    };
    entry
        .tags
        .iter()
        .any(|group| tag_group_matches(group, qname, rs, memo, tag_names))
}

fn tag_group_matches(
    group: &TagGroup,
    qname: &str,
    rs: &RuleSetDb,
    memo: &mut TagMemo,
    tag_names: &[String],
) -> bool {
    // Positive check: if this group has include tags, at least one must match.
    // If there are no include tags (exclude-only group), every domain passes.
    let match_positive = if !group.include_ids.is_empty() {
        group
            .include_ids
            .iter()
            .any(|&id| memo.check(rs, id, &tag_names[id as usize], qname))
    } else {
        true
    };

    if !match_positive {
        return false;
    }

    // Negative check.
    !group
        .exclude_ids
        .iter()
        .any(|&id| memo.check(rs, id, &tag_names[id as usize], qname))
}

// Tests.

#[cfg(test)]
mod tests {
    use super::*;

    fn rule(idx: usize, matcher: Vec<RuleMatcher>) -> Rule {
        Rule {
            index: idx,
            server: "s".to_string(),
            server_arc: Arc::from("s"),
            kind: crate::server::ServerKind::Fixed(crate::config::FixedAnswerSet::default()),
            cache_policy: crate::cache::ResolvedCachePolicy::default(),
            filters: Vec::new(),
            matcher,
            strip_ecs: false,
        }
    }

    fn domain(pattern: &str) -> RuleMatcher {
        RuleMatcher::Domain(pattern.to_string())
    }

    #[test]
    fn catch_all_matches_everything() {
        let rules = vec![rule(0, Vec::new())];
        let idx = RouteIndex::build(&rules, 0);
        let r = idx.route(&rules, &Arc::from("anything.example"), None).unwrap();
        assert_eq!(r.index, 0);
    }

    #[test]
    fn domain_pattern_matches_without_ruleset() {
        let rules = vec![
            rule(0, vec![domain("example.com")]),
            rule(1, Vec::new()), // catch-all
        ];
        let idx = RouteIndex::build(&rules, 0);
        assert_eq!(
            idx.route(&rules, &Arc::from("example.com"), None).unwrap().index,
            0,
            "exact match"
        );
        assert_eq!(
            idx.route(&rules, &Arc::from("other.example"), None).unwrap().index,
            1,
            "falls through to catch-all"
        );
    }

    #[test]
    fn earlier_rule_wins_regardless_of_pattern_specificity() {
        // Rule 0 has a wildcard (less specific); rule 1 has an exact match for
        // the same name. Declaration order must win, not pattern specificity.
        let rules = vec![
            rule(0, vec![domain("*.example.com")]),
            rule(1, vec![domain("a.example.com")]),
        ];
        let idx = RouteIndex::build(&rules, 0);
        assert_eq!(idx.route(&rules, &Arc::from("a.example.com"), None).unwrap().index, 0);
    }

    #[test]
    fn catch_all_before_a_later_rule_wins() {
        let rules = vec![
            rule(0, Vec::new()), // catch-all, declared first
            rule(1, vec![domain("example.com")]),
        ];
        let idx = RouteIndex::build(&rules, 0);
        assert_eq!(idx.route(&rules, &Arc::from("example.com"), None).unwrap().index, 0);
    }

    #[test]
    fn multiple_matcher_entries_are_ored() {
        let rules = vec![rule(0, vec![domain("a.example"), domain("b.example")])];
        let idx = RouteIndex::build(&rules, 0);
        assert!(idx.route(&rules, &Arc::from("a.example"), None).is_some());
        assert!(idx.route(&rules, &Arc::from("b.example"), None).is_some());
        assert!(idx.route(&rules, &Arc::from("c.example"), None).is_none());
    }

    /// Pure-forwarding shapes must resolve as a constant, without consulting
    /// (or populating) the route cache — pinned by observing that the answer
    /// is correct even for qnames never seen before, and that a catch-all at
    /// index 0 shadows later conditional rules exactly as a linear scan would.
    #[test]
    fn constant_route_shapes_resolve_without_cache() {
        // Single catch-all rule (pure forwarder).
        let rules = vec![rule(0, Vec::new())];
        let idx = RouteIndex::build(&rules, 0);
        assert!(idx.constant_route.is_some());
        assert_eq!(
            idx.route(&rules, &Arc::from("a.example"), None).unwrap().index,
            0
        );

        // Catch-all first + a later (unreachable) conditional rule.
        let rules = vec![rule(0, Vec::new()), rule(1, vec![domain("x.example")])];
        let idx = RouteIndex::build(&rules, 0);
        assert!(idx.constant_route.is_some());
        assert_eq!(
            idx.route(&rules, &Arc::from("x.example"), None).unwrap().index,
            0,
            "catch-all at index 0 shadows the later rule"
        );

        // No rules at all (route.final only): constant no-match.
        let rules: Vec<Rule> = Vec::new();
        let idx = RouteIndex::build(&rules, 0);
        assert!(idx.constant_route.is_some());
        assert!(idx.route(&rules, &Arc::from("x.example"), None).is_none());

        // A conditional rule before the catch-all: NOT constant.
        let rules = vec![rule(0, vec![domain("x.example")]), rule(1, Vec::new())];
        let idx = RouteIndex::build(&rules, 0);
        assert!(idx.constant_route.is_none());
        assert_eq!(idx.route(&rules, &Arc::from("x.example"), None).unwrap().index, 0);
        assert_eq!(idx.route(&rules, &Arc::from("y.example"), None).unwrap().index, 1);
    }

    #[test]
    fn tag_only_rule_never_matches_without_ruleset() {
        let rules = vec![rule(
            0,
            vec![RuleMatcher::Tag {
                include: vec!["cn".to_string()],
                exclude: Vec::new(),
            }],
        )];
        let idx = RouteIndex::build(&rules, 0);
        assert!(idx.route(&rules, &Arc::from("example.com"), None).is_none());
    }
}
