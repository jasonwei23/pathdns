//! Compiled routing index for fast group selection at query time.
//!
//! `RouteIndex` is built once at config load time from the finalized group
//! list.  Groups are GeoSite-only (no domain-list files), so the index stores
//! two things:
//!
//! - **GeoSite entries**: groups with `geosite_include` or `geosite_exclude`,
//!   checked in ascending group-index order with per-query tag memoization so
//!   each tag string is evaluated at most once per query.
//! - **Catch-all index**: the first group with no positive matchers and no
//!   exclude rules; matches every domain unconditionally.
//!
//! The merge of these two streams preserves first-match semantics identical to
//! the old linear group matching loop.

use crate::geosite::GeoSiteDb;
use crate::server::CustomGroup;
use moka::sync::Cache as MokaCache;
use smallvec::SmallVec;
use std::collections::HashMap;

// TagMemo.

/// Per-query memoization of `GeoSiteDb::matches(tag_id, qname)`.
///
/// Uses tag IDs (u16) as indices into a SmallVec<[Option<bool>; 32]>.
/// This avoids string comparisons on the hot path.
struct TagMemo {
    results: SmallVec<[Option<bool>; 32]>,
}

impl TagMemo {
    fn new(num_tags: usize) -> Self {
        let mut results = SmallVec::new();
        results.resize(num_tags, None);
        Self { results }
    }

    fn check(&mut self, gs: &GeoSiteDb, tag_id: u16, tag_name: &str, qname: &str) -> bool {
        let idx = tag_id as usize;
        if let Some(v) = self.results.get(idx).copied().flatten() {
            return v;
        }
        let v = gs.matches(tag_name, qname);
        if let Some(slot) = self.results.get_mut(idx) {
            *slot = Some(v);
        }
        v
    }
}

// GeoSiteEntry.

/// A group that requires GeoSite consultation at routing time.
struct GeoSiteEntry {
    /// Index into `AppState::groups`.
    group_idx: usize,
    /// Interned tag IDs for include tags.
    include_ids: SmallVec<[u16; 4]>,
    /// Interned tag IDs for exclude tags.
    exclude_ids: SmallVec<[u16; 4]>,
}

// RouteIndex.

/// Precompiled routing index.  Build once after group construction; reuse for
/// every query. Immutable after `build`; thread-safe without locking.
pub struct RouteIndex {
    /// Groups with GeoSite rules, in ascending group-index order.
    geosite_entries: Vec<GeoSiteEntry>,

    /// First true catch-all group: no positive matchers and no geosite_exclude.
    /// Matches every domain unconditionally.
    catch_all_idx: Option<usize>,

    /// Interned tag names: tag_id -> tag name string.
    tag_names: Vec<String>,

    /// Number of unique tags (for TagMemo sizing).
    num_tags: usize,

    /// L1 route cache: qname -> group index (or usize::MAX for no match).
    route_cache: MokaCache<String, usize>,
}

impl RouteIndex {
    /// Invalidate the route cache.  Call after a GeoSite database reload so
    /// cached routing decisions are re-derived against the new DB.
    pub fn invalidate(&self) {
        self.route_cache.invalidate_all();
    }

    /// Build the index from the finalized group slice.
    ///
    /// Groups are partitioned into two non-overlapping streams:
    /// - **GeoSite groups**: have `geosite_include` or `geosite_exclude`;
    ///   stored in `geosite_entries`.
    /// - **Catch-all**: no positive matchers and no GeoSite rules;
    ///   first one stored as `catch_all_idx`.
    pub fn build(groups: &[CustomGroup]) -> Self {
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

        let mut geosite_entries: Vec<GeoSiteEntry> = Vec::new();
        let mut catch_all_idx: Option<usize> = None;

        for (idx, group) in groups.iter().enumerate() {
            if !group.geosite_include.is_empty() || !group.geosite_exclude.is_empty() {
                let include_ids = group.geosite_include.iter().map(|t| intern(t)).collect();
                let exclude_ids = group.geosite_exclude.iter().map(|t| intern(t)).collect();
                geosite_entries.push(GeoSiteEntry {
                    group_idx: idx,
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
            geosite_entries,
            catch_all_idx,
            tag_names,
            num_tags,
            route_cache,
        }
    }

    /// Find the first matching group for `qname` using the precompiled index.
    ///
    /// The two streams, `geosite_entries` and `catch_all_idx`, are advanced
    /// in ascending group-index order, preserving first-match semantics.
    ///
    /// When `geosite = None` the index is safe: include tags never match;
    /// exclude tags never block (can't confirm exclusion without the DB).
    pub fn route<'a>(
        &self,
        groups: &'a [CustomGroup],
        qname: &str,
        geosite: Option<&GeoSiteDb>,
    ) -> Option<&'a CustomGroup> {
        // L1 route cache: only cache when geosite is available (or no geosite needed).
        // We don't cache when geosite is None but geosite entries exist, because the
        // result might differ once the DB is loaded.
        let use_cache = geosite.is_some() || self.geosite_entries.is_empty();
        if use_cache {
            if let Some(idx) = self.route_cache.get(qname) {
                return if idx == usize::MAX {
                    None
                } else {
                    groups.get(idx)
                };
            }
            let result = self.route_uncached(groups, qname, geosite);
            let idx = result
                .map(|g| {
                    groups
                        .iter()
                        .position(|x| std::ptr::eq(x, g))
                        .unwrap_or(usize::MAX)
                })
                .unwrap_or(usize::MAX);
            self.route_cache.insert(qname.to_string(), idx);
            return result;
        }
        self.route_uncached(groups, qname, geosite)
    }

    fn route_uncached<'a>(
        &self,
        groups: &'a [CustomGroup],
        qname: &str,
        geosite: Option<&GeoSiteDb>,
    ) -> Option<&'a CustomGroup> {
        let catch_all = self.catch_all_idx.unwrap_or(usize::MAX);

        if self.geosite_entries.is_empty() {
            return if catch_all == usize::MAX {
                None
            } else {
                Some(&groups[catch_all])
            };
        }

        let mut tag_memo = TagMemo::new(self.num_tags);

        for entry in &self.geosite_entries {
            // If the catch-all group precedes this GeoSite entry, it wins first.
            if catch_all < entry.group_idx {
                return Some(&groups[catch_all]);
            }
            let group = &groups[entry.group_idx];
            if geo_entry_matches(entry, qname, geosite, &mut tag_memo, &self.tag_names) {
                return Some(group);
            }
        }

        // All GeoSite entries exhausted; fall through to catch-all if present.
        if catch_all != usize::MAX {
            Some(&groups[catch_all])
        } else {
            None
        }
    }
}

fn geo_entry_matches(
    entry: &GeoSiteEntry,
    qname: &str,
    geosite: Option<&GeoSiteDb>,
    memo: &mut TagMemo,
    tag_names: &[String],
) -> bool {
    // Positive check: if this entry has include tags, at least one must match.
    // If there are no include tags (exclude-only group), every domain passes.
    let match_positive = if !entry.include_ids.is_empty() {
        geosite.is_some_and(|gs| {
            entry
                .include_ids
                .iter()
                .any(|&id| memo.check(gs, id, &tag_names[id as usize], qname))
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
    match geosite {
        Some(gs) => !entry
            .exclude_ids
            .iter()
            .any(|&id| memo.check(gs, id, &tag_names[id as usize], qname)),
        // Without a DB we can't confirm exclusion, so allow.
        None => true,
    }
}

// Tests.
