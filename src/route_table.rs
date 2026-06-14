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
use std::sync::Arc;

// TagMemo.

/// Per-query memoization of `GeoSiteDb::matches(tag_id, qname)`.
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

    fn check(&mut self, gs: &GeoSiteDb, tag_id: u16, tag_name: &str, qname: &str) -> bool {
        let idx = tag_id as usize;
        let chunk_idx = idx / 64;
        let bit = 1u64 << (idx % 64);
        if let Some(chunk) = self.chunks.get(chunk_idx) {
            if chunk.seen & bit != 0 {
                return chunk.matched & bit != 0;
            }
        }
        let v = gs.matches(tag_name, qname);
        if let Some(chunk) = self.chunks.get_mut(chunk_idx) {
            chunk.seen |= bit;
            if v {
                chunk.matched |= bit;
            }
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
    route_cache: MokaCache<Arc<str>, usize>,
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
            let idx = self.route_index_uncached(qname, geosite);
            self.route_cache.insert(Arc::from(qname), idx);
            return groups.get(idx);
        }
        groups.get(self.route_index_uncached(qname, geosite))
    }

    fn route_index_uncached(&self, qname: &str, geosite: Option<&GeoSiteDb>) -> usize {
        let catch_all = self.catch_all_idx.unwrap_or(usize::MAX);

        if self.geosite_entries.is_empty() {
            return catch_all;
        }

        let mut tag_memo = TagMemo::new(self.num_tags);

        for entry in &self.geosite_entries {
            // If the catch-all group precedes this GeoSite entry, it wins first.
            if catch_all < entry.group_idx {
                return catch_all;
            }
            if geo_entry_matches(entry, qname, geosite, &mut tag_memo, &self.tag_names) {
                return entry.group_idx;
            }
        }

        // All GeoSite entries exhausted; fall through to catch-all if present.
        catch_all
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tag_memo_packs_sixty_four_tags_per_chunk() {
        let empty = TagMemo::new(0);
        assert!(empty.chunks.is_empty());

        let inline = TagMemo::new(64);
        assert_eq!(inline.chunks.len(), 1);
        assert!(!inline.chunks.spilled());

        let two_chunks = TagMemo::new(65);
        assert_eq!(two_chunks.chunks.len(), 2);
    }

    #[test]
    fn tag_memo_chunk_tracks_seen_and_matched_independently() {
        let mut memo = TagMemo::new(64);
        let false_bit = 1u64 << 7;
        let true_bit = 1u64 << 42;

        memo.chunks[0].seen |= false_bit | true_bit;
        memo.chunks[0].matched |= true_bit;

        assert_ne!(memo.chunks[0].seen & false_bit, 0);
        assert_eq!(memo.chunks[0].matched & false_bit, 0);
        assert_ne!(memo.chunks[0].matched & true_bit, 0);
    }
}
