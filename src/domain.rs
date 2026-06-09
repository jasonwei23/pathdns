//! Domain name utilities: normalization, suffix matching, and CSV tokenization.
//!
//! These helpers operate on domain *strings* rather than on DNS wire format.
//! They are shared by the GeoSite matcher, verdict cache, and config parser.
//! Wire-format packet utilities live in `dns`.

use std::collections::{hash_map::Entry, HashMap};

// Constants.

/// Maximum label-depth tracked by `SuffixTable`. Names with more labels are truncated
/// to their `SUFFIX_MAX_LEVELS` most-specific labels when inserted.
pub const SUFFIX_MAX_LEVELS: usize = 8;

// SuffixTable.

/// Label-aligned suffix matching table shared by `DomainList` and `GeoSiteDb`.
///
/// `insert` adds a normalized domain suffix (e.g. `"example.com"`). `contains_suffix`
/// returns `true` when the queried name equals or is a subdomain of any inserted suffix
/// (e.g. `"www.example.com"` matches `"example.com"`). The walk is O(depth) with a small
/// bitmask pre-filter that skips depths with no entries.
#[derive(Debug, Default)]
pub struct SuffixTable {
    entries: HashMap<String, ()>,
    /// Bitmask: bit `i` is set when at least one suffix with `i+1` dot-separated labels
    /// has been inserted. Used to skip probes at absent depths.
    level_interest: u8,
    level_max: usize,
}

impl SuffixTable {
    /// Insert `name` (already normalized, lowercase, no trailing dot).
    /// Returns `true` if the name was not already present.
    pub fn insert(&mut self, name: String) -> bool {
        match self.entries.entry(name) {
            Entry::Occupied(_) => false,
            Entry::Vacant(e) => {
                let level = e.key().split('.').count().min(SUFFIX_MAX_LEVELS);
                if level > 0 {
                    self.level_interest |= 1u8 << (level - 1);
                    self.level_max = self.level_max.max(level);
                }
                e.insert(());
                true
            }
        }
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Returns `true` when `name` equals or is a subdomain of any inserted suffix.
    /// `name` must already be normalized (lowercase, no trailing dot).
    pub fn contains_suffix(&self, name: &str) -> bool {
        if self.entries.is_empty() {
            return false;
        }
        let bytes = name.as_bytes();
        let mut label_starts = [0usize; SUFFIX_MAX_LEVELS + 1];
        let mut n_starts = 1usize;
        for (i, &b) in bytes.iter().enumerate() {
            if b == b'.' && n_starts <= SUFFIX_MAX_LEVELS {
                label_starts[n_starts] = i + 1;
                n_starts += 1;
            }
        }
        let total = n_starts;
        let max = total.min(self.level_max);
        for level in (1..=max).rev() {
            if self.level_interest & (1u8 << (level - 1)) == 0 {
                continue;
            }
            let start = total - level;
            if self.entries.contains_key(&name[label_starts[start]..]) {
                return true;
            }
        }
        false
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
