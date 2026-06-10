//! Domain name utilities: normalization, suffix matching, and CSV tokenization.
//!
//! These helpers operate on domain *strings* rather than on DNS wire format.
//! They are shared by the GeoSite matcher, verdict cache, and config parser.
//! Wire-format packet utilities live in `dns`.

use rustc_hash::FxHashMap;
use std::collections::hash_map::Entry;

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
    entries: FxHashMap<String, ()>,
    /// Bitmask: bit `i` is set when at least one suffix with `i+1` dot-separated labels
    /// has been inserted. Used to skip probes at absent depths.
    level_interest: u8,
    level_max: usize,
}

impl SuffixTable {
    /// Insert `name` (already normalized, lowercase, no trailing dot).
    /// Returns `true` if the name was not already present.
    pub fn insert(&mut self, name: String) -> bool {
        let label_count = name.split('.').count();
        let level = label_count.min(SUFFIX_MAX_LEVELS);
        // Truncate overly-deep names to their rightmost SUFFIX_MAX_LEVELS labels so
        // the stored key matches what contains_suffix extracts from the query name.
        let effective_name = if label_count > SUFFIX_MAX_LEVELS {
            let skip = label_count - SUFFIX_MAX_LEVELS;
            let mut dot_count = 0usize;
            let start = name
                .bytes()
                .position(|b| {
                    if b == b'.' {
                        dot_count += 1;
                        dot_count == skip
                    } else {
                        false
                    }
                })
                .map_or(0, |i| i + 1);
            name[start..].to_string()
        } else {
            name
        };
        match self.entries.entry(effective_name) {
            Entry::Occupied(_) => false,
            Entry::Vacant(e) => {
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
        // Scan right-to-left: suffix_starts[k] is the byte offset of the
        // (k+2)-label suffix from the right.  suffix_starts[0] points to the
        // single-label suffix (after the last dot); suffix_starts[k] points to
        // the (k+1+1 = k+2)-label suffix.
        let mut suffix_starts = [0usize; SUFFIX_MAX_LEVELS];
        let mut count = 0usize;
        for (i, &b) in name.as_bytes().iter().enumerate().rev() {
            if b == b'.' {
                suffix_starts[count] = i + 1;
                count += 1;
                if count >= SUFFIX_MAX_LEVELS {
                    break;
                }
            }
        }
        // total_levels: how many suffix lengths we can probe, capped by level_max.
        let total_levels = (count + 1).min(self.level_max);
        for level in (1..=total_levels).rev() {
            if self.level_interest & (1u8 << (level - 1)) == 0 {
                continue;
            }
            let start = if level <= count { suffix_starts[level - 1] } else { 0 };
            if self.entries.contains_key(&name[start..]) {
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

#[cfg(test)]
mod tests {
    use super::*;

    fn make_table(suffixes: &[&str]) -> SuffixTable {
        let mut t = SuffixTable::default();
        for &s in suffixes {
            t.insert(s.to_string());
        }
        t
    }

    #[test]
    fn basic_suffix_match() {
        let t = make_table(&["example.com"]);
        assert!(t.contains_suffix("example.com"));
        assert!(t.contains_suffix("www.example.com"));
        assert!(t.contains_suffix("a.b.example.com"));
        assert!(!t.contains_suffix("notexample.com"));
        assert!(!t.contains_suffix("com"));
    }

    #[test]
    fn single_label_suffix() {
        let t = make_table(&["com"]);
        assert!(t.contains_suffix("com"));
        assert!(t.contains_suffix("example.com"));
        assert!(t.contains_suffix("foo.bar.com"));
        assert!(!t.contains_suffix("net"));
    }

    #[test]
    fn deep_query_matches_shallow_suffix() {
        let t = make_table(&["e.f.g.h.i"]);
        assert!(
            t.contains_suffix("a.b.c.d.e.f.g.h.i"),
            "9-label query should match 5-label suffix"
        );
        assert!(
            t.contains_suffix("x.a.b.c.d.e.f.g.h.i"),
            "10-label query should match 5-label suffix"
        );
    }

    #[test]
    fn max_depth_suffix_matches_deeper_query() {
        let suffix = "a.b.c.d.e.f.g.h";
        let t = make_table(&[suffix]);
        assert!(t.contains_suffix("a.b.c.d.e.f.g.h"), "exact match");
        assert!(t.contains_suffix("x.a.b.c.d.e.f.g.h"), "9-label query");
        assert!(t.contains_suffix("y.x.a.b.c.d.e.f.g.h"), "10-label query");
        assert!(!t.contains_suffix("b.c.d.e.f.g.h"), "shorter name should not match");
    }

    #[test]
    fn insert_truncates_overlength_names() {
        let nine_label = "a.b.c.d.e.f.g.h.i";
        let t = make_table(&[nine_label]);
        assert!(
            t.contains_suffix("x.b.c.d.e.f.g.h.i"),
            "10-label query matches truncated 8-label key"
        );
        assert!(
            t.contains_suffix("b.c.d.e.f.g.h.i"),
            "exact truncated suffix matches"
        );
    }

    #[test]
    fn no_false_positives_across_tlds() {
        let t = make_table(&["google.com"]);
        assert!(!t.contains_suffix("google.net"));
        assert!(!t.contains_suffix("notgoogle.com"));
        assert!(!t.contains_suffix("com"));
    }

    #[test]
    fn empty_table() {
        let t = SuffixTable::default();
        assert!(!t.contains_suffix("example.com"));
    }

    #[test]
    fn normalize_domain_basic() {
        assert_eq!(normalize_domain("Example.COM."), Some("example.com".into()));
        assert_eq!(normalize_domain(""), None);
        assert_eq!(normalize_domain("."), None);
        assert_eq!(normalize_domain("a..b"), None);
        assert_eq!(normalize_domain("a"), Some("a".into()));
    }
}
