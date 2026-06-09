//! Conditional query-drop rules (`--filter-qtype`).
//!
//! A `FilterRule` matches when ALL non-None conditions hold:
//! - `qtype`       — DNS query type
//! - `geosite_tag` — domain must match this GeoSite tag (None = any domain)
//! - `group`       — query must be destined for this routing group (None = any group)
//!
//! Unconditional rules (`qtype` only) are short-circuited on the fast path via
//! `Config::filter_qtype`; this function handles only conditional rules.

use crate::config::FilterRule;
use crate::geosite::GeoSiteDb;

/// Returns `true` when the query should be dropped (answered with an empty reply).
///
/// Called on the slow path after the routing group has been determined.
/// `group_name` is the routing group name (e.g. "main", "alt", "none", or a custom name).
/// `geosite` is the current GeoSite snapshot; `None` means GeoSite is not loaded.
pub fn should_filter_query(
    rules: &[FilterRule],
    qtype: u16,
    group_name: &str,
    geosite: Option<&GeoSiteDb>,
    qname: &str,
) -> bool {
    rules.iter().any(|r| {
        r.qtype == qtype
            && r.group.as_deref().map_or(true, |g| g == group_name)
            && r.geosite_tag
                .as_deref()
                .map_or(true, |tag| geosite.is_some_and(|gs| gs.matches(tag, qname)))
    })
}
