//! Routing decisions: map a query (qname, qtype) to a `RouteTarget`.
//!
//! Groups are checked in definition order via `route_table.route()`.
//! When no group matches, the configured `fallback` is applied.

use crate::geosite::GeoSiteDb;
use crate::server::{CustomGroup, HotState, ResolvedFallback};
use crate::upstream::UpstreamPool;
use std::sync::Arc;

static NONE_ARC: std::sync::OnceLock<Arc<str>> = std::sync::OnceLock::new();

#[inline]
fn none_arc() -> Arc<str> {
    NONE_ARC.get_or_init(|| Arc::from("none")).clone()
}

/// The upstream target selected for a query.
#[derive(Clone, Copy)]
pub enum RouteTarget<'a> {
    /// Route to a named custom group. The `usize` is the group's index in `HotState::groups`.
    Group(&'a CustomGroup, usize),
    /// Race primary vs secondary; first valid non-SERVFAIL response wins.
    Race {
        primary: &'a CustomGroup,
        secondary: &'a CustomGroup,
    },
    /// IP-test primary vs secondary using the configured ipset.
    NoneIpSet {
        primary: &'a CustomGroup,
        secondary: &'a CustomGroup,
    },
}

impl<'a> RouteTarget<'a> {
    pub fn group_name(&self) -> &'a str {
        match self {
            Self::Group(group, _) => &group.name,
            Self::Race { .. } | Self::NoneIpSet { .. } => "none",
        }
    }

    /// Returns the group name as a pre-interned `Arc<str>`, avoiding per-call allocation.
    pub fn group_name_arc(&self) -> Arc<str> {
        match self {
            Self::Group(group, _) => group.name_arc.clone(),
            Self::Race { .. } | Self::NoneIpSet { .. } => none_arc(),
        }
    }

    pub fn skip_cache(&self) -> bool {
        match self {
            Self::Group(group, _) => group.cache_policy.skip,
            Self::Race { .. } | Self::NoneIpSet { .. } => false,
        }
    }

    pub fn upstream(&self) -> Option<&'a UpstreamPool> {
        match self {
            Self::Group(group, _) => group.upstream.as_ref(),
            Self::Race { .. } | Self::NoneIpSet { .. } => None,
        }
    }

    /// Returns true when every upstream in this target strips ECS, meaning all clients
    /// can share a single cache entry keyed on the ECS-stripped variant.
    pub fn strip_ecs(&self) -> bool {
        match self {
            Self::Group(g, _) => g.strip_ecs,
            Self::Race { primary, secondary } | Self::NoneIpSet { primary, secondary } => {
                primary.strip_ecs && secondary.strip_ecs
            }
        }
    }
}

/// Determine the `RouteTarget` for a (qname, qtype) using the fallback config.
/// Returns `None` for `FallbackTarget::Null` (caller returns empty response).
pub fn classify_target<'a>(hot: &'a HotState, qtype: u16) -> Option<RouteTarget<'a>> {
    match &hot.fallback {
        ResolvedFallback::Null => None,
        ResolvedFallback::Group(idx) => {
            let group = &hot.groups[*idx];
            group.target()
        }
        ResolvedFallback::Race { primary, secondary } => Some(RouteTarget::Race {
            primary: &hot.groups[*primary],
            secondary: &hot.groups[*secondary],
        }),
        ResolvedFallback::NoneIpSet { primary, secondary } => {
            if matches!(qtype, 1 | 28) {
                Some(RouteTarget::NoneIpSet {
                    primary: &hot.groups[*primary],
                    secondary: &hot.groups[*secondary],
                })
            } else {
                Some(RouteTarget::Race {
                    primary: &hot.groups[*primary],
                    secondary: &hot.groups[*secondary],
                })
            }
        }
    }
}

/// Determine the `RouteTarget` for a background cache-refresh task.
pub fn choose_refresh_target<'a>(
    hot: &'a HotState,
    geosite: Option<Arc<GeoSiteDb>>,
    qname: &str,
    qtype: u16,
) -> Option<RouteTarget<'a>> {
    if let Some(group) = hot
        .routing_index
        .route(&hot.groups, qname, geosite.as_deref())
    {
        return group.target();
    }
    classify_target(hot, qtype)
}
