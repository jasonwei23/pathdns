//! Routing decisions: map a query (qname, qtype) to a `RouteTarget`.
//!
//! Groups are checked in definition order via `routing_index.route()`.
//! When no group matches, the configured `fallback` is applied.

use crate::server::{AppState, CustomGroup, ResolvedFallback};
use crate::upstream::UpstreamPool;
use std::sync::Arc;

/// The upstream target selected for a query.
#[derive(Clone, Copy)]
pub enum RouteTarget<'a> {
    /// Route to a named custom group.
    Group(&'a CustomGroup),
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
            Self::Group(group) => &group.name,
            Self::Race { .. } | Self::NoneIpSet { .. } => "none",
        }
    }

    pub fn skip_cache(&self) -> bool {
        match self {
            Self::Group(group) => group.cache_policy.skip,
            Self::Race { .. } | Self::NoneIpSet { .. } => false,
        }
    }

    pub fn upstream(&self) -> Option<&'a UpstreamPool> {
        match self {
            Self::Group(group) => group.upstream.as_ref(),
            Self::Race { .. } | Self::NoneIpSet { .. } => None,
        }
    }

    /// Returns true when every upstream in this target strips ECS, meaning all clients
    /// can share a single cache entry keyed on the ECS-stripped variant.
    pub fn strip_ecs(&self) -> bool {
        match self {
            Self::Group(g) => g.strip_ecs,
            Self::Race { primary, secondary } | Self::NoneIpSet { primary, secondary } => {
                primary.strip_ecs && secondary.strip_ecs
            }
        }
    }
}

/// Determine the `RouteTarget` for a (qname, qtype) using the fallback config.
/// Returns `None` for `FallbackTarget::Null` (caller returns empty response).
pub fn classify_target<'a>(state: &'a AppState, qtype: u16) -> Option<RouteTarget<'a>> {
    match &state.fallback {
        ResolvedFallback::Null => None,
        ResolvedFallback::Group(idx) => {
            let group = &state.groups[*idx];
            group.target()
        }
        ResolvedFallback::Race { primary, secondary } => Some(RouteTarget::Race {
            primary: &state.groups[*primary],
            secondary: &state.groups[*secondary],
        }),
        ResolvedFallback::NoneIpSet { primary, secondary } => {
            if matches!(qtype, 1 | 28) {
                Some(RouteTarget::NoneIpSet {
                    primary: &state.groups[*primary],
                    secondary: &state.groups[*secondary],
                })
            } else {
                Some(RouteTarget::Race {
                    primary: &state.groups[*primary],
                    secondary: &state.groups[*secondary],
                })
            }
        }
    }
}

/// Determine the `RouteTarget` for a background cache-refresh task.
pub fn choose_refresh_target<'a>(
    state: &'a AppState,
    qname: &str,
    qtype: u16,
) -> Option<RouteTarget<'a>> {
    let geosite = if state.needs_geosite {
        state.geosite_snapshot()
    } else {
        None
    };
    if let Some(group) = state
        .routing_index
        .route(&state.groups, qname, geosite.as_deref())
    {
        return group.target();
    }
    classify_target(state, qtype)
}
