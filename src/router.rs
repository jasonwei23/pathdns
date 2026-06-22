//! Routing decisions: map a query (qname, qtype) to a `RouteTarget`.
//!
//! Rules are checked in definition order via `route_index.route()`.
//! When no rule matches, the configured `fallback` is applied.

use crate::server::{Rule, HotState, ResolvedFallback};
use crate::upstream::UpstreamPool;
use std::sync::Arc;

static NONE_ARC: std::sync::OnceLock<Arc<str>> = std::sync::OnceLock::new();

#[inline]
pub(crate) fn none_arc() -> Arc<str> {
    NONE_ARC.get_or_init(|| Arc::from("none")).clone()
}

/// The upstream target selected for a query.
#[derive(Clone, Copy)]
pub enum RouteTarget<'a> {
    /// Route to a named custom rule. The `usize` is the rule's index in `HotState::rules`.
    Rule(&'a Rule, usize),
    /// Race primary vs secondary; first valid non-SERVFAIL response wins.
    Race {
        primary: &'a Rule,
        secondary: &'a Rule,
    },
    /// IP-test primary vs secondary using the configured ipset.
    IpSetTest {
        primary: &'a Rule,
        secondary: &'a Rule,
    },
}

impl<'a> RouteTarget<'a> {
    pub fn rule_name(&self) -> &'a str {
        match self {
            Self::Rule(rule, _) => &rule.name,
            Self::Race { .. } | Self::IpSetTest { .. } => "none",
        }
    }

    /// Returns the rule name as a pre-interned `Arc<str>`, avoiding per-call allocation.
    pub fn rule_name_arc(&self) -> Arc<str> {
        match self {
            Self::Rule(rule, _) => rule.name_arc.clone(),
            Self::Race { .. } | Self::IpSetTest { .. } => none_arc(),
        }
    }

    pub fn skip_cache(&self) -> bool {
        match self {
            Self::Rule(rule, _) => rule.cache_policy.skip,
            Self::Race { .. } | Self::IpSetTest { .. } => false,
        }
    }

    /// Whether this target collapses CNAME chains in A/AAAA answers.
    pub fn collapse(&self) -> bool {
        match self {
            Self::Rule(rule, _) => rule.collapse,
            Self::Race { .. } | Self::IpSetTest { .. } => false,
        }
    }

    pub fn upstream(&self) -> Option<&'a UpstreamPool> {
        match self {
            Self::Rule(rule, _) => rule.upstream.as_ref(),
            Self::Race { .. } | Self::IpSetTest { .. } => None,
        }
    }

    /// Returns true when every upstream in this target strips ECS, meaning all clients
    /// can share a single cache entry keyed on the ECS-stripped variant.
    pub fn strip_ecs(&self) -> bool {
        match self {
            Self::Rule(g, _) => g.strip_ecs,
            Self::Race { primary, secondary } | Self::IpSetTest { primary, secondary } => {
                primary.strip_ecs && secondary.strip_ecs
            }
        }
    }
}

/// Determine the `RouteTarget` for a (qname, qtype) using the fallback config.
/// Every fallback resolves to a routable target — there is no empty-response
/// fallback (omitting `route.final` uses the last rule).
pub fn classify_target<'a>(hot: &'a HotState, qtype: u16) -> RouteTarget<'a> {
    match &hot.fallback {
        ResolvedFallback::Rule(idx) => RouteTarget::Rule(&hot.rules[*idx], *idx),
        ResolvedFallback::Race { primary, secondary } => RouteTarget::Race {
            primary: &hot.rules[*primary],
            secondary: &hot.rules[*secondary],
        },
        ResolvedFallback::IpSetTest { primary, secondary } => {
            if matches!(qtype, 1 | 28) {
                RouteTarget::IpSetTest {
                    primary: &hot.rules[*primary],
                    secondary: &hot.rules[*secondary],
                }
            } else {
                RouteTarget::Race {
                    primary: &hot.rules[*primary],
                    secondary: &hot.rules[*secondary],
                }
            }
        }
    }
}

