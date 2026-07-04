//! Routing decisions: map a query (qname, qtype) to a `RouteTarget`.
//!
//! Rules are checked in definition order via `route_index.route()`.
//! When no rule matches, the configured `fallback` is applied.

use crate::server::{HotState, ResolvedFallback, Rule};
use crate::upstream::UpstreamPool;
use std::sync::Arc;

static FINAL_ARC: std::sync::OnceLock<Arc<str>> = std::sync::OnceLock::new();

/// Display name for a `route.final` primary/secondary fallback whose actual winner
/// (primary vs secondary) isn't known — e.g. both sides failed. When the winner is
/// known, `Rule::final_name_arc` (`"final->{name}"`) is used instead.
#[inline]
pub(crate) fn final_arc() -> Arc<str> {
    FINAL_ARC.get_or_init(|| Arc::from("final")).clone()
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
    /// IP-test primary vs secondary using an ipcidr-behavior ruleset tag.
    CidrTest {
        primary: &'a Rule,
        secondary: &'a Rule,
    },
}

impl<'a> RouteTarget<'a> {
    pub fn rule_name(&self) -> &'a str {
        match self {
            Self::Rule(rule, _) => &rule.name,
            Self::Race { .. } | Self::CidrTest { .. } => "final",
        }
    }

    /// Returns the rule name as a pre-interned `Arc<str>`, avoiding per-call allocation.
    /// For `Race`/`CidrTest` this is the generic `"final"` fallback name — once the
    /// actual winner (primary vs secondary) is known, prefer that rule's
    /// `final_name_arc` (`"final->{name}"`) instead.
    pub fn rule_name_arc(&self) -> Arc<str> {
        match self {
            Self::Rule(rule, _) => rule.name_arc.clone(),
            Self::Race { .. } | Self::CidrTest { .. } => final_arc(),
        }
    }

    pub fn skip_cache(&self) -> bool {
        match self {
            Self::Rule(rule, _) => rule.cache_policy.skip,
            Self::Race { .. } | Self::CidrTest { .. } => false,
        }
    }

    pub fn upstream(&self) -> Option<&'a UpstreamPool> {
        match self {
            Self::Rule(rule, _) => rule.upstream.as_ref(),
            Self::Race { .. } | Self::CidrTest { .. } => None,
        }
    }

    /// Returns true when every upstream in this target strips ECS, meaning all clients
    /// can share a single cache entry keyed on the ECS-stripped variant.
    pub fn strip_ecs(&self) -> bool {
        match self {
            Self::Rule(g, _) => g.strip_ecs,
            Self::Race { primary, secondary } | Self::CidrTest { primary, secondary } => {
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
        ResolvedFallback::CidrTest { primary, secondary } => {
            if matches!(qtype, 1 | 28) {
                RouteTarget::CidrTest {
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
