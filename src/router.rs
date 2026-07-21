//! Routing decisions: map a query (qname, qtype) to a `RouteTarget`.
//!
//! Rules are checked in definition order via `route_index.route()`.
//! When no rule matches, the configured `fallback` is applied.

use crate::server::{HotState, ResolvedFallback, Rule, Server, ServerKind};
use std::sync::Arc;

static FINAL_ARC: std::sync::OnceLock<Arc<str>> = std::sync::OnceLock::new();

/// Display name for a `route.final` primary/secondary fallback whose actual winner
/// (primary vs secondary) isn't known — e.g. both sides failed. When the winner is
/// known, `Server::final_name_arc` (`"final->{name}"`) is used instead.
#[inline]
pub(crate) fn final_arc() -> Arc<str> {
    FINAL_ARC.get_or_init(|| Arc::from("final")).clone()
}

/// The upstream target selected for a query.
#[derive(Clone, Copy)]
pub enum RouteTarget<'a> {
    /// Route to a named custom rule. The `usize` is the rule's index in `HotState::rules`.
    Rule(&'a Rule, usize),
    /// Route straight to a `route.servers` entry: an explicit single-target
    /// `route.final`, or a `rule.filter`'s `forward` action. Bypasses
    /// rule-level cache overrides/filters/add-ip — global cache policy
    /// applies. The `usize` is the server's index in `HotState::servers`.
    Server(&'a Server, usize),
    /// Race primary vs secondary; first valid non-SERVFAIL response wins.
    Race {
        primary: &'a Server,
        secondary: &'a Server,
    },
    /// IP-test primary vs secondary using an ipcidr-behavior ruleset tag.
    CidrTest {
        primary: &'a Server,
        secondary: &'a Server,
    },
}

impl<'a> RouteTarget<'a> {
    /// The upstream name reported to the query log / cache attribution — the
    /// server this target actually resolves (or resolved) through, not
    /// necessarily the matched rule's own name.
    pub fn upstream_name(&self) -> &'a str {
        match self {
            Self::Rule(rule, _) => &rule.server,
            Self::Server(s, _) => &s.name,
            Self::Race { .. } | Self::CidrTest { .. } => "final",
        }
    }

    /// Returns the reporting identity as a pre-interned `Arc<str>`, avoiding a
    /// per-call allocation. `Rule` reports the server it resolves through;
    /// `Server` (an explicit single-target `final`/`forward`) reports
    /// `"final->{name}"` immediately, since there's no winner ambiguity to
    /// resolve later. For `Race`/`CidrTest` this is the generic `"final"`
    /// fallback name — once the actual winner (primary vs secondary) is
    /// known, prefer that server's `final_name_arc` instead.
    pub fn upstream_name_arc(&self) -> Arc<str> {
        match self {
            Self::Rule(rule, _) => rule.server_arc.clone(),
            Self::Server(s, _) => s.final_name_arc.clone(),
            Self::Race { .. } | Self::CidrTest { .. } => final_arc(),
        }
    }

    pub fn skip_cache(&self) -> bool {
        match self {
            Self::Rule(rule, _) => rule.cache_policy.skip,
            Self::Server(_, _) => false,
            Self::Race { .. } | Self::CidrTest { .. } => false,
        }
    }

    /// The `ServerKind` this target actually resolved to. `Rule`/`Server` know
    /// their kind unconditionally; `Race`/`CidrTest` only know it once the
    /// winning side (whichever of `primary`/`secondary` actually answered) is
    /// known, so `winner` must be supplied for those — `None` (winner
    /// undetermined, e.g. a race tie-break failure) reports `None` here too.
    pub fn resolved_kind(&self, winner: Option<&'a Server>) -> Option<&'a ServerKind> {
        match self {
            Self::Rule(rule, _) => Some(&rule.kind),
            Self::Server(s, _) => Some(&s.kind),
            Self::Race { .. } | Self::CidrTest { .. } => winner.map(|s| &s.kind),
        }
    }

    /// Returns true when every upstream in this target strips ECS, meaning all clients
    /// can share a single cache entry keyed on the ECS-stripped variant.
    pub fn strip_ecs(&self) -> bool {
        match self {
            Self::Rule(rule, _) => rule.strip_ecs,
            Self::Server(s, _) => s.strip_ecs,
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
        ResolvedFallback::Server(idx) => RouteTarget::Server(&hot.servers[*idx], *idx),
        ResolvedFallback::Race { primary, secondary } => RouteTarget::Race {
            primary: &hot.servers[*primary],
            secondary: &hot.servers[*secondary],
        },
        ResolvedFallback::CidrTest { primary, secondary } => {
            if matches!(qtype, 1 | 28) {
                RouteTarget::CidrTest {
                    primary: &hot.servers[*primary],
                    secondary: &hot.servers[*secondary],
                }
            } else {
                RouteTarget::Race {
                    primary: &hot.servers[*primary],
                    secondary: &hot.servers[*secondary],
                }
            }
        }
    }
}
