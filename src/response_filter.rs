//! Post-response rule filters (`rule.filter`): inspect the resolved response, then
//! decide how to answer — RouteDNS-style router/response-blocklist semantics.
//!
//! A rule's `filter` is an ordered list of [`ResponseFilter`] entries; the first
//! entry whose criteria all match wins (same first-match convention as the `rules`
//! table itself). Criteria within one entry are ANDed; an entry with no criteria
//! at all is rejected at config parse time. Every entry requires the resolved
//! response, so a rule with any `filter` entries always queries upstream first.
//!
//! Match dimensions:
//! - `answer-ip` — one or more `route.ruleset` tags (`behavior: ipcidr`), each
//!   optionally prefixed with `!` to exclude; matches if any resolved answer IP
//!   falls in an include tag's range (or there are no include tags) and none
//!   falls in an exclude tag's range. The same tag-reference mechanism as
//!   `route.final`'s `answer-ip` field, so ipcidr data has one consistent way
//!   to be introduced regardless of where it's used.
//! - `response-type` — matches if any RR in the answer section has one of these types.
//! - `response-rcode` — matches the response RCODE.
//! - `response-qclass` — matches the response QCLASS.
//!
//! Actions ([`FilterAction`]):
//! - `accept` — return the response as-is. The only action `add-ip` is valid
//!   with (see below) — a `drop`/`forward` entry has no response of its own to
//!   pull IPs from.
//! - `drop` — send no reply at all.
//! - `forward` — answer using a named `route.servers` entry's upstream
//!   directly, bypassing rule-level routing/filters entirely (still
//!   cached/logged under the *matched* rule's own identity — see
//!   `crate::resolver::resolve_with_filters`). An empty/NOERROR reply is just
//!   `forward` to a `RCODE://NOERROR` [fixed-answer server](../README.md);
//!   there is no dedicated action for it.
//!
//! `add-ip` populates an ipset/nftset with resolved IPs when an `accept` entry
//! matches — see `crate::ipset`. Since `response-type: A`/`AAAA` already forces
//! the answer section to carry only that record type (a query has exactly one
//! QTYPE), an `add-ip` entry is required to pin `response-type` to exactly one
//! of `A`/`AAAA`, so `add-ip: "myset"` unambiguously targets one address family.

use crate::ruleset::RuleSetDb;
use std::collections::HashSet;

#[derive(Debug, Clone, Copy)]
pub enum FilterAction {
    /// Return the response as-is (see `ResponseFilter::add_ip` for the
    /// optional ipset/nftset side effect this can carry).
    Accept,
    Drop,
    /// Index into `HotState::servers` of the forward target, resolved at startup.
    Forward(usize),
}

#[derive(Debug, Clone)]
pub struct ResponseFilter {
    /// `route.ruleset` ipcidr tag(s), with optional `!` exclusion; empty =
    /// unconstrained. See `crate::config::AnswerIpMatcher`.
    pub answer_ip: crate::config::AnswerIpMatcher,
    /// Empty = unconstrained. Matches if any RR in the answer section has one of these types.
    pub response_type: HashSet<u16>,
    /// Empty = unconstrained.
    pub response_rcode: HashSet<u8>,
    /// Empty = unconstrained.
    pub response_qclass: HashSet<u16>,
    pub action: FilterAction,
}

impl ResponseFilter {
    /// Match using the resolved response.
    pub fn matches(&self, ruleset: Option<&RuleSetDb>, resp: &[u8], question_end: usize) -> bool {
        if !self.answer_ip.is_empty() {
            let ips = crate::dns::answer_ips(resp, question_end);
            let hit = ruleset.is_some_and(|rs| rs.matches_answer_ip(&self.answer_ip, &ips));
            if !hit {
                return false;
            }
        }
        if !self.response_type.is_empty() {
            let types = crate::dns::answer_rr_types(resp, question_end);
            if !types.iter().any(|t| self.response_type.contains(t)) {
                return false;
            }
        }
        if !self.response_rcode.is_empty()
            && !self.response_rcode.contains(&crate::dns::rcode(resp))
        {
            return false;
        }
        if !self.response_qclass.is_empty() {
            let qc = crate::dns::question_qclass(resp, question_end).unwrap_or(0);
            if !self.response_qclass.contains(&qc) {
                return false;
            }
        }
        true
    }
}

/// First filter (in list order, plus its index) whose criteria match the resolved
/// response. The index lets the caller look up this entry's `add-ip` target (if
/// any) in `IpSetManager`, keyed by `(rule_idx, filter_idx)`.
pub fn first_match<'a>(
    filters: &'a [ResponseFilter],
    ruleset: Option<&RuleSetDb>,
    resp: &[u8],
    question_end: usize,
) -> Option<(usize, &'a ResponseFilter)> {
    filters
        .iter()
        .enumerate()
        .find(|(_, f)| f.matches(ruleset, resp, question_end))
}
