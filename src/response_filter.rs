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
//! - `answer-ip` — one or more `route.ruleset` tags (`behavior: ipcidr`); matches
//!   if any resolved answer IP falls in any of the referenced tags' ranges. The
//!   same tag-reference mechanism as `route.final`'s `answer-ip` field, so ipcidr
//!   data has one consistent way to be introduced regardless of where it's used.
//! - `response-type` — matches if any RR in the answer section has one of these types.
//! - `response-rcode` — matches the response RCODE.
//! - `response-qclass` — matches the response QCLASS.
//!
//! Actions ([`FilterAction`]):
//! - `empty` — synthesise an empty NOERROR/NODATA reply, so the client fails over
//!   immediately instead of waiting out a timeout.
//! - `drop` — send no reply at all.
//! - `continue` — treat this rule as unmatched and let routing try the next rule
//!   that matches the query (bounded hop count; falls through to `route.final`
//!   once no more rules match).
//! - `forward` — answer using another named rule's upstream directly, bypassing
//!   that rule's own routing/filters/cache policy.

use crate::ruleset::RuleSetDb;
use std::collections::HashSet;

#[derive(Debug, Clone, Copy)]
pub enum FilterAction {
    Empty,
    Drop,
    Continue,
    /// Index into `HotState::rules` of the forward target, resolved at startup.
    Forward(usize),
}

#[derive(Debug, Clone)]
pub struct ResponseFilter {
    /// `route.ruleset` tags (`behavior: ipcidr`); empty = unconstrained. Matches if
    /// any resolved answer IP falls in any of these tags' ranges.
    pub answer_ip: Vec<String>,
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
            let hit = ruleset.is_some_and(|rs| {
                self.answer_ip
                    .iter()
                    .any(|tag| rs.matches_any_ip(tag, &ips))
            });
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

/// First filter (in list order) whose criteria match the resolved response.
pub fn first_match(
    filters: &[ResponseFilter],
    ruleset: Option<&RuleSetDb>,
    resp: &[u8],
    question_end: usize,
) -> Option<FilterAction> {
    filters
        .iter()
        .find(|f| f.matches(ruleset, resp, question_end))
        .map(|f| f.action)
}
