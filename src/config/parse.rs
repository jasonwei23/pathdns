//! JSON-to-domain-type parsing/validation helpers for `Config`, split out of
//! `config/mod.rs` (which now holds just the schema types and top-level
//! validation) to keep that file to a manageable size.

use super::json::{self, JsonBindSection, JsonRuleCacheSection, JsonRuleEntry, JsonRuleSetEntry};
use super::*;
use anyhow::{anyhow, Context, Result};
use crate::ruleset::{RuleSetBehavior, RuleSetFormat, RuleSetSpec};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

// ── Config parsing helpers ───────────────────────────────────────────────────

/// Parse the `route.final` config value.
///
/// Accepted forms:
/// - `"route": {"final": "<rule>"}` — route unmatched queries to a named rule
/// - `"route": {"final": {"primary":…, "secondary":…, "answer-ip":…}}`
///   — **answer-ip test mode**: both rules are queried concurrently (for latency),
///   but the upstream is *decided by ipcidr-behavior `route.ruleset` membership*.
///   `answer-ip` is required.
///
/// Omitting `route.final` entirely falls back to the last rule.
pub(super) fn parse_final_config(
    value: serde_json::Value,
    rules: &[RuleSpec],
) -> Result<(FallbackConfig, Option<VerdictCacheConfig>)> {
    let rule_exists = |name: &str| rules.iter().any(|g| g.name == name);

    // String shorthand: a rule name.
    if let serde_json::Value::String(name) = &value {
        if !rule_exists(name) {
            return Err(anyhow!("route.final \"{name}\": no such rule"));
        }
        return Ok((
            FallbackConfig {
                target: FallbackTarget::Rule(name.clone()),
                noip_as_primary_ip: false,
            },
            None,
        ));
    }

    // Object form: always answer-ip test mode.
    let jf: json::JsonFinalSection =
        serde_json::from_value(value).map_err(|e| anyhow!("invalid route.final section: {e}"))?;

    let primary = jf.primary.ok_or_else(|| {
        anyhow!(
            "route.final: answer-ip test mode requires \"primary\" \
             (to route to a single rule use \"route.final\": \"<rule>\")"
        )
    })?;
    let secondary = jf
        .secondary
        .ok_or_else(|| anyhow!("route.final: answer-ip test mode requires \"secondary\""))?;
    if !rule_exists(&primary) {
        return Err(anyhow!("route.final.primary \"{primary}\": no such rule"));
    }
    if !rule_exists(&secondary) {
        return Err(anyhow!(
            "route.final.secondary \"{secondary}\": no such rule"
        ));
    }
    if primary == secondary {
        return Err(anyhow!(
            "route.final.primary and route.final.secondary must be different rules"
        ));
    }
    let answer_ip_tags =
        parse_tag_list(jf.answer_ip, "route.final.answer-ip").with_context(|| {
            "the primary's answer IPs are tested against that tag's IP ranges \
         to decide which upstream's answer is used"
        })?;
    if answer_ip_tags.is_empty() {
        return Err(anyhow!(
            "route.final: {{\"primary\", \"secondary\"}} requires \"answer-ip\" — \
             the primary's answer IPs are tested against that route.ruleset \
             tag (behavior: ipcidr) to decide which upstream's answer is used"
        ));
    }

    let verdict_cache = jf.verdict_cache.and_then(|vc| {
        vc.size
            .filter(|&c| c > 0)
            .map(|capacity| VerdictCacheConfig {
                capacity,
                ttl: Duration::from_secs(vc.ttl.unwrap_or(0)),
            })
    });

    Ok((
        FallbackConfig {
            target: FallbackTarget::Dual {
                primary,
                secondary,
                answer_ip_tags,
            },
            noip_as_primary_ip: jf.noip_as_primary_ip.unwrap_or(false),
        },
        verdict_cache,
    ))
}

pub(super) fn parse_ipset_config(rules: &[RuleSpec]) -> Result<Option<IpSetConfig>> {
    // Add pairs come from rule.add_ip entries.
    let mut add_rules: Vec<(String, IpSetPair)> = Vec::new();
    for rule in rules {
        if let Some(raw) = &rule.add_ip {
            add_rules.push((rule.name.clone(), parse_ipset_pair(raw)?));
        }
    }

    if !add_rules.is_empty() {
        Ok(Some(IpSetConfig { add_rules }))
    } else {
        Ok(None)
    }
}

pub(super) fn parse_rule_tag_entry(value: &str) -> Result<RuleTagEntry> {
    let value = value.trim();
    let (raw, negated) = match value.strip_prefix('!') {
        Some(t) => (t, true),
        None => (value, false),
    };
    if raw.is_empty() || is_invalid_ruleset_tag(raw) {
        return Err(anyhow!("rule tag: expected TAG or !TAG, got: {value}"));
    }
    let lowered = raw.to_lowercase();
    if negated {
        Ok(RuleTagEntry::Exclude(lowered))
    } else {
        Ok(RuleTagEntry::Include(lowered))
    }
}

pub(super) fn is_invalid_ruleset_tag(value: &str) -> bool {
    value.contains(':') || value.contains('/') || value.contains('\\')
}

/// Validate and lowercase a `route.ruleset` tag reference used for ipcidr matching
/// (not a set name) — shared by `route.final`'s `answer-ip` and `rule.filter`'s
/// `answer-ip`, so both are validated the same way.
pub(super) fn validate_ipcidr_tag_ref(tag: &str) -> Result<String> {
    let tag = tag.trim();
    if tag.is_empty() || is_invalid_ruleset_tag(tag) {
        return Err(anyhow!(
            "\"{tag}\" must be a plain route.ruleset tag (behavior: ipcidr), not a set name"
        ));
    }
    Ok(tag.to_lowercase())
}

pub(super) enum RuleTagEntry {
    Include(String),
    Exclude(String),
}

/// Parse and validate `route.ruleset` entries into `RuleSetSpec`s.
///
/// Each entry requires a non-empty `tag` (unique across the whole list — a
/// rule-set file carries no tag of its own, so `RuleSetDb` trusts this
/// invariant instead of re-checking it), a `format` of `text`/`mrs`, a
/// `behavior` of `domain`/`ipcidr`, and a non-empty `path`.
pub(super) fn parse_ruleset_specs(entries: Vec<JsonRuleSetEntry>) -> Result<Vec<RuleSetSpec>> {
    let mut seen_tags = std::collections::HashSet::new();
    let mut specs = Vec::with_capacity(entries.len());
    for e in entries {
        let tag = e.tag.trim();
        if tag.is_empty() || is_invalid_ruleset_tag(tag) {
            return Err(anyhow!(
                "route.ruleset entry: tag must be non-empty and must not \
                 contain ':', '/', or '\\', got: {}",
                e.tag
            ));
        }
        let tag = tag.to_lowercase();
        if !seen_tags.insert(tag.clone()) {
            return Err(anyhow!("route.ruleset: duplicate tag '{tag}'"));
        }

        let format = match e.format.as_str() {
            "text" => RuleSetFormat::Text,
            "mrs" => RuleSetFormat::Mrs,
            other => {
                return Err(anyhow!(
                    "route.ruleset entry '{tag}': format must be \"text\" or \"mrs\", got: {other}"
                ))
            }
        };
        let behavior = match e.behavior.as_str() {
            "domain" => RuleSetBehavior::Domain,
            "ipcidr" => RuleSetBehavior::IpCidr,
            other => {
                return Err(anyhow!(
                    "route.ruleset entry '{tag}': behavior must be \"domain\" or \"ipcidr\", got: {other}"
                ))
            }
        };
        if e.path.trim().is_empty() {
            return Err(anyhow!("route.ruleset entry '{tag}': path cannot be empty"));
        }

        specs.push(RuleSetSpec {
            tag,
            format,
            behavior,
            path: PathBuf::from(e.path),
        });
    }
    Ok(specs)
}

pub(super) fn parse_rule_cache_policy(cache: Option<JsonRuleCacheSection>) -> Result<Option<RuleCachePolicy>> {
    let Some(c) = cache else {
        return Ok(None);
    };

    // Check for conflicting fields when size: 0 disables the cache.
    let has_other_fields = c.min_ttl.is_some() || c.max_ttl.is_some();

    match c.size {
        Some(0) => {
            if has_other_fields {
                return Err(anyhow!(
                    "rule cache.size: 0 disables caching for this rule; \
                     other cache fields are meaningless alongside it and must be removed"
                ));
            }
            return Ok(Some(RuleCachePolicy {
                skip: true,
                min_ttl: None,
                max_ttl: None,
            }));
        }
        Some(n) => {
            return Err(anyhow!(
                "rule cache.size must be 0 (skip cache) or omitted; \
                 set the cache capacity with the global cache.size (got {n})"
            ));
        }
        None => {}
    }

    // Validate min_ttl ≤ max_ttl when both are set and non-zero.
    if let (Some(min), Some(max)) = (c.min_ttl, c.max_ttl) {
        if min > 0 && max > 0 && min > max {
            return Err(anyhow!(
                "rule cache.min-ttl ({min}) must not be greater than cache.max-ttl ({max})"
            ));
        }
    }

    Ok(Some(RuleCachePolicy {
        skip: false,
        min_ttl: c.min_ttl,
        max_ttl: c.max_ttl,
    }))
}

/// Accept a `route.ruleset` tag name or array of tag names (used by `answer-ip`),
/// validating and lowercasing each via `validate_ipcidr_tag_ref`.
pub(super) fn parse_tag_list(value: Option<serde_json::Value>, field: &str) -> Result<Vec<String>> {
    let one = |v: serde_json::Value| -> Result<String> {
        let serde_json::Value::String(s) = v else {
            return Err(anyhow!(
                "{field} must be a tag name string or an array of them"
            ));
        };
        validate_ipcidr_tag_ref(&s).with_context(|| field.to_string())
    };
    match value {
        None | Some(serde_json::Value::Null) => Ok(vec![]),
        Some(serde_json::Value::Array(arr)) => arr.into_iter().map(one).collect(),
        Some(v) => Ok(vec![one(v)?]),
    }
}

/// Accept a positive integer or array of positive integers (used by
/// `response-type` / `response-qclass`, both 16-bit DNS fields), coercing string
/// elements through `parse_name`.
pub(super) fn parse_u16_list(
    value: Option<serde_json::Value>,
    field: &str,
    parse_name: impl Fn(&str) -> Result<u64>,
) -> Result<Vec<u16>> {
    fn to_u16(n: u64, field: &str) -> Result<u16> {
        u16::try_from(n).map_err(|_| anyhow!("{field} value {n} is out of range (0–65535)"))
    }
    let one = |v: serde_json::Value| -> Result<u16> {
        match v {
            serde_json::Value::Number(n) => to_u16(
                n.as_u64()
                    .ok_or_else(|| anyhow!("{field} must be a non-negative integer or name"))?,
                field,
            ),
            serde_json::Value::String(s) => to_u16(parse_name(&s)?, field),
            _ => Err(anyhow!(
                "{field} must be an integer, a name string, or an array of them"
            )),
        }
    };
    match value {
        None | Some(serde_json::Value::Null) => Ok(vec![]),
        Some(serde_json::Value::Array(arr)) => arr.into_iter().map(one).collect(),
        Some(v) => Ok(vec![one(v)?]),
    }
}

pub(super) fn parse_rrtype_name(name: &str) -> Result<u64> {
    Ok(match name.to_ascii_uppercase().as_str() {
        "A" => 1,
        "NS" => 2,
        "CNAME" => 5,
        "SOA" => 6,
        "PTR" => 12,
        "MX" => 15,
        "TXT" => 16,
        "AAAA" => 28,
        "SRV" => 33,
        "OPT" => 41,
        "DS" => 43,
        "RRSIG" => 46,
        "NSEC" => 47,
        "DNSKEY" => 48,
        "SVCB" => 64,
        "HTTPS" => 65,
        "CAA" => 257,
        "ANY" => 255,
        other => other.parse::<u64>().map_err(|_| {
            anyhow!(
                "unknown response-type \"{other}\" — use a record type name \
                 (A/AAAA/CNAME/MX/TXT/NS/SOA/PTR/SRV/HTTPS/SVCB/CAA/...) or a number 0–65535"
            )
        })?,
    })
}

pub(super) fn parse_qclass_name(name: &str) -> Result<u64> {
    Ok(match name.to_ascii_uppercase().as_str() {
        "IN" => 1,
        "CH" => 3,
        "HS" => 4,
        "NONE" => 254,
        "ANY" => 255,
        other => other.parse::<u64>().map_err(|_| {
            anyhow!(
                "unknown response-qclass \"{other}\" — use IN/CH/HS/NONE/ANY or a number 0–65535"
            )
        })?,
    })
}

/// Accept a positive integer or array of positive integers/names for `response-rcode`
/// (an 8-bit field, unlike the other filter dimensions), reusing `parse_rcode_name`.
pub(super) fn parse_rcode_list(value: Option<serde_json::Value>) -> Result<Vec<u8>> {
    let one = |v: serde_json::Value| -> Result<u8> {
        match v {
            serde_json::Value::Number(n) => {
                let n = n.as_u64().ok_or_else(|| {
                    anyhow!("response-rcode must be a non-negative integer or name")
                })?;
                u8::try_from(n)
                    .map_err(|_| anyhow!("response-rcode value {n} is out of range (0–15)"))
            }
            serde_json::Value::String(s) => parse_rcode_name(&s),
            _ => Err(anyhow!(
                "response-rcode must be an integer, a name string, or an array of them"
            )),
        }
    };
    match value {
        None | Some(serde_json::Value::Null) => Ok(vec![]),
        Some(serde_json::Value::Array(arr)) => arr.into_iter().map(one).collect(),
        Some(v) => Ok(vec![one(v)?]),
    }
}

/// Parse `rule.filter`: an ordered list of match-criteria + action entries.
/// See `crate::response_filter` module docs for match/action semantics.
pub(super) fn parse_rule_filters(
    entries: Option<Vec<json::JsonRuleFilterEntry>>,
) -> Result<Vec<RuleFilterSpec>> {
    let Some(entries) = entries else {
        return Ok(vec![]);
    };
    entries
        .into_iter()
        .enumerate()
        .map(|(i, e)| parse_rule_filter_entry(e).with_context(|| format!("rule.filter[{i}]")))
        .collect()
}

pub(super) fn parse_rule_filter_entry(e: json::JsonRuleFilterEntry) -> Result<RuleFilterSpec> {
    let answer_ip = parse_tag_list(e.answer_ip, "answer-ip")?;
    let response_type = parse_u16_list(e.response_type, "response-type", parse_rrtype_name)?;
    let response_rcode = parse_rcode_list(e.response_rcode)?;
    let response_qclass = parse_u16_list(e.response_qclass, "response-qclass", parse_qclass_name)?;

    if answer_ip.is_empty()
        && response_type.is_empty()
        && response_rcode.is_empty()
        && response_qclass.is_empty()
    {
        return Err(anyhow!(
            "must specify at least one match criterion (answer-ip / \
             response-type / response-rcode / response-qclass)"
        ));
    }

    let action = match e.action.to_ascii_lowercase().as_str() {
        "empty" => {
            if e.forward.is_some() {
                return Err(anyhow!("\"forward\" is only valid with action \"forward\""));
            }
            RuleFilterActionSpec::Empty
        }
        "drop" => {
            if e.forward.is_some() {
                return Err(anyhow!("\"forward\" is only valid with action \"forward\""));
            }
            RuleFilterActionSpec::Drop
        }
        "continue" => {
            if e.forward.is_some() {
                return Err(anyhow!("\"forward\" is only valid with action \"forward\""));
            }
            RuleFilterActionSpec::Continue
        }
        "forward" => {
            let target = e.forward.filter(|s| !s.trim().is_empty()).ok_or_else(|| {
                anyhow!("action \"forward\" requires \"forward\": \"<rule name>\"")
            })?;
            RuleFilterActionSpec::Forward(target.trim().to_string())
        }
        other => {
            return Err(anyhow!(
                "unknown filter action \"{other}\" — use empty/drop/continue/forward"
            ))
        }
    };

    Ok(RuleFilterSpec {
        answer_ip,
        response_type,
        response_rcode,
        response_qclass,
        action,
    })
}

pub(super) fn parse_json_rule(jg: JsonRuleEntry) -> Result<RuleSpec> {
    let name = jg.name.trim();
    if name.is_empty() {
        return Err(anyhow!("rule name cannot be empty"));
    }
    let mut ruleset_include = Vec::new();
    let mut ruleset_exclude = Vec::new();
    for tags in jg.tag.iter().flatten() {
        for entry in crate::domain::split_csv(tags) {
            match parse_rule_tag_entry(entry)? {
                RuleTagEntry::Include(t) => ruleset_include.push(t),
                RuleTagEntry::Exclude(t) => ruleset_exclude.push(t),
            }
        }
    }
    let urls = jg.upstream.as_deref().unwrap_or(&[]);
    if urls.is_empty() {
        return Err(anyhow!("rule \"{name}\" requires an upstream"));
    }
    let upstream = parse_upstreams(urls)?;
    let cache_policy = parse_rule_cache_policy(jg.cache)?;
    let filters = parse_rule_filters(jg.filter).with_context(|| format!("rule \"{name}\""))?;
    Ok(RuleSpec {
        name: name.to_string(),
        ruleset_include,
        ruleset_exclude,
        upstream,
        add_ip: jg.add_ip.filter(|s| !s.is_empty()),
        cache_policy,
        filters,
    })
}

/// Parse the `route.answer` map (domain pattern → fixed-answer URL(s)) into a
/// compiled `AnswerMap`. Each value is a single URL string or an array of URLs,
/// restricted to `A://`, `AAAA://`, `CNAME://`, and `RCODE://` (real upstreams
/// are rejected — the map only synthesises local answers).
pub(super) fn parse_answer_map(
    json_answers: std::collections::BTreeMap<String, serde_json::Value>,
) -> Result<crate::answer_map::AnswerMap> {
    let mut map = crate::answer_map::AnswerMap::default();
    for (pattern, value) in json_answers {
        let urls = answer_value_to_urls(&pattern, value)?;
        let (fixed_rcode, rcode_ttl, fixed_answers) = parse_answer_urls(&pattern, &urls)?;
        map.insert(
            &pattern,
            crate::answer_map::AnswerEntry {
                fixed_rcode,
                rcode_ttl,
                fixed_answers,
            },
        )
        .with_context(|| format!("route.answer entry \"{pattern}\""))?;
    }
    Ok(map)
}

/// Coerce a `route.answer` value (string or array of strings) into a list of URLs.
pub(super) fn answer_value_to_urls(pattern: &str, value: serde_json::Value) -> Result<Vec<String>> {
    match value {
        serde_json::Value::String(s) => Ok(vec![s]),
        serde_json::Value::Array(arr) => arr
            .into_iter()
            .map(|v| {
                v.as_str().map(str::to_string).ok_or_else(|| {
                    anyhow!("route.answer entry \"{pattern}\": array values must be strings")
                })
            })
            .collect(),
        _ => Err(anyhow!(
            "route.answer entry \"{pattern}\": value must be a string or array of strings"
        )),
    }
}

/// Validate and parse fixed-answer/RCODE URLs for a `route.answer` entry.
/// Real upstreams are rejected; the same A/AAAA/CNAME/RCODE coexistence rules as
/// fixed-answer rules apply. Returns `(fixed_rcode, rcode_ttl, fixed_answers)`;
/// `rcode_ttl` is only meaningful when `fixed_rcode` is `Some`.
pub(super) fn parse_answer_urls(
    pattern: &str,
    urls: &[String],
) -> Result<(Option<u8>, u32, Vec<FixedAnswer>)> {
    if urls.is_empty() {
        return Err(anyhow!(
            "route.answer entry \"{pattern}\" requires at least one answer"
        ));
    }
    let is_rcode = |u: &String| u.to_ascii_uppercase().starts_with("RCODE://");
    let is_fixed = |u: &String| {
        let upper = u.to_ascii_uppercase();
        upper.starts_with("A://") || upper.starts_with("AAAA://") || upper.starts_with("CNAME://")
    };
    let rcode_count = urls.iter().filter(|u| is_rcode(u)).count();
    let fixed_count = urls.iter().filter(|u| is_fixed(u)).count();
    if rcode_count + fixed_count != urls.len() {
        return Err(anyhow!(
            "route.answer entry \"{pattern}\": only A://, AAAA://, CNAME://, RCODE:// are allowed (no real upstreams)"
        ));
    }
    if rcode_count > 0 && fixed_count > 0 {
        return Err(anyhow!(
            "route.answer entry \"{pattern}\": cannot mix RCODE:// with A://, AAAA://, CNAME://"
        ));
    }
    if rcode_count > 1 {
        return Err(anyhow!(
            "route.answer entry \"{pattern}\": only one RCODE:// is allowed"
        ));
    }
    if rcode_count == 1 {
        let url = urls
            .iter()
            .find(|u| is_rcode(u))
            .ok_or_else(|| anyhow!("route.answer entry \"{pattern}\": missing RCODE value"))?;
        let rest = url.split_once("://").map(|(_, rest)| rest).unwrap_or("");
        let (rcode_name, ttl) = split_answer_ttl(rest).with_context(|| {
            format!("route.answer entry \"{pattern}\": invalid RCODE \"{url}\"")
        })?;
        let rcode = parse_rcode_name(rcode_name).with_context(|| {
            format!("route.answer entry \"{pattern}\": invalid RCODE \"{url}\"")
        })?;
        return Ok((Some(rcode), ttl, Vec::new()));
    }
    // Fixed answers: A and AAAA may coexist; CNAME is exclusive with both.
    let a_count = urls
        .iter()
        .filter(|u| u.to_ascii_uppercase().starts_with("A://"))
        .count();
    let aaaa_count = urls
        .iter()
        .filter(|u| u.to_ascii_uppercase().starts_with("AAAA://"))
        .count();
    let cname_count = urls
        .iter()
        .filter(|u| u.to_ascii_uppercase().starts_with("CNAME://"))
        .count();
    if a_count > 1 {
        return Err(anyhow!(
            "route.answer entry \"{pattern}\": only one A:// is allowed"
        ));
    }
    if aaaa_count > 1 {
        return Err(anyhow!(
            "route.answer entry \"{pattern}\": only one AAAA:// is allowed"
        ));
    }
    if cname_count > 1 {
        return Err(anyhow!(
            "route.answer entry \"{pattern}\": only one CNAME:// is allowed"
        ));
    }
    if cname_count > 0 && (a_count > 0 || aaaa_count > 0) {
        return Err(anyhow!(
            "route.answer entry \"{pattern}\": CNAME:// cannot be combined with A:// or AAAA://"
        ));
    }
    let answers = urls
        .iter()
        .map(|url| {
            parse_fixed_answer(url).with_context(|| format!("route.answer entry \"{pattern}\""))
        })
        .collect::<Result<Vec<_>>>()?;
    Ok((None, DEFAULT_ANSWER_TTL, answers))
}

pub(super) fn parse_rules(json_rules: Vec<JsonRuleEntry>) -> Result<Vec<RuleSpec>> {
    let mut rules = Vec::new();
    for jg in json_rules {
        rules.push(parse_json_rule(jg)?);
    }

    // Reject duplicate rule names.
    let mut seen = std::collections::HashSet::new();
    for g in &rules {
        if !seen.insert(g.name.as_str()) {
            return Err(anyhow!("duplicate rule name: \"{}\"", g.name));
        }
    }

    // Every filter "forward" target must reference a real rule (checked only after
    // all rule names are known, since forward targets may be defined later in the list).
    for g in &rules {
        for f in &g.filters {
            if let RuleFilterActionSpec::Forward(target) = &f.action {
                if !rules.iter().any(|r| &r.name == target) {
                    return Err(anyhow!(
                        "rule \"{}\": filter forward target \"{target}\": no such rule",
                        g.name
                    ));
                }
            }
        }
    }

    Ok(rules)
}

/// Parse the `interface` config list into an `InterfaceFilter`.
///
/// - Empty list → `All` (default, no SO_BINDTODEVICE)
/// - All entries start with `!` → `Except(names)` (all interfaces except these)
/// - No entry starts with `!` → `Only(names)` (only these interfaces)
/// - Mixed → error
pub(super) fn parse_interface_filter(names: Vec<String>) -> Result<InterfaceFilter> {
    if names.is_empty() {
        return Ok(InterfaceFilter::All);
    }
    let n_deny = names.iter().filter(|n| n.starts_with('!')).count();
    if n_deny > 0 && n_deny < names.len() {
        return Err(anyhow!(
            "interface list must be all allow (e.g. [\"eth0\"]) or all deny (e.g. [\"!wan\"]); \
             cannot mix '!' and non-'!' entries"
        ));
    }
    if n_deny == names.len() {
        let excluded: Vec<String> = names.into_iter().map(|n| n[1..].to_string()).collect();
        if excluded.iter().any(|n| n.is_empty()) {
            return Err(anyhow!("interface deny entry must not be just '!'"));
        }
        Ok(InterfaceFilter::Except(excluded))
    } else {
        if names.iter().any(|n| n.is_empty()) {
            return Err(anyhow!("interface name must not be empty"));
        }
        Ok(InterfaceFilter::Only(names))
    }
}

pub(super) fn parse_bind_config(
    bind: Option<JsonBindSection>,
) -> Result<(Vec<BindEndpoint>, InterfaceFilter)> {
    let b = bind.unwrap_or_default();
    let port = b.port.unwrap_or(65353);
    if port == 0 {
        return Err(anyhow!("bind.port must be between 1 and 65535"));
    }
    let (udp, tcp) = match b.proto.as_deref() {
        None | Some("both") => (true, true),
        Some("udp") => (true, false),
        Some("tcp") => (false, true),
        Some(other) => return Err(anyhow!("bind.proto: unknown value '{other}'")),
    };
    let addrs: Vec<IpAddr> = match b.addr {
        None => vec![IpAddr::V4(Ipv4Addr::LOCALHOST)],
        Some(serde_json::Value::String(s)) => vec![parse_ip_only(&s)?],
        Some(serde_json::Value::Array(arr)) => arr
            .iter()
            .map(|v| {
                v.as_str()
                    .ok_or_else(|| anyhow!("bind.addr entries must be strings"))
                    .and_then(parse_ip_only)
            })
            .collect::<Result<_>>()?,
        _ => return Err(anyhow!("bind.addr must be a string or array of strings")),
    };
    let mut seen = std::collections::HashSet::new();
    let mut endpoints = Vec::new();
    for ip in addrs {
        if !seen.insert(ip) {
            return Err(anyhow!("duplicate bind address: {ip}"));
        }
        endpoints.push(BindEndpoint {
            addr: SocketAddr::new(ip, port),
            udp,
            tcp,
        });
    }
    let interface = parse_interface_filter(b.interface.unwrap_or_default())?;
    Ok((endpoints, interface))
}

pub(super) fn parse_ip_only(s: &str) -> Result<IpAddr> {
    let s = s
        .strip_prefix('[')
        .and_then(|s| s.strip_suffix(']'))
        .unwrap_or(s);
    s.parse::<IpAddr>()
        .with_context(|| format!("invalid bind.addr '{s}': expected IP address without port"))
}

pub(super) fn normalize_addr_with_default_port(s: &str, default_port: u16) -> String {
    if s.starts_with('[') {
        if s.rsplit_once(']')
            .is_some_and(|(_, tail)| tail.starts_with(':') && tail[1..].parse::<u16>().is_ok())
        {
            return s.to_string();
        }
        return format!("{s}:{default_port}");
    }
    let colon_count = s.as_bytes().iter().filter(|&&b| b == b':').count();
    if colon_count >= 2 {
        return format!("[{s}]:{default_port}");
    }
    if s.rsplit_once(':')
        .is_some_and(|(_, port)| port.parse::<u16>().is_ok())
    {
        s.to_string()
    } else {
        format!("{s}:{default_port}")
    }
}

/// Split an answer URL's authority (everything after `://`) into the value and a
/// TTL parsed from an optional `?ttl=N` query. Any other query parameter is an error.
pub(super) fn split_answer_ttl(rest: &str) -> Result<(&str, u32)> {
    let Some((value, query)) = rest.split_once('?') else {
        return Ok((rest, DEFAULT_ANSWER_TTL));
    };
    let mut ttl = DEFAULT_ANSWER_TTL;
    for param in query.split('&').filter(|p| !p.is_empty()) {
        let v = param.strip_prefix("ttl=").ok_or_else(|| {
            anyhow!("unknown query parameter '{param}' (only ?ttl= is supported)")
        })?;
        ttl = v
            .parse::<u32>()
            .map_err(|_| anyhow!("invalid ?ttl= value '{v}'"))?;
        if ttl > 2_147_483_647 {
            return Err(anyhow!(
                "?ttl={ttl} exceeds the maximum DNS TTL (2147483647)"
            ));
        }
    }
    Ok((value, ttl))
}

/// Parse an `A://`, `AAAA://`, or `CNAME://` value into a `FixedAnswer`, honouring
/// an optional `?ttl=N` (default [`DEFAULT_ANSWER_TTL`]).
pub(super) fn parse_fixed_answer(url: &str) -> Result<FixedAnswer> {
    let (scheme, rest) = url
        .split_once("://")
        .ok_or_else(|| anyhow!("malformed fixed-answer upstream: '{url}'"))?;
    let (value, ttl) = split_answer_ttl(rest)?;
    match scheme.to_ascii_uppercase().as_str() {
        "A" => {
            let addr: Ipv4Addr = value
                .trim()
                .parse()
                .with_context(|| format!("A://: expected an IPv4 address, got '{value}'"))?;
            Ok(FixedAnswer::A(addr, ttl))
        }
        "AAAA" => {
            let addr: Ipv6Addr = value
                .trim()
                .parse()
                .with_context(|| format!("AAAA://: expected an IPv6 address, got '{value}'"))?;
            Ok(FixedAnswer::Aaaa(addr, ttl))
        }
        "CNAME" => {
            let target = value.trim().trim_end_matches('.');
            if target.is_empty() {
                return Err(anyhow!("CNAME://: target domain cannot be empty"));
            }
            // Validate wire encoding up-front so bad config is caught at startup.
            crate::dns::encode_dns_name(target)
                .with_context(|| format!("CNAME://: invalid target domain '{target}'"))?;
            Ok(FixedAnswer::Cname(target.to_ascii_lowercase(), ttl))
        }
        other => Err(anyhow!(
            "unknown fixed-answer scheme '{other}' (expected A, AAAA, or CNAME)"
        )),
    }
}

pub(super) fn parse_ipset_pair(value: &str) -> Result<IpSetPair> {
    let mut parts = value.splitn(2, ',').map(str::trim);
    let v4 = normalize_ipset_name(parts.next().unwrap_or_default());
    let v6 = normalize_ipset_name(parts.next().unwrap_or_default());
    if v4.is_none() && v6.is_none() {
        return Err(anyhow!("invalid ipset/nftset pair: {value}"));
    }
    Ok(IpSetPair { v4, v6 })
}

pub(super) fn normalize_ipset_name(value: &str) -> Option<String> {
    if value.is_empty() || value == "null" {
        None
    } else {
        Some(value.to_string())
    }
}

pub(super) fn authority_host(authority: &str) -> Result<&str> {
    if let Some(rest) = authority.strip_prefix('[') {
        let Some((host, tail)) = rest.split_once(']') else {
            return Err(anyhow!("invalid IPv6 upstream authority: {authority}"));
        };
        if !tail.is_empty() && !tail.starts_with(':') {
            return Err(anyhow!("invalid upstream authority: {authority}"));
        }
        return Ok(host);
    }
    // An unbracketed authority with 2+ colons is an IPv6 literal missing its
    // required brackets. Without this check, the `rsplit_once(':')` fallback
    // below would silently treat the trailing group as a port — e.g.
    // "2001:db8::1:53" would misparse as address "2001:db8::1" port 53
    // instead of being rejected, sending traffic to a different, wrong
    // address with no diagnostic at all.
    if authority.as_bytes().iter().filter(|&&b| b == b':').count() >= 2 {
        return Err(anyhow!(
            "invalid upstream authority '{authority}': IPv6 addresses must be \
             bracketed, e.g. [::1]:53"
        ));
    }
    Ok(authority
        .rsplit_once(':')
        .filter(|(_, port)| port.parse::<u16>().is_ok())
        .map_or(authority, |(host, _)| host))
}

pub(super) fn strip_ipv6_brackets(host: &str) -> &str {
    host.strip_prefix('[')
        .and_then(|s| s.strip_suffix(']'))
        .unwrap_or(host)
}

// ── Bootstrap DNS — per-upstream hostname resolution at startup ───────────────

/// Parse a `?bootstrap=IP` parameter value.  Must be an IP literal — hostnames
/// are rejected to prevent the same chicken-and-egg problem bootstrap DNS solves.
pub(super) fn parse_bootstrap_addr(s: &str) -> Result<SocketAddr> {
    let normalized = normalize_addr_with_default_port(s, 53);
    // parse::<SocketAddr>() accepts only IP literals, not hostnames.
    normalized.parse::<SocketAddr>().with_context(|| {
        format!(
            "?bootstrap='{s}': must be a literal IP address \
             (e.g. ?bootstrap=223.5.5.5 or ?bootstrap=[::1]:53), not a hostname"
        )
    })
}

/// Extract the port from a `host:port` or `[ipv6]:port` authority string.
pub(super) fn authority_port(authority: &str, default_port: u16) -> u16 {
    if authority.starts_with('[') {
        authority
            .rsplit_once(']')
            .and_then(|(_, tail)| tail.strip_prefix(':')?.parse::<u16>().ok())
            .unwrap_or(default_port)
    } else {
        authority
            .rsplit_once(':')
            .and_then(|(_, p)| p.parse::<u16>().ok())
            .unwrap_or(default_port)
    }
}

/// Resolve an upstream `host` to a `SocketAddr`.
///
/// IP literals are returned directly.  Hostnames are resolved via one-shot UDP
/// queries to the provided `bootstrap` server.  If no bootstrap is given and the
/// host is not an IP literal, an error is returned — `/etc/resolv.conf` is
/// never consulted (it may point to `127.0.0.1` on OpenWrt).
pub(super) fn resolve_host(host: &str, port: u16, bootstrap: &[SocketAddr]) -> Result<SocketAddr> {
    let bare = strip_ipv6_brackets(host);
    if let Ok(ip) = bare.parse::<std::net::IpAddr>() {
        return Ok(SocketAddr::new(ip, port));
    }
    if bootstrap.is_empty() {
        return Err(anyhow!(
            "upstream hostname '{host}' requires ?bootstrap=<IP> to resolve at startup \
             (e.g. tls://dns.google?bootstrap=223.5.5.5); \
             /etc/resolv.conf is never used"
        ));
    }
    let mut last_err: Option<anyhow::Error> = None;
    for &server in bootstrap {
        for qtype in [1u16, 28u16] {
            match bootstrap::bootstrap_udp_query(host, qtype, server) {
                Ok(ip) => return Ok(SocketAddr::new(ip, port)),
                Err(e) => last_err = Some(e),
            }
        }
    }
    Err(last_err.unwrap_or_else(|| anyhow!("no bootstrap servers configured")))
        .with_context(|| format!("bootstrap DNS: failed to resolve '{host}'"))
}

/// Like `parse_authority`, but resolves hostnames using bootstrap DNS.
pub(super) fn resolve_authority<'a>(
    authority: &'a str,
    default_port: u16,
    bootstrap: &[SocketAddr],
) -> Result<(&'a str, SocketAddr)> {
    let host = authority_host(authority)?;
    let port = authority_port(authority, default_port);
    let addr = resolve_host(host, port, bootstrap)?;
    Ok((host, addr))
}
