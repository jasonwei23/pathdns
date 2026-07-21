//! JSON-to-domain-type parsing/validation helpers for `Config`, split out of
//! `config/mod.rs` (which now holds just the schema types and top-level
//! validation) to keep that file to a manageable size.

use super::json::{
    self, JsonBindSection, JsonCacheOverride, JsonDashboardSection, JsonRuleEntry,
    JsonRuleSetEntry, NameOrNumber, OneOrMany,
};
use super::*;
use crate::ruleset::{RuleSetBehavior, RuleSetFormat, RuleSetSpec};
use anyhow::{anyhow, Context, Result};
use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

// ── Config parsing helpers ───────────────────────────────────────────────────

/// Parse the `route.final` config value.
///
/// Accepted forms:
/// - `"route": {"final": "<server>"}` — route unmatched queries straight to a
///   named `route.servers` entry (global cache policy applies; no rule-level
///   filters/add-ip, since this bypasses rule matching entirely).
/// - `"route": {"final": {"primary":…, "secondary":…, "answer-ip":…}}`
///   — **answer-ip test mode**: both servers are queried concurrently (for
///   latency), but the upstream is *decided by ipcidr-behavior `route.ruleset`
///   membership*. `answer-ip` is required.
///
/// Omitting `route.final` entirely falls back to the last configured rule
/// (its cache policy/filters/add-ip apply, unlike the explicit forms above).
pub(super) fn parse_final_config(
    value: serde_json::Value,
    servers: &[(String, ServerSpec)],
) -> Result<(FallbackConfig, Option<VerdictCacheConfig>)> {
    let server_exists = |name: &str| servers.iter().any(|(n, _)| n == name);

    // String shorthand: a server name.
    if let serde_json::Value::String(name) = &value {
        if !server_exists(name) {
            return Err(anyhow!(
                "route.final \"{name}\": no such route.servers entry"
            ));
        }
        return Ok((
            FallbackConfig {
                target: FallbackTarget::Server(name.clone()),
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
             (to route to a single server use \"route.final\": \"<server>\")"
        )
    })?;
    let secondary = jf
        .secondary
        .ok_or_else(|| anyhow!("route.final: answer-ip test mode requires \"secondary\""))?;
    if !server_exists(&primary) {
        return Err(anyhow!(
            "route.final.primary \"{primary}\": no such route.servers entry"
        ));
    }
    if !server_exists(&secondary) {
        return Err(anyhow!(
            "route.final.secondary \"{secondary}\": no such route.servers entry"
        ));
    }
    if primary == secondary {
        return Err(anyhow!(
            "route.final.primary and route.final.secondary must be different servers"
        ));
    }
    let answer_ip =
        parse_answer_ip_matcher(jf.answer_ip, "route.final.answer-ip").with_context(|| {
            "the primary's answer IPs are tested against that tag's IP ranges \
         to decide which upstream's answer is used"
        })?;
    if answer_ip.is_empty() {
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
                answer_ip,
            },
            noip_as_primary_ip: jf.noip_as_primary_ip.unwrap_or(false),
        },
        verdict_cache,
    ))
}

pub(super) fn parse_ipset_config(rules: &[RuleSpec]) -> Result<Option<IpSetConfig>> {
    // Add targets come from filter.add_ip entries, keyed by (rule position,
    // filter position within that rule) — rules and filter entries have no
    // name of their own. `parse_rule_filter_entry` already validated that any
    // entry with `add_ip` set has `response_type` pinned to exactly {A} or
    // {AAAA}, so the family bit here is a direct read, not a re-derivation.
    let mut add_rules: Vec<(usize, usize, String, bool)> = Vec::new();
    for (rule_idx, rule) in rules.iter().enumerate() {
        for (filter_idx, f) in rule.filters.iter().enumerate() {
            if let Some(raw) = &f.add_ip {
                let is_v6 = f.response_type.contains(&28);
                add_rules.push((rule_idx, filter_idx, raw.clone(), is_v6));
            }
        }
    }

    if !add_rules.is_empty() {
        Ok(Some(IpSetConfig { add_rules }))
    } else {
        Ok(None)
    }
}

/// Parse one `rule.matcher` entry: either a `tag:cn,!gfw` ruleset-tag
/// expression, or a domain pattern (bare/`+.`/`.`/`*.` — see
/// `crate::domain::classify_pattern`).
///
/// A rule's `tag:` entry may be exclude-only (`tag:!gfw`, matching everything
/// except `gfw`) so a rule can still express a "catch everything except X"
/// pattern the way the old exclude-only `rule.tag` field did.
pub(super) fn parse_rule_matcher_entry(value: &str) -> Result<RuleMatcher> {
    let value = value.trim();
    if let Some(rest) = value.strip_prefix("tag:") {
        let mut include = Vec::new();
        let mut exclude = Vec::new();
        for token in crate::domain::split_csv(rest) {
            if let Some(name) = token.strip_prefix('!') {
                let name = name.trim();
                if name.is_empty() || is_invalid_ruleset_tag(name) {
                    return Err(anyhow!("rule matcher: invalid tag exclusion '{token}'"));
                }
                exclude.push(name.to_lowercase());
            } else {
                if is_invalid_ruleset_tag(token) {
                    return Err(anyhow!("rule matcher: invalid tag '{token}'"));
                }
                include.push(token.to_lowercase());
            }
        }
        if include.is_empty() && exclude.is_empty() {
            return Err(anyhow!(
                "rule matcher \"tag:{rest}\": expected at least one TAG or !TAG"
            ));
        }
        return Ok(RuleMatcher::Tag { include, exclude });
    }
    if matches!(
        crate::domain::classify_pattern(value),
        crate::domain::PatternKind::Invalid
    ) {
        return Err(anyhow!("invalid rule matcher domain pattern '{value}'"));
    }
    Ok(RuleMatcher::Domain(value.to_string()))
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

/// Parse `route.servers`: name -> a single string or an array of them.
/// Order is preserved (`servers` is built into a stable-order list, not a
/// `HashMap`) purely so startup logs/dashboard rendering are reproducible
/// across reloads; lookups elsewhere still go through a name-keyed map built
/// once in `build_hot_state`.
///
/// Each entry is either:
/// - one or more real upstream URLs (multiple = hedged/raced nodes in one
///   pool — the same capability `rules[].upstream` used to offer directly
///   before it became a single server-name reference), or
/// - one or more fixed-answer URLs (`A://`, `AAAA://`, `RCODE://` — see
///   [`parse_fixed_answer_set`]), never mixed with real upstream URLs in the
///   same entry.
pub(super) fn parse_servers(
    json_servers: std::collections::BTreeMap<String, serde_json::Value>,
) -> Result<Vec<(String, ServerSpec)>> {
    // ── Phase 1: validate names, collect URLs, classify each entry as fixed vs.
    // real upstream, and record each upstream's `?bootstrap=<name>` references.
    // Hostnames are NOT resolved here — that waits for Phase 2, once dependency
    // order is known.
    struct Pending {
        name: String,
        urls: Vec<String>,
        is_fixed: bool,
        deps: Vec<String>,
    }
    let mut seen = HashSet::new();
    let mut pending: Vec<Pending> = Vec::with_capacity(json_servers.len());
    for (name, value) in json_servers {
        let name = name.trim().to_string();
        if name.is_empty() {
            return Err(anyhow!("route.servers: server name cannot be empty"));
        }
        if !seen.insert(name.clone()) {
            return Err(anyhow!("route.servers: duplicate server name '{name}'"));
        }
        let urls: Vec<String> = match value {
            serde_json::Value::String(s) => vec![s],
            serde_json::Value::Array(arr) => arr
                .into_iter()
                .map(|v| {
                    v.as_str().map(str::to_string).ok_or_else(|| {
                        anyhow!("route.servers.{name}: array values must be strings")
                    })
                })
                .collect::<Result<Vec<_>>>()?,
            _ => {
                return Err(anyhow!(
                    "route.servers.{name}: must be a URL string or an array of URL strings"
                ))
            }
        };
        if urls.is_empty() {
            return Err(anyhow!(
                "route.servers.{name}: requires at least one upstream URL"
            ));
        }
        let fixed_count = urls.iter().filter(|u| is_fixed_answer_url(u)).count();
        let is_fixed = if fixed_count == 0 {
            false
        } else if fixed_count == urls.len() {
            true
        } else {
            return Err(anyhow!(
                "route.servers.{name}: cannot mix a fixed answer (A://, AAAA://, RCODE://) \
                 with a real upstream URL"
            ));
        };
        let deps = if is_fixed {
            Vec::new()
        } else {
            urls.iter()
                .filter_map(|u| bootstrap_ref(u).map(|r| r.trim().to_string()))
                .collect()
        };
        pending.push(Pending {
            name,
            urls,
            is_fixed,
            deps,
        });
    }

    // Validate every `?bootstrap=<name>` reference: it must name a different,
    // existing, real-upstream server (a fixed answer can't serve a bootstrap
    // query). Doing this before Phase 2 keeps every failure network-free.
    let all: HashSet<&str> = pending.iter().map(|p| p.name.as_str()).collect();
    let fixed: HashSet<&str> = pending
        .iter()
        .filter(|p| p.is_fixed)
        .map(|p| p.name.as_str())
        .collect();
    for p in &pending {
        for dep in &p.deps {
            if dep == &p.name {
                return Err(anyhow!(
                    "route.servers.{}: ?bootstrap={dep} cannot reference itself",
                    p.name
                ));
            }
            if !all.contains(dep.as_str()) {
                return Err(anyhow!(
                    "route.servers.{}: ?bootstrap={dep}: no such route.servers entry",
                    p.name
                ));
            }
            if fixed.contains(dep.as_str()) {
                return Err(anyhow!(
                    "route.servers.{}: ?bootstrap={dep} must reference a real upstream, \
                     not a fixed-answer server",
                    p.name
                ));
            }
        }
    }

    // ── Phase 2: resolve in dependency order. A server becomes ready once every
    // server it bootstraps from is resolved, so its bootstrap query can use that
    // server's resolved address(es) and fwmark. Results go into index-aligned
    // slots so the original (name-sorted) order is preserved for the caller.
    let mut resolved: Vec<Option<ServerSpec>> = (0..pending.len()).map(|_| None).collect();
    let mut targets: HashMap<String, Vec<BootstrapTarget>> = HashMap::new();
    let mut remaining = pending.len();
    while remaining > 0 {
        let mut progressed = false;
        for (i, p) in pending.iter().enumerate() {
            if resolved[i].is_some() {
                continue;
            }
            if !p.deps.iter().all(|d| targets.contains_key(d)) {
                continue;
            }
            let spec = if p.is_fixed {
                ServerSpec::Fixed(parse_fixed_answer_set(&p.name, &p.urls)?)
            } else {
                // Scope the lookup so its immutable borrow of `targets` ends
                // before we insert this server's own targets below.
                let endpoints = {
                    let lookup = |name: &str| -> Result<Vec<BootstrapTarget>> {
                        Ok(targets.get(name).cloned().unwrap_or_default())
                    };
                    parse_upstreams(&p.urls, &lookup)
                        .with_context(|| format!("route.servers.{}", p.name))?
                };
                let tgts = endpoints
                    .iter()
                    .map(|e| BootstrapTarget {
                        addr: e.addr,
                        mark: e.mark,
                    })
                    .collect();
                targets.insert(p.name.clone(), tgts);
                ServerSpec::Upstream(endpoints)
            };
            resolved[i] = Some(spec);
            remaining -= 1;
            progressed = true;
        }
        if !progressed {
            let stuck: Vec<&str> = pending
                .iter()
                .enumerate()
                .filter(|(i, _)| resolved[*i].is_none())
                .map(|(_, p)| p.name.as_str())
                .collect();
            return Err(anyhow!(
                "route.servers: ?bootstrap reference cycle among: {}",
                stuck.join(", ")
            ));
        }
    }

    // Re-emit in the original (name-sorted) order. Every slot is `Some` — the
    // loop above only exits when `remaining` reaches zero — so `filter_map`
    // drops nothing.
    let out = pending
        .into_iter()
        .zip(resolved)
        .filter_map(|(p, spec)| spec.map(|s| (p.name, s)))
        .collect();
    Ok(out)
}

/// Does `url` use one of the fixed-answer schemes (`A://`, `AAAA://`, `RCODE://`)
/// rather than a real upstream transport scheme?
fn is_fixed_answer_url(url: &str) -> bool {
    url.split_once("://").is_some_and(|(scheme, _)| {
        matches!(scheme.to_ascii_uppercase().as_str(), "A" | "AAAA" | "RCODE")
    })
}

/// Validate and parse a `route.servers` entry's fixed-answer URL(s) — up to
/// one `A://` + one `AAAA://` (coexisting), or a single `RCODE://` (exclusive
/// with the others). `urls` must all be fixed-answer URLs (checked by the
/// caller via [`is_fixed_answer_url`]).
fn parse_fixed_answer_set(name: &str, urls: &[String]) -> Result<FixedAnswerSet> {
    let scheme_of = |u: &str| {
        u.split_once("://")
            .map(|(scheme, _)| scheme.to_ascii_uppercase())
    };
    let count_scheme = |scheme: &str| {
        urls.iter()
            .filter(|u| scheme_of(u).as_deref() == Some(scheme))
            .count()
    };
    let rcode_count = count_scheme("RCODE");
    let a_count = count_scheme("A");
    let aaaa_count = count_scheme("AAAA");
    if rcode_count > 0 && (a_count + aaaa_count) > 0 {
        return Err(anyhow!(
            "route.servers.{name}: cannot mix RCODE:// with A:// or AAAA://"
        ));
    }
    if rcode_count > 1 {
        return Err(anyhow!(
            "route.servers.{name}: only one RCODE:// is allowed"
        ));
    }
    if rcode_count == 1 {
        let url = &urls[0];
        let rest = url.split_once("://").map(|(_, rest)| rest).unwrap_or("");
        let (rcode_name, ttl) = split_answer_ttl(rest)
            .with_context(|| format!("route.servers.{name}: invalid RCODE \"{url}\""))?;
        let rcode = parse_rcode_name(rcode_name)
            .with_context(|| format!("route.servers.{name}: invalid RCODE \"{url}\""))?;
        return Ok(FixedAnswerSet {
            rcode: Some(rcode),
            rcode_ttl: ttl,
            answers: Vec::new(),
        });
    }
    if a_count > 1 {
        return Err(anyhow!("route.servers.{name}: only one A:// is allowed"));
    }
    if aaaa_count > 1 {
        return Err(anyhow!("route.servers.{name}: only one AAAA:// is allowed"));
    }
    let answers = urls
        .iter()
        .map(|url| parse_fixed_answer(url).with_context(|| format!("route.servers.{name}")))
        .collect::<Result<Vec<_>>>()?;
    Ok(FixedAnswerSet {
        rcode: None,
        rcode_ttl: 0,
        answers,
    })
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

/// Apply `cache.overrides` — a map keyed by `route.servers` name — onto the
/// `cache_policy` of every `RuleSpec` resolving through that server. Per entry:
/// `no-cache: true` disables caching (and cannot be combined with a
/// `min-ttl`/`max-ttl` override); `min-ttl`/`max-ttl` clamp that server's TTLs.
/// Errors on a server name no rule references, `min-ttl > max-ttl`, or a
/// `no-cache`/ttl combination. (The map structure makes duplicate entries
/// impossible, so there's nothing to dedup.)
pub(super) fn apply_cache_field_overrides(
    overrides: std::collections::BTreeMap<String, JsonCacheOverride>,
    rules: &mut [RuleSpec],
) -> Result<()> {
    for (name, ov) in overrides {
        let no_cache = ov.no_cache.unwrap_or(false);
        if no_cache && (ov.min_ttl.is_some() || ov.max_ttl.is_some()) {
            return Err(anyhow!(
                "cache.overrides.{name}: no-cache cannot be combined with a \
                 min-ttl/max-ttl override"
            ));
        }
        if let (Some(min), Some(max)) = (ov.min_ttl, ov.max_ttl) {
            if min > max {
                return Err(anyhow!(
                    "cache.overrides.{name}: min-ttl ({min}) must not exceed max-ttl ({max})"
                ));
            }
        }
        let matching: Vec<&mut RuleSpec> = rules.iter_mut().filter(|r| r.server == name).collect();
        if matching.is_empty() {
            return Err(anyhow!(
                "cache.overrides references server '{name}', which no rule's upstream uses"
            ));
        }
        // An empty override object ({}) is a no-op — nothing to apply.
        if !no_cache && ov.min_ttl.is_none() && ov.max_ttl.is_none() {
            continue;
        }
        for rule in matching {
            rule.cache_policy = Some(RuleCachePolicy {
                skip: no_cache,
                min_ttl: ov.min_ttl,
                max_ttl: ov.max_ttl,
            });
        }
    }
    Ok(())
}

/// Convert a `NameOrNumber` element to a `u16`, resolving a symbolic name
/// through `parse_name`. Shared by `parse_u16_list`/`parse_rcode_list`.
fn name_or_number_to_u64(
    item: NameOrNumber,
    field: &str,
    parse_name: impl Fn(&str) -> Result<u64>,
) -> Result<u64> {
    match item {
        NameOrNumber::Number(n) => u64::try_from(n)
            .map_err(|_| anyhow!("{field} must be a non-negative integer or name")),
        NameOrNumber::Name(s) => parse_name(&s),
    }
}

/// Accept a `route.ruleset` tag name or array of them (used by `answer-ip`),
/// each optionally prefixed with `!` to exclude instead of include — same
/// convention as `rule.matcher`'s `tag:` expressions. Each name is validated
/// and lowercased via `validate_ipcidr_tag_ref`.
pub(super) fn parse_answer_ip_matcher(
    value: Option<OneOrMany<String>>,
    field: &str,
) -> Result<AnswerIpMatcher> {
    let raw: Vec<String> = value.map(OneOrMany::into_vec).unwrap_or_default();

    let mut include = Vec::new();
    let mut exclude = Vec::new();
    for entry in &raw {
        if let Some(name) = entry.trim().strip_prefix('!') {
            exclude.push(validate_ipcidr_tag_ref(name).with_context(|| field.to_string())?);
        } else {
            include.push(validate_ipcidr_tag_ref(entry).with_context(|| field.to_string())?);
        }
    }
    Ok(AnswerIpMatcher { include, exclude })
}

/// Accept a positive integer or array of positive integers (used by
/// `response-type` / `response-qclass`, both 16-bit DNS fields), coercing string
/// elements through `parse_name`.
pub(super) fn parse_u16_list(
    value: Option<OneOrMany<NameOrNumber>>,
    field: &str,
    parse_name: impl Fn(&str) -> Result<u64>,
) -> Result<Vec<u16>> {
    value
        .map(OneOrMany::into_vec)
        .unwrap_or_default()
        .into_iter()
        .map(|item| {
            let n = name_or_number_to_u64(item, field, &parse_name)?;
            u16::try_from(n).map_err(|_| anyhow!("{field} value {n} is out of range (0–65535)"))
        })
        .collect()
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
pub(super) fn parse_rcode_list(value: Option<OneOrMany<NameOrNumber>>) -> Result<Vec<u8>> {
    value
        .map(OneOrMany::into_vec)
        .unwrap_or_default()
        .into_iter()
        .map(|item| {
            // Names route through `parse_rcode_name` (which already range-checks);
            // bare numbers are validated to the 4-bit RCODE range here.
            match item {
                NameOrNumber::Name(s) => parse_rcode_name(&s),
                NameOrNumber::Number(n) => u8::try_from(n)
                    .ok()
                    .filter(|&rcode| rcode <= 15)
                    .ok_or_else(|| anyhow!("response-rcode value {n} is out of range (0–15)")),
            }
        })
        .collect()
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
    let answer_ip = parse_answer_ip_matcher(e.answer_ip, "answer-ip")?;
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

    let action_name = e.action.to_ascii_lowercase();
    if action_name != "forward" && e.forward.is_some() {
        return Err(anyhow!("\"forward\" is only valid with action \"forward\""));
    }
    let action = match action_name.as_str() {
        "accept" => RuleFilterActionSpec::Accept,
        "drop" => RuleFilterActionSpec::Drop,
        "forward" => {
            let target = e.forward.filter(|s| !s.trim().is_empty()).ok_or_else(|| {
                anyhow!("action \"forward\" requires \"forward\": \"<rule name>\"")
            })?;
            RuleFilterActionSpec::Forward(target.trim().to_string())
        }
        other => {
            return Err(anyhow!(
                "unknown filter action \"{other}\" — use accept/drop/forward"
            ))
        }
    };

    let add_ip = e.add_ip.filter(|s| !s.trim().is_empty());
    if add_ip.is_some() {
        if !matches!(action, RuleFilterActionSpec::Accept) {
            return Err(anyhow!("\"add-ip\" is only valid with action \"accept\""));
        }
        // A query only ever gets one record type back, so pinning response-type
        // to exactly one of A/AAAA is what makes a single set name unambiguous
        // (which address family's resolved IPs actually go into it).
        let distinct: HashSet<u16> = response_type.iter().copied().collect();
        if distinct != HashSet::from([1]) && distinct != HashSet::from([28]) {
            return Err(anyhow!(
                "\"add-ip\" requires \"response-type\": \"A\" or \"AAAA\" (exactly one), \
                 not both and not omitted — a query only ever gets one record type back"
            ));
        }
    }

    Ok(RuleFilterSpec {
        answer_ip,
        response_type,
        response_rcode,
        response_qclass,
        action,
        add_ip,
    })
}

pub(super) fn parse_json_rule(idx: usize, jg: JsonRuleEntry) -> Result<RuleSpec> {
    let mut matcher = Vec::new();
    for entry in jg.matcher.iter().flatten() {
        matcher.push(parse_rule_matcher_entry(entry).with_context(|| format!("rule #{idx}"))?);
    }
    let server = jg
        .upstream
        .filter(|s| !s.trim().is_empty())
        .ok_or_else(|| anyhow!("rule #{idx} requires an upstream (a route.servers name)"))?
        .trim()
        .to_string();
    let filters = parse_rule_filters(jg.filter).with_context(|| format!("rule #{idx}"))?;
    Ok(RuleSpec {
        matcher,
        server,
        // Filled in later by `apply_cache_field_overrides`, once the full
        // rule list is known — see `Config::from_json`.
        cache_policy: None,
        filters,
    })
}

pub(super) fn parse_rules(
    json_rules: Vec<JsonRuleEntry>,
    servers: &[(String, ServerSpec)],
) -> Result<Vec<RuleSpec>> {
    let mut rules = Vec::new();
    for (idx, jg) in json_rules.into_iter().enumerate() {
        rules.push(parse_json_rule(idx, jg)?);
    }

    // Every filter "forward" target must reference a real route.servers entry.
    for (idx, g) in rules.iter().enumerate() {
        for f in &g.filters {
            if let RuleFilterActionSpec::Forward(target) = &f.action {
                if !servers.iter().any(|(name, _)| name == target) {
                    return Err(anyhow!(
                        "rule #{idx}: filter forward target \"{target}\": no such route.servers entry"
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

/// Parse the `dashboard` section (query log viewer + HTTP API), deriving its
/// bind addresses from the main `bind` config with the dashboard port substituted.
pub(super) fn parse_dashboard_config(
    dashboard: Option<JsonDashboardSection>,
    bind_addrs: &[BindEndpoint],
    interface: &InterfaceFilter,
) -> Result<DashboardConfig> {
    let Some(ql) = dashboard else {
        return Ok(DashboardConfig {
            enabled: false,
            bind: Vec::new(),
            token: None,
            memory: 0,
            channel: 4096,
            file: None,
        });
    };

    let bind: Vec<(SocketAddr, Option<String>)> = if let Some(port) = ql.port {
        if port == 0 {
            return Err(anyhow!("dashboard.port must be between 1 and 65535"));
        }
        let mut seen = std::collections::HashSet::new();
        let unique_ips: Vec<_> = bind_addrs
            .iter()
            .filter(|ep| seen.insert(ep.addr.ip()))
            .map(|ep| ep.addr.ip())
            .collect();
        match interface {
            InterfaceFilter::Only(ifaces) => unique_ips
                .iter()
                .flat_map(|&ip| {
                    ifaces
                        .iter()
                        .map(move |iface| (SocketAddr::new(ip, port), Some(iface.clone())))
                })
                .collect(),
            _ => unique_ips
                .iter()
                .map(|&ip| (SocketAddr::new(ip, port), None))
                .collect(),
        }
    } else {
        vec![]
    };
    if ql
        .token
        .as_deref()
        .is_some_and(|token| token.trim().is_empty())
    {
        return Err(anyhow!("dashboard.token must not be empty"));
    }
    let channel = ql.channel.unwrap_or(4096);
    if channel == 0 {
        return Err(anyhow!("dashboard.channel must be at least 1"));
    }
    if channel > 1_000_000 {
        return Err(anyhow!("dashboard.channel must not exceed 1000000"));
    }
    let memory = ql.memory.unwrap_or(1000);
    if memory > 10_000_000 {
        return Err(anyhow!("dashboard.memory must not exceed 10000000"));
    }
    let file = if let Some(f) = ql.file {
        let dir = PathBuf::from(f.dir.unwrap_or_else(|| "./querylog".to_string()));
        let max_mb = f.max_mb.unwrap_or(8);
        let max_segments = f.max_segments.unwrap_or(3);
        if max_mb == 0 {
            return Err(anyhow!("dashboard.file.max-mb must be at least 1"));
        }
        if max_segments == 0 {
            return Err(anyhow!("dashboard.file.max-segments must be at least 1"));
        }
        let batch_size = f.batch_size.unwrap_or(256).max(1);
        let flush_interval_ms = f.flush_interval_ms.unwrap_or(500).max(50);
        let retention_days = f.retention_days;
        let compress = f.compress.unwrap_or(true);
        Some(DashboardFileConfig {
            dir,
            max_mb,
            max_segments,
            batch_size,
            flush_interval_ms,
            retention_days,
            compress,
        })
    } else {
        None
    };
    Ok(DashboardConfig {
        enabled: true,
        bind,
        token: ql.token,
        memory,
        channel,
        file,
    })
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
        Some(list) => list
            .into_vec()
            .iter()
            .map(|s| parse_ip_only(s))
            .collect::<Result<_>>()?,
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

/// Parse an `A://` or `AAAA://` value into a `FixedAnswer`, honouring an
/// optional `?ttl=N` (default [`DEFAULT_ANSWER_TTL`]).
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
        other => Err(anyhow!(
            "unknown fixed-answer scheme '{other}' (expected A or AAAA)"
        )),
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

/// A resolved bootstrap target: where to send the one-shot bootstrap UDP query,
/// and the `SO_MARK` to stamp that socket with. Both are inherited from the
/// referenced `route.servers` entry (`?bootstrap=<name>`), so bootstrap traffic
/// follows the same address and policy route as that server's own queries.
#[derive(Clone, Copy)]
pub(super) struct BootstrapTarget {
    pub(super) addr: SocketAddr,
    pub(super) mark: Option<u32>,
}

/// Extract a `?bootstrap=<name>` reference from an upstream URL's query string,
/// if present. Returns the referenced `route.servers` name (untrimmed).
fn bootstrap_ref(url: &str) -> Option<&str> {
    let (_, rest) = url.split_once("://")?;
    let (_, query) = rest.split_once('?')?;
    query.split('&').find_map(|p| p.strip_prefix("bootstrap="))
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
/// queries to the provided `bootstrap` targets.  If no bootstrap is given and the
/// host is not an IP literal, an error is returned — `/etc/resolv.conf` is
/// never consulted (it may point to `127.0.0.1` on OpenWrt).
///
/// Each target carries the fwmark of the `route.servers` entry it came from, so
/// the bootstrap query goes out the referenced resolver's own policy route
/// instead of leaking onto the main table.
pub(super) fn resolve_host(
    host: &str,
    port: u16,
    bootstrap: &[BootstrapTarget],
) -> Result<SocketAddr> {
    let bare = strip_ipv6_brackets(host);
    if let Ok(ip) = bare.parse::<std::net::IpAddr>() {
        return Ok(SocketAddr::new(ip, port));
    }
    if bootstrap.is_empty() {
        return Err(anyhow!(
            "upstream hostname '{host}' requires ?bootstrap=<server> to resolve at startup \
             (e.g. tls://dns.google?bootstrap=domestic-dns, where domestic-dns is a \
             route.servers entry with an IP-literal address); /etc/resolv.conf is never used"
        ));
    }
    let mut last_err: Option<anyhow::Error> = None;
    for target in bootstrap {
        for qtype in [1u16, 28u16] {
            match bootstrap::bootstrap_udp_query(host, qtype, target.addr, target.mark) {
                Ok(ip) => return Ok(SocketAddr::new(ip, port)),
                Err(e) => last_err = Some(e),
            }
        }
    }
    Err(last_err.unwrap_or_else(|| anyhow!("no bootstrap servers configured")))
        .with_context(|| format!("bootstrap DNS: failed to resolve '{host}'"))
}

/// Like `authority_host`/`authority_port`, but resolves hostnames using bootstrap DNS.
pub(super) fn resolve_authority<'a>(
    authority: &'a str,
    default_port: u16,
    bootstrap: &[BootstrapTarget],
) -> Result<(&'a str, SocketAddr)> {
    let host = authority_host(authority)?;
    let port = authority_port(authority, default_port);
    let addr = resolve_host(host, port, bootstrap)?;
    Ok((host, addr))
}

#[cfg(test)]
mod rule_matcher_tests {
    use super::*;

    #[test]
    fn bare_domain_is_a_domain_matcher() {
        let m = parse_rule_matcher_entry("example.com").unwrap();
        assert!(matches!(m, RuleMatcher::Domain(p) if p == "example.com"));
    }

    #[test]
    fn suffix_and_wildcard_patterns_are_accepted() {
        assert!(parse_rule_matcher_entry("+.example.com").is_ok());
        assert!(parse_rule_matcher_entry("*.example.com").is_ok());
    }

    #[test]
    fn invalid_domain_pattern_is_rejected() {
        assert!(parse_rule_matcher_entry("").is_err());
    }

    #[test]
    fn tag_expression_parses_include_and_exclude() {
        let m = parse_rule_matcher_entry("tag:cn,!gfw").unwrap();
        match m {
            RuleMatcher::Tag { include, exclude } => {
                assert_eq!(include, vec!["cn".to_string()]);
                assert_eq!(exclude, vec!["gfw".to_string()]);
            }
            RuleMatcher::Domain(_) => panic!("expected Tag"),
        }
    }

    #[test]
    fn exclude_only_tag_expression_is_accepted() {
        let m = parse_rule_matcher_entry("tag:!gfw").unwrap();
        match m {
            RuleMatcher::Tag { include, exclude } => {
                assert!(include.is_empty());
                assert_eq!(exclude, vec!["gfw".to_string()]);
            }
            RuleMatcher::Domain(_) => panic!("expected Tag"),
        }
    }

    #[test]
    fn empty_tag_expression_is_rejected() {
        assert!(parse_rule_matcher_entry("tag:").is_err());
    }

    #[test]
    fn tag_expression_lowercases_names() {
        let m = parse_rule_matcher_entry("tag:CN").unwrap();
        assert!(matches!(m, RuleMatcher::Tag { include, .. } if include == vec!["cn".to_string()]));
    }
}

#[cfg(test)]
mod cache_field_override_tests {
    use super::*;

    fn rule(server: &str) -> RuleSpec {
        RuleSpec {
            matcher: Vec::new(),
            server: server.to_string(),
            cache_policy: None,
            filters: Vec::new(),
        }
    }

    fn ov(min_ttl: Option<u32>, max_ttl: Option<u32>, no_cache: Option<bool>) -> JsonCacheOverride {
        JsonCacheOverride {
            min_ttl,
            max_ttl,
            no_cache,
        }
    }

    fn overrides(
        pairs: Vec<(&str, JsonCacheOverride)>,
    ) -> std::collections::BTreeMap<String, JsonCacheOverride> {
        pairs.into_iter().map(|(k, v)| (k.to_string(), v)).collect()
    }

    #[test]
    fn no_cache_disables_caching_for_that_rule_only() {
        let mut rules = vec![rule("domestic"), rule("overseas")];
        apply_cache_field_overrides(
            overrides(vec![("overseas", ov(None, None, Some(true)))]),
            &mut rules,
        )
        .unwrap();
        assert!(rules[0].cache_policy.is_none());
        let p = rules[1].cache_policy.as_ref().unwrap();
        assert!(p.skip);
        assert_eq!(p.min_ttl, None);
        assert_eq!(p.max_ttl, None);
    }

    #[test]
    fn min_and_max_ttl_merge_into_one_policy() {
        let mut rules = vec![rule("domestic")];
        apply_cache_field_overrides(
            overrides(vec![("domestic", ov(Some(30), Some(3600), None))]),
            &mut rules,
        )
        .unwrap();
        let p = rules[0].cache_policy.as_ref().unwrap();
        assert!(!p.skip);
        assert_eq!(p.min_ttl, Some(30));
        assert_eq!(p.max_ttl, Some(3600));
    }

    #[test]
    fn rejects_unknown_server_name() {
        let mut rules = vec![rule("domestic")];
        let err = apply_cache_field_overrides(
            overrides(vec![("nosuchserver", ov(None, None, Some(true)))]),
            &mut rules,
        )
        .unwrap_err();
        assert!(err.to_string().contains("which no rule's upstream uses"));
    }

    #[test]
    fn override_applies_to_every_rule_sharing_the_server() {
        let mut rules = vec![rule("domestic"), rule("domestic"), rule("overseas")];
        apply_cache_field_overrides(
            overrides(vec![("domestic", ov(None, None, Some(true)))]),
            &mut rules,
        )
        .unwrap();
        assert!(rules[0].cache_policy.as_ref().unwrap().skip);
        assert!(rules[1].cache_policy.as_ref().unwrap().skip);
        assert!(rules[2].cache_policy.is_none());
    }

    #[test]
    fn rejects_no_cache_combined_with_ttl_override() {
        let mut rules = vec![rule("domestic")];
        let err = apply_cache_field_overrides(
            overrides(vec![("domestic", ov(Some(30), None, Some(true)))]),
            &mut rules,
        )
        .unwrap_err();
        assert!(err.to_string().contains("cannot be combined"));
    }

    #[test]
    fn rejects_min_greater_than_max() {
        let mut rules = vec![rule("domestic")];
        let err = apply_cache_field_overrides(
            overrides(vec![("domestic", ov(Some(3600), Some(30), None))]),
            &mut rules,
        )
        .unwrap_err();
        assert!(err.to_string().contains("must not exceed"));
    }
}

#[cfg(test)]
mod one_or_many_tests {
    use super::*;
    use serde_json::json;

    fn filter(v: serde_json::Value) -> RuleFilterSpec {
        let e: json::JsonRuleFilterEntry = serde_json::from_value(v).unwrap();
        parse_rule_filter_entry(e).unwrap()
    }

    #[test]
    fn scalar_and_one_element_array_are_equivalent() {
        let single = filter(json!({ "response-type": "A", "action": "accept" }));
        let array = filter(json!({ "response-type": ["A"], "action": "accept" }));
        assert_eq!(single.response_type, array.response_type);
        assert_eq!(single.response_type, vec![1u16]);
    }

    #[test]
    fn name_and_number_forms_are_equivalent() {
        let by_name = filter(json!({ "response-type": "AAAA", "action": "drop" }));
        let by_num = filter(json!({ "response-type": 28, "action": "drop" }));
        assert_eq!(by_name.response_type, by_num.response_type);
        assert_eq!(by_num.response_type, vec![28u16]);
    }

}

#[cfg(test)]
mod bootstrap_reference_tests {
    use super::*;
    use serde_json::json;

    fn servers(pairs: &[(&str, serde_json::Value)]) -> std::collections::BTreeMap<String, serde_json::Value> {
        pairs.iter().map(|(k, v)| (k.to_string(), v.clone())).collect()
    }

    #[test]
    fn bootstrap_ref_extracts_server_name() {
        assert_eq!(bootstrap_ref("tls://dns.google?bootstrap=base"), Some("base"));
        assert_eq!(
            bootstrap_ref("tls://dns.google?mark=0x1&bootstrap=base&no-sni"),
            Some("base")
        );
        assert_eq!(bootstrap_ref("tls://1.1.1.1"), None);
        assert_eq!(bootstrap_ref("223.5.5.5"), None);
    }

    #[test]
    fn self_reference_is_rejected() {
        let err = parse_servers(servers(&[("a", json!("tls://dns.google?bootstrap=a"))]))
            .unwrap_err()
            .to_string();
        assert!(err.contains("cannot reference itself"), "{err}");
    }

    #[test]
    fn unknown_reference_is_rejected() {
        let err = parse_servers(servers(&[("a", json!("tls://dns.google?bootstrap=missing"))]))
            .unwrap_err()
            .to_string();
        assert!(err.contains("no such route.servers entry"), "{err}");
    }

    #[test]
    fn fixed_answer_target_is_rejected() {
        let err = parse_servers(servers(&[
            ("blocked", json!("RCODE://NXDOMAIN")),
            ("a", json!("tls://dns.google?bootstrap=blocked")),
        ]))
        .unwrap_err()
        .to_string();
        assert!(err.contains("must reference a real upstream"), "{err}");
    }

    #[test]
    fn reference_cycle_is_rejected() {
        let err = parse_servers(servers(&[
            ("a", json!("tls://a.example?bootstrap=b")),
            ("b", json!("tls://b.example?bootstrap=a")),
        ]))
        .unwrap_err()
        .to_string();
        assert!(err.contains("cycle"), "{err}");
    }

    /// A dependency is resolved before its dependent even when it sorts *after*
    /// it in the (name-ordered) map — proving Phase 2 orders by dependency, not
    /// by name. Both authorities are IP literals, so no bootstrap query fires.
    #[test]
    fn dependency_is_resolved_before_dependent_regardless_of_name_order() {
        let out = parse_servers(servers(&[
            ("a-dependent", json!("udp://8.8.8.8?bootstrap=z-base")),
            ("z-base", json!("223.5.5.5")),
        ]))
        .unwrap();
        assert_eq!(out.len(), 2);
        // Output preserves name order.
        assert_eq!(out[0].0, "a-dependent");
        assert_eq!(out[1].0, "z-base");
    }
}
