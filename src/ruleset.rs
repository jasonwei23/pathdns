//! Ruleset domain/IP-CIDR database: mihomo-compatible `route.ruleset` loading.
//!
//! ## Formats
//! - `format: "mrs"`: mihomo's zstd-compressed rule-set binary. See [`crate::mrs`].
//! - `format: "text"`: mihomo's plain-text rule-set convention — one pattern per
//!   line, blank lines and `#`/`//` full-line comments skipped. This is the
//!   format used by e.g. `MetaCubeX/meta-rules-dat`'s `*.list` files.
//!
//! ## Behaviors
//! - `behavior: "domain"`: matched against the query name. Pattern conventions
//!   (shared with the decoded form of `.mrs` domain sets — see [`crate::mrs`]):
//!   - bare `example.com` — exact match only
//!   - `+.example.com`    — the domain itself and all subdomains
//!   - `*.example.com`    — single-label wildcard (see
//!     [`crate::domain::wildcard_domain_regex`])
//!   - `.example.com`     — subdomains only, without the apex (rare; treated
//!     the same as `+.example.com` — mihomo's own text dump can't tell the two
//!     apart either once round-tripped through a `.mrs` file)
//! - `behavior: "ipcidr"`: matched against a resolved IP address (used by
//!   `route.final`'s `answer-ip` field and `rule.filter`'s `answer-ip` match
//!   criterion — see [`crate::iprange`] for the sorted-range matching
//!   structure). Referencing an ipcidr tag from `rule.tag` / `route.answer`'s
//!   `tag:` is a config error, and vice versa: a domain tag referenced from an
//!   `answer-ip` field is also an error.
//!
//! ## Tags
//! Each `route.ruleset` entry carries its own explicit `tag` (config validation
//! rejects duplicates — [`RuleSetSpec`]s here are assumed already unique).
//! Unlike geosite `.dat`/`.json`, a rule-set file carries no tag of its own.
//! Selective loading: an entry's file is never opened unless its tag is
//! referenced by a rule/answer/fallback tag expression.

use crate::domain::DomainMatcher;
use crate::iprange::{IpRangeSet, IpRangeSetBuilder};
use anyhow::{anyhow, Context, Result};
use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::path::PathBuf;

// Per-tag matcher storage: a domain matcher whose values carry no payload — only
// set membership matters for tag matching.
type TagMatchers = DomainMatcher<()>;

/// Ruleset file format (`route.ruleset[].format`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuleSetFormat {
    Text,
    Mrs,
}

/// Ruleset matching behavior (`route.ruleset[].behavior`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuleSetBehavior {
    Domain,
    IpCidr,
}

/// One `route.ruleset` entry: an explicit tag bound to a file, with its
/// declared format and behavior.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuleSetSpec {
    pub tag: String,
    pub format: RuleSetFormat,
    pub behavior: RuleSetBehavior,
    pub path: PathBuf,
}

enum TagEntry {
    Domain(TagMatchers),
    IpCidr(IpRangeSet),
}

/// Compiled ruleset database. Holds matchers for a selected subset of tags only.
pub struct RuleSetDb {
    tags: HashMap<String, TagEntry>,
}

impl RuleSetDb {
    /// Load `domain_tags` and `ipcidr_tags` from `specs`.
    ///
    /// Selective loading: a spec's file is never opened unless its tag is in
    /// `domain_tags` or `ipcidr_tags`. Returns an error if a requested tag is
    /// absent, declared with the wrong behavior for the set it was requested
    /// from, or its file fails to parse/validate.
    pub fn load(
        specs: &[RuleSetSpec],
        domain_tags: &HashSet<String>,
        ipcidr_tags: &HashSet<String>,
    ) -> Result<Self> {
        let mut db = Self {
            tags: HashMap::new(),
        };
        for spec in specs {
            // Load whenever the tag is requested from *either* set, regardless of
            // whether the spec's own declared behavior matches — a mismatch must
            // still load the entry so the validation loops below can report the
            // specific "wrong behavior" error instead of a misleading "not found".
            if !domain_tags.contains(&spec.tag) && !ipcidr_tags.contains(&spec.tag) {
                continue;
            }
            let entry = match spec.behavior {
                RuleSetBehavior::Domain => {
                    let patterns = read_domain_patterns(spec).with_context(|| {
                        format!(
                            "failed to load ruleset '{}' ({})",
                            spec.tag,
                            spec.path.display()
                        )
                    })?;
                    let mut matchers = TagMatchers::default();
                    for p in &patterns {
                        if !apply_domain_pattern(&mut matchers, p) {
                            // Not fatal (unlike an ipcidr-behavior ruleset's invalid CIDR
                            // lines, which do hard-error): printed rather than silenced so
                            // an operator's ruleset typo is actually visible instead of
                            // silently shrinking the rule count with zero diagnostic.
                            crate::log_error!(
                                "ruleset tag={} status=pattern_skipped reason=unparseable pattern={p}",
                                spec.tag
                            );
                        }
                    }
                    TagEntry::Domain(matchers)
                }
                RuleSetBehavior::IpCidr => {
                    let set = build_ipcidr_set(spec).with_context(|| {
                        format!(
                            "failed to load ruleset '{}' ({})",
                            spec.tag,
                            spec.path.display()
                        )
                    })?;
                    TagEntry::IpCidr(set)
                }
            };
            db.tags.insert(spec.tag.clone(), entry);
        }

        for tag in domain_tags {
            match db.tags.get(tag.as_str()) {
                None => {
                    return Err(anyhow!(
                        "ruleset tag '{tag}' not found in any configured route.ruleset entry"
                    ))
                }
                Some(TagEntry::IpCidr(_)) => {
                    return Err(anyhow!(
                        "ruleset tag '{tag}' has behavior=ipcidr, which cannot be used for \
                         domain-based tag matching (rule.tag / route.answer's tag:)"
                    ))
                }
                Some(TagEntry::Domain(_)) => {}
            }
        }
        for tag in ipcidr_tags {
            match db.tags.get(tag.as_str()) {
                None => {
                    return Err(anyhow!(
                        "ruleset tag '{tag}' not found in any configured route.ruleset entry"
                    ))
                }
                Some(TagEntry::Domain(_)) => {
                    return Err(anyhow!(
                        "ruleset tag '{tag}' has behavior=domain, which cannot be used for \
                         route.final's IP-based fallback test"
                    ))
                }
                Some(TagEntry::IpCidr(_)) => {}
            }
        }
        Ok(db)
    }

    /// Returns `true` when `domain` matches any rule stored under `tag`.
    ///
    /// `domain` must already be normalized (lowercase, no trailing dot).
    /// `tag` must be lowercase. Always `false` for an ipcidr-behavior tag —
    /// config validation in `load` prevents such a tag from ever being
    /// reachable from a rule/answer expression in the first place.
    pub fn matches(&self, tag: &str, domain: &str) -> bool {
        match self.tags.get(tag) {
            Some(TagEntry::Domain(m)) => {
                m.lookup_specific(domain).is_some() || m.lookup_fuzzy(domain).is_some()
            }
            _ => false,
        }
    }

    /// Returns `true` when `ip` falls within any range stored under `tag`.
    ///
    /// `tag` must be lowercase. Always `false` for a domain-behavior tag —
    /// config validation in `load` prevents such a tag from ever being
    /// reachable from an `answer-ip` field in the first place.
    pub fn matches_ip(&self, tag: &str, ip: IpAddr) -> bool {
        match self.tags.get(tag) {
            Some(TagEntry::IpCidr(set)) => set.contains(ip),
            _ => false,
        }
    }

    /// Returns `true` when any of `ips` falls within `tag`'s range — the
    /// `route.final`/`rule.filter` `answer-ip` primary/secondary decision,
    /// testing every IP in a resolved answer at once instead of one at a time.
    pub fn matches_any_ip(&self, tag: &str, ips: &[IpAddr]) -> bool {
        ips.iter().any(|ip| self.matches_ip(tag, *ip))
    }

    /// Iterator over loaded (tag, entry_count) pairs, for startup logging.
    pub fn tag_counts(&self) -> impl Iterator<Item = (&str, usize)> {
        self.tags.iter().map(|(k, v)| {
            let n = match v {
                TagEntry::Domain(m) => m.len(),
                TagEntry::IpCidr(set) => set.len(),
            };
            (k.as_str(), n)
        })
    }
}

// Domain-behavior loading.

/// Read a domain-behavior ruleset file's patterns, in mihomo's inline text form.
fn read_domain_patterns(spec: &RuleSetSpec) -> Result<Vec<String>> {
    let raw = std::fs::read(&spec.path)?;
    match spec.format {
        RuleSetFormat::Mrs => crate::mrs::decode_domain_patterns(&raw),
        RuleSetFormat::Text => {
            let text = String::from_utf8(raw).context("ruleset text file is not valid UTF-8")?;
            Ok(parse_text_lines(&text))
        }
    }
}

/// Split a mihomo-style plain-text rule-set into its pattern lines: trimmed,
/// blank lines and `#`/`//` full-line comments skipped.
fn parse_text_lines(text: &str) -> Vec<String> {
    text.lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#') && !line.starts_with("//"))
        .map(str::to_string)
        .collect()
}

/// Apply one decoded/text domain pattern (see module docs for the text
/// conventions) to `matchers`. Malformed entries are skipped rather than
/// failing the whole file; returns `false` in that case so the caller can
/// warn (an ipcidr-behavior ruleset instead hard-errors on a bad line, so a
/// silent domain-side skip would otherwise be an easy-to-miss inconsistency
/// for an operator who mistyped a line).
fn apply_domain_pattern(matchers: &mut TagMatchers, pattern: &str) -> bool {
    use crate::domain::PatternKind;
    match crate::domain::classify_pattern(pattern) {
        PatternKind::Suffix(n) => {
            matchers.insert_suffix(n, ());
            true
        }
        PatternKind::Full(n) => {
            matchers.insert_full(n, ());
            true
        }
        PatternKind::Wildcard(re) => {
            matchers.insert_regex(re, ());
            true
        }
        PatternKind::Invalid => false,
    }
}

// IP-CIDR loading.

/// Build a queryable IP-range set from an ipcidr-behavior ruleset file.
fn build_ipcidr_set(spec: &RuleSetSpec) -> Result<IpRangeSet> {
    let mut builder = IpRangeSetBuilder::default();
    match spec.format {
        RuleSetFormat::Mrs => {
            let raw = std::fs::read(&spec.path)?;
            for (from, to) in crate::mrs::decode_ipcidr_ranges(&raw)? {
                builder.push_range(from, to);
            }
        }
        RuleSetFormat::Text => {
            let raw = std::fs::read(&spec.path)?;
            let text = String::from_utf8(raw).context("ruleset text file is not valid UTF-8")?;
            for (lineno, line) in text.lines().enumerate() {
                let line = line.trim();
                if line.is_empty() || line.starts_with('#') || line.starts_with("//") {
                    continue;
                }
                builder
                    .push_cidr_line(line)
                    .with_context(|| format!("line {}: invalid CIDR '{}'", lineno + 1, line))?;
            }
        }
    }
    Ok(builder.build())
}
