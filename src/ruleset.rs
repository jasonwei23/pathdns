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
//!   structure). Referencing an ipcidr tag from `rule.matcher`'s `tag:` is a
//!   config error, and vice versa: a domain tag referenced from an
//!   `answer-ip` field is also an error.
//!
//! ## Tags
//! Each `route.ruleset` entry carries its own explicit `tag` (config validation
//! rejects duplicates — [`RuleSetSpec`]s here are assumed already unique).
//! Unlike geosite `.dat`/`.json`, a rule-set file carries no tag of its own.
//! Selective loading: an entry's file is never opened unless its tag is
//! referenced by a rule/fallback tag expression.

use crate::domain::DomainMatcher;
use crate::iprange::{IpRangeSet, IpRangeSetBuilder};
use anyhow::{anyhow, Context, Result};
use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::Arc;

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
///
/// Entries are `Arc`-wrapped so a partial reload (`load`'s `reuse` parameter)
/// can share an unchanged tag's already-parsed matcher with the previous
/// `RuleSetDb` instance instead of re-parsing its file.
pub struct RuleSetDb {
    tags: HashMap<String, Arc<TagEntry>>,
}

impl RuleSetDb {
    /// Load `domain_tags` and `ipcidr_tags` from `specs`.
    ///
    /// Selective loading: a spec's file is never opened unless its tag is in
    /// `domain_tags` or `ipcidr_tags`. Returns an error if a requested tag is
    /// absent, declared with the wrong behavior for the set it was requested
    /// from, or its file fails to parse/validate.
    ///
    /// `reuse`, when set, is `(previous_db, changed_paths)`: a spec whose
    /// tag was already loaded in `previous_db` and whose normalized path
    /// (`crate::server::normalized_watch_path` — the same form the
    /// file-watcher derives from its inotify events) is *not* in
    /// `changed_paths` is copied from there (an `Arc` clone, no file I/O or
    /// re-parsing) instead of being read again. Used by a ruleset-only
    /// hot-reload triggered by a single file's change, so touching one
    /// geosite category doesn't force every other referenced ruleset file to
    /// be re-decompressed and re-indexed too. Full paths, not bare file
    /// names: two directories may each hold a same-named ruleset file, and
    /// name-only matching would needlessly re-parse both when either changes.
    pub fn load(
        specs: &[RuleSetSpec],
        domain_tags: &HashSet<String>,
        ipcidr_tags: &HashSet<String>,
        reuse: Option<(&RuleSetDb, &HashSet<PathBuf>)>,
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
            if let Some((prev, changed_paths)) = reuse {
                let file_changed =
                    changed_paths.contains(&crate::server::normalized_watch_path(&spec.path));
                if !file_changed {
                    if let Some(entry) = prev.tags.get(&spec.tag) {
                        db.tags.insert(spec.tag.clone(), Arc::clone(entry));
                        continue;
                    }
                }
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
            db.tags.insert(spec.tag.clone(), Arc::new(entry));
        }

        for tag in domain_tags {
            match db.tags.get(tag.as_str()).map(Arc::as_ref) {
                None => {
                    return Err(anyhow!(
                        "ruleset tag '{tag}' not found in any configured route.ruleset entry"
                    ))
                }
                Some(TagEntry::IpCidr(_)) => {
                    return Err(anyhow!(
                        "ruleset tag '{tag}' has behavior=ipcidr, which cannot be used for \
                         domain-based tag matching (rule.matcher's tag:)"
                    ))
                }
                Some(TagEntry::Domain(_)) => {}
            }
        }
        for tag in ipcidr_tags {
            match db.tags.get(tag.as_str()).map(Arc::as_ref) {
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
    /// reachable from a `rule.matcher` tag expression in the first place.
    pub fn matches(&self, tag: &str, domain: &str) -> bool {
        match self.tags.get(tag).map(Arc::as_ref) {
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
        match self.tags.get(tag).map(Arc::as_ref) {
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

    /// Evaluates a full `answer-ip` matcher (include + optional `!` exclude
    /// tags) against a resolved answer's IPs. Matches when any IP falls in an
    /// include tag's range (or there are no include tags) AND no IP falls in
    /// any exclude tag's range — `!tag` alone means "none of the answer IPs
    /// are in this range", the strict complement of the plain (include-only)
    /// case, so exactly one of `tag`/`!tag` is ever true for a given answer.
    pub fn matches_answer_ip(&self, m: &crate::config::AnswerIpMatcher, ips: &[IpAddr]) -> bool {
        let include_ok =
            m.include.is_empty() || m.include.iter().any(|tag| self.matches_any_ip(tag, ips));
        let exclude_ok = !m.exclude.iter().any(|tag| self.matches_any_ip(tag, ips));
        include_ok && exclude_ok
    }

    /// Iterator over loaded (tag, entry_count) pairs, for startup logging.
    pub fn tag_counts(&self) -> impl Iterator<Item = (&str, usize)> {
        self.tags.iter().map(|(k, v)| {
            let n = match v.as_ref() {
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

#[cfg(test)]
mod tests {
    use super::*;

    /// A `load` with `reuse` set and a tag's file name absent from
    /// `changed_filenames` must not touch that file at all — proven here by
    /// deleting the file after the first load and reloading with `reuse`:
    /// if `load` tried to re-read it, this would error (or, if it silently
    /// tolerated the missing file some other way, lose the tag entirely)
    /// instead of matching against the original content.
    #[test]
    fn reuse_skips_unchanged_file_entirely() {
        let dir = std::env::temp_dir().join(format!(
            "pathdns-ruleset-test-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let cn_path = dir.join("cn.list");
        let gfw_path = dir.join("gfw.list");
        std::fs::write(&cn_path, "+.bilibili.com\n").unwrap();
        std::fs::write(&gfw_path, "+.blocked.com\n").unwrap();

        let specs = vec![
            RuleSetSpec {
                tag: "cn".to_string(),
                format: RuleSetFormat::Text,
                behavior: RuleSetBehavior::Domain,
                path: cn_path.clone(),
            },
            RuleSetSpec {
                tag: "gfw".to_string(),
                format: RuleSetFormat::Text,
                behavior: RuleSetBehavior::Domain,
                path: gfw_path.clone(),
            },
        ];
        let tags: HashSet<String> = ["cn", "gfw"].iter().map(|s| s.to_string()).collect();

        let first = RuleSetDb::load(&specs, &tags, &HashSet::new(), None).unwrap();
        assert!(first.matches("cn", "a.bilibili.com"));
        assert!(first.matches("gfw", "a.blocked.com"));

        // Change gfw.list's content on disk and delete cn.list entirely —
        // if `load` re-read cn.list despite it being absent from
        // `changed_filenames`, this would surface as an error (file gone).
        std::fs::write(&gfw_path, "+.blocked.com\n+.newly-blocked.test\n").unwrap();
        std::fs::remove_file(&cn_path).unwrap();

        let mut changed = HashSet::new();
        changed.insert(crate::server::normalized_watch_path(&gfw_path));
        let second = RuleSetDb::load(&specs, &tags, &HashSet::new(), Some((&first, &changed)))
            .expect("reused cn tag must not trigger a re-read of the now-missing file");

        // gfw.list actually changed and was reloaded: new pattern visible.
        assert!(second.matches("gfw", "a.blocked.com"));
        assert!(second.matches("gfw", "newly-blocked.test"));
        // cn.list was reused from `first` even though its file is now gone.
        assert!(second.matches("cn", "a.bilibili.com"));

        std::fs::remove_file(&gfw_path).ok();
        std::fs::remove_dir(&dir).ok();
    }

    /// Same setup, but `reuse` is `None` (as at startup / a full config
    /// reload): every referenced tag must be read fresh regardless.
    #[test]
    fn no_reuse_reads_every_file_fresh() {
        let dir = std::env::temp_dir().join(format!(
            "pathdns-ruleset-test-noreuse-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let cn_path = dir.join("cn.list");
        std::fs::write(&cn_path, "+.bilibili.com\n").unwrap();

        let specs = vec![RuleSetSpec {
            tag: "cn".to_string(),
            format: RuleSetFormat::Text,
            behavior: RuleSetBehavior::Domain,
            path: cn_path.clone(),
        }];
        let tags: HashSet<String> = ["cn"].iter().map(|s| s.to_string()).collect();

        let first = RuleSetDb::load(&specs, &tags, &HashSet::new(), None).unwrap();
        assert!(first.matches("cn", "a.bilibili.com"));
        assert!(!first.matches("cn", "a.other.test"));

        std::fs::write(&cn_path, "+.other.test\n").unwrap();
        let second = RuleSetDb::load(&specs, &tags, &HashSet::new(), None).unwrap();
        assert!(second.matches("cn", "a.other.test"));
        assert!(!second.matches("cn", "a.bilibili.com"));

        std::fs::remove_file(&cn_path).ok();
        std::fs::remove_dir(&dir).ok();
    }
}
