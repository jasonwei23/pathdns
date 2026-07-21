//! Config fingerprinting for cache/verdict-cache persistence validation,
//! split out of `config/mod.rs`.

use super::*;

/// FNV-1a hash of the routing/cache-affecting config fields.
///
/// Written to the cache persistence file so that a stale cache from a previous config
/// is automatically rejected instead of bypassing the new routing or cache policy.
/// Covers: rules (matcher, upstream identity, filters, cache policy), fallback
/// routing, global cache TTL settings, and ruleset file paths.
pub fn cache_fingerprint(cfg: &Config) -> u64 {
    let mut h = crate::hasher::Fnv1a::new();
    macro_rules! feed {
        ($bytes:expr) => {
            h.write($bytes)
        };
    }
    macro_rules! sep {
        () => {
            h.write_sep()
        };
    }

    // Every `route.servers` entry, in declaration order (stable: parsed from a
    // BTreeMap): name plus the whole Debug-derived `ServerSpec`, so a newly
    // added field can't be silently forgotten here. Fed globally rather than
    // only for servers a rule directly references — `route.final`'s target(s)
    // and `rule.filter`'s `forward` targets also shape what a cached entry is
    // a cache *of*, but only their *names* appear in the sections below, so a
    // spec-content change to such a server (A://1.1.1.1 -> A://2.2.2.2 under
    // the same name) must invalidate the persisted cache through this pass.
    for (name, spec) in &cfg.servers {
        feed!(name.as_bytes());
        sep!();
        feed!(format!("{spec:?}").as_bytes());
        sep!();
    }
    sep!();

    for g in &cfg.rules {
        // The rule -> server binding; the server's own content is covered by
        // the global pass above.
        feed!(g.server.as_bytes());
        sep!();

        // Feeding the whole Debug-derived matcher list (rather than hand-picking
        // fields) means a newly added `RuleMatcher` variant/field can't be
        // silently forgotten here.
        feed!(format!("{:?}", g.matcher).as_bytes());
        sep!();

        // Filter order is significant (first-match), so entries are fed as-is.
        for f in &g.filters {
            // Order doesn't affect matching within each side (any-of), so sort
            // each independently for a canonical fingerprint; include/exclude
            // themselves are fed as distinct groups since they mean opposite things.
            let mut include = f.answer_ip.include.clone();
            include.sort_unstable();
            for tag in &include {
                feed!(tag.as_bytes());
                sep!();
            }
            sep!();
            let mut exclude = f.answer_ip.exclude.clone();
            exclude.sort_unstable();
            for tag in &exclude {
                feed!(tag.as_bytes());
                sep!();
            }
            sep!();
            for rt in &f.response_type {
                feed!(&rt.to_le_bytes());
            }
            sep!();
            for rc in &f.response_rcode {
                feed!(&[*rc]);
            }
            sep!();
            for qc in &f.response_qclass {
                feed!(&qc.to_le_bytes());
            }
            sep!();
            match &f.action {
                RuleFilterActionSpec::Accept => feed!(b"accept"),
                RuleFilterActionSpec::Drop => feed!(b"drop"),
                RuleFilterActionSpec::Forward(name) => {
                    feed!(b"forward");
                    feed!(name.as_bytes());
                }
            }
            sep!();
        }
        sep!();

        if let Some(p) = &g.cache_policy {
            feed!(&[p.skip as u8]);
            feed!(&p.min_ttl.unwrap_or(0).to_le_bytes());
            feed!(&p.max_ttl.unwrap_or(0).to_le_bytes());
        }
        sep!();
    }

    match &cfg.fallback.target {
        FallbackTarget::LastRule => {
            feed!(b"last-rule");
        }
        FallbackTarget::Server(name) => {
            feed!(b"server");
            feed!(name.as_bytes());
        }
        FallbackTarget::Dual {
            primary,
            secondary,
            answer_ip,
        } => {
            feed!(b"none");
            feed!(primary.as_bytes());
            feed!(secondary.as_bytes());
            // Order doesn't affect matching within each side (any-of), so sort each
            // independently; include/exclude are fed as distinct groups.
            let mut include = answer_ip.include.clone();
            include.sort_unstable();
            for tag in &include {
                feed!(tag.as_bytes());
                sep!();
            }
            sep!();
            let mut exclude = answer_ip.exclude.clone();
            exclude.sort_unstable();
            for tag in &exclude {
                feed!(tag.as_bytes());
                sep!();
            }
        }
    }
    sep!();
    // Affects which side of a Dual fallback answers a NODATA reply, i.e. what
    // a cached entry for such a query contains.
    feed!(&[cfg.fallback.noip_as_primary_ip as u8]);
    sep!();

    feed!(&cfg.cache_min_ttl.to_le_bytes());
    feed!(&cfg.cache_max_ttl.to_le_bytes());
    sep!();

    for spec in &cfg.ruleset_specs {
        feed!(spec.tag.as_bytes());
        feed!(&[spec.format as u8, spec.behavior as u8]);
        feed!(spec.path.to_string_lossy().as_bytes());
        // Include mtime+size so a same-path file replacement invalidates the
        // cache. Nanosecond mtime (not seconds): an equal-length replacement
        // landing within the same second — easy for a scripted ruleset update
        // — must still be distinguishable. (Linux filesystems in common use
        // store nanosecond timestamps; a filesystem that truncates them just
        // degrades back toward the old behavior.)
        if let Ok(meta) = std::fs::metadata(&spec.path) {
            let mtime = meta
                .modified()
                .ok()
                .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                .map(|d| d.as_nanos() as u64)
                .unwrap_or(0);
            feed!(&mtime.to_le_bytes());
            feed!(&meta.len().to_le_bytes());
        }
        sep!();
    }

    h.finish()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config_from(json: serde_json::Value) -> Config {
        let json_cfg: crate::config::json::JsonConfig =
            serde_json::from_value(json).expect("valid test config json");
        Config::from_json(json_cfg).expect("test config parses")
    }

    /// `primary`/`secondary` are referenced only by `route.final` (never by a
    /// rule), so their spec content is exactly the coverage gap the global
    /// server pass exists to close.
    fn dual_final_config(primary_addr: &str, noip: bool) -> Config {
        config_from(serde_json::json!({
            "route": {
                "servers": {
                    "primary": primary_addr,
                    "secondary": "127.0.0.2:53",
                    "rule-answer": "A://9.9.9.9",
                },
                "rules": [
                    { "matcher": ["example.com"], "upstream": "rule-answer" }
                ],
                "final": {
                    "primary": "primary",
                    "secondary": "secondary",
                    "answer-ip": "cn-ip",
                    "noip-as-primary-ip": noip,
                }
            }
        }))
    }

    #[test]
    fn identical_configs_share_a_fingerprint() {
        let a = dual_final_config("127.0.0.1:53", false);
        let b = dual_final_config("127.0.0.1:53", false);
        assert_eq!(cache_fingerprint(&a), cache_fingerprint(&b));
    }

    /// A server's spec content must be covered even when the server is only
    /// reachable through `route.final` (a name-only reference): retargeting
    /// the same server name at a different upstream changes what every cached
    /// entry produced through it contains.
    #[test]
    fn changing_a_final_only_server_spec_changes_the_fingerprint() {
        let a = dual_final_config("127.0.0.1:53", false);
        let b = dual_final_config("127.0.0.3:53", false);
        assert_ne!(cache_fingerprint(&a), cache_fingerprint(&b));
    }

    #[test]
    fn noip_as_primary_ip_is_part_of_the_fingerprint() {
        let a = dual_final_config("127.0.0.1:53", false);
        let b = dual_final_config("127.0.0.1:53", true);
        assert_ne!(cache_fingerprint(&a), cache_fingerprint(&b));
    }

    /// End-to-end coverage of the `cache.overrides` wiring in `from_json`:
    /// a valid override parses, and one naming an unreferenced server is
    /// rejected with the expected error.
    #[test]
    fn cache_overrides_wire_through_from_json() {
        let base = |ov: serde_json::Value| {
            serde_json::json!({
                "route": {
                    "servers": { "s": "127.0.0.1:53" },
                    "rules": [{ "matcher": ["example.com"], "upstream": "s" }],
                    "final": "s"
                },
                "cache": { "overrides": ov }
            })
        };
        // Valid override for a referenced server parses.
        let _ = config_from(base(serde_json::json!({ "s": { "min-ttl": 30 } })));

        // An override for a server no rule uses is a config error.
        let json_cfg: crate::config::json::JsonConfig =
            serde_json::from_value(base(serde_json::json!({ "nope": { "no-cache": true } })))
                .expect("valid test config json");
        let err = Config::from_json(json_cfg).unwrap_err().to_string();
        assert!(err.contains("which no rule's upstream uses"), "{err}");
    }
}
