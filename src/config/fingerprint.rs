//! Config fingerprinting for cache/verdict-cache persistence validation,
//! split out of `config/mod.rs`.

use super::*;

/// FNV-1a hash of the routing/cache-affecting config fields.
///
/// Written to the cache persistence file so that a stale cache from a previous config
/// is automatically rejected instead of bypassing the new routing or cache policy.
/// Covers: rules (name, tags, upstream identity, filters, cache policy), fallback
/// routing, global cache TTL settings, `route.answer`, and ruleset file paths.
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

    for g in &cfg.rules {
        feed!(g.name.as_bytes());
        sep!();

        // Upstream identity (host/port/proto/ECS mode/mark, ...) affects what a
        // cached entry actually is a cache *of*; feeding the whole Debug-derived
        // struct (rather than hand-picking fields) means a newly added
        // `UpstreamEndpoint` field can't be silently forgotten here the way
        // upstream identity previously was.
        feed!(format!("{:?}", g.upstream).as_bytes());
        sep!();

        let mut include = g.ruleset_include.clone();
        include.sort_unstable();
        for t in &include {
            feed!(t.as_bytes());
            sep!();
        }
        let mut exclude = g.ruleset_exclude.clone();
        exclude.sort_unstable();
        for t in &exclude {
            feed!(b"!");
            feed!(t.as_bytes());
            sep!();
        }

        // Filter order is significant (first-match), so entries are fed as-is.
        for f in &g.filters {
            for ip in &f.answer_ip {
                feed!(ip.as_bytes());
                sep!();
            }
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
                RuleFilterActionSpec::Empty => feed!(b"empty"),
                RuleFilterActionSpec::Drop => feed!(b"drop"),
                RuleFilterActionSpec::Continue => feed!(b"continue"),
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
        FallbackTarget::Rule(name) => {
            feed!(b"rule");
            feed!(name.as_bytes());
        }
        FallbackTarget::Dual {
            primary,
            secondary,
            answer_ip_tags,
        } => {
            feed!(b"none");
            feed!(primary.as_bytes());
            feed!(secondary.as_bytes());
            // Order doesn't affect matching (any-of), so sort for a canonical fingerprint.
            let mut tags = answer_ip_tags.clone();
            tags.sort_unstable();
            for tag in &tags {
                feed!(tag.as_bytes());
                sep!();
            }
        }
    }
    sep!();

    feed!(&cfg.cache_min_ttl.to_le_bytes());
    feed!(&cfg.cache_max_ttl.to_le_bytes());
    sep!();

    // route.answer entries are cached like any other answer; a changed fixed
    // answer must invalidate a persisted cache the same way a changed upstream does.
    feed!(format!("{:?}", cfg.answer_map).as_bytes());
    sep!();

    for spec in &cfg.ruleset_specs {
        feed!(spec.tag.as_bytes());
        feed!(&[spec.format as u8, spec.behavior as u8]);
        feed!(spec.path.to_string_lossy().as_bytes());
        // Include mtime+size so a same-path file replacement invalidates the cache.
        if let Ok(meta) = std::fs::metadata(&spec.path) {
            let mtime = meta
                .modified()
                .ok()
                .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                .map(|d| d.as_secs())
                .unwrap_or(0);
            feed!(&mtime.to_le_bytes());
            feed!(&meta.len().to_le_bytes());
        }
        sep!();
    }

    h.finish()
}
