//! GeoSite domain database: loads `.dat` (protobuf wire format) and `.json` files.
//!
//! ## File formats
//! - `.dat`: V2Ray / Xray binary `GeoSiteList` protobuf; each top-level field is a
//!   `GeoSite` message with a `country_code` string and a repeated `Domain` message.
//!   Domain types: `0=keyword`, `1=regexp`, `2=rootdomain/subdomain`, `3=full`.
//! - `.json`: `{"entries":[{"tag":"...","domains":[...]}]}`. Domain prefix rules:
//!   `full:`, `domain:` (subdomain), `keyword:`, `regexp:`, bare = subdomain.
//!
//! ## Selective loading
//! Only tags referenced by the config are parsed. Unneeded entries are skipped with
//! minimal work (phase-1 country_code scan, then entry skipped). If a requested tag
//! is absent from every loaded file, `load` returns a startup error naming the tag.
//!
//! ## Per-tag matching
//! Each tag's domains are stored in a shared [`crate::domain::DomainMatcher`]
//! (full → subdomain/root-domain → keyword → regex); only set membership matters here, so the
//! value type is `()`.
//!
//! All stored names are normalized to lowercase ASCII via `domain::normalize_domain`.

use crate::domain::DomainMatcher;
use anyhow::{anyhow, Context, Result};
use regex::Regex;
use std::collections::{HashMap, HashSet};
use std::path::Path;

// Per-tag matcher storage: a domain matcher whose values carry no payload — only
// set membership matters for tag matching.
type TagMatchers = DomainMatcher<()>;

// Public API.

/// Compiled GeoSite database. Holds matchers for a selected subset of tags only.
pub struct GeoSiteDb {
    tags: HashMap<String, TagMatchers>,
}

impl GeoSiteDb {
    /// Load `requested_tags` from `files`. Tags are compared case-insensitively.
    ///
    /// Tag expressions may include an attribute filter: `"steam@cn"` loads only the
    /// domains in the `steam` category that carry the `@cn` attribute in the dat file.
    ///
    /// Returns an error if any requested tag is absent from all files, or if a file
    /// cannot be parsed. Loading is selective: entries for unrequested tags are skipped
    /// after reading their `country_code` field.
    pub fn load(files: &[std::path::PathBuf], requested_tags: &HashSet<String>) -> Result<Self> {
        let mut db = Self {
            tags: HashMap::new(),
        };
        for file in files {
            let ext = file
                .extension()
                .and_then(|e| e.to_str())
                .unwrap_or("")
                .to_lowercase();
            match ext.as_str() {
                "dat" => db
                    .load_dat(file, requested_tags)
                    .with_context(|| format!("failed to load geosite dat: {}", file.display()))?,
                "json" => db
                    .load_json(file, requested_tags)
                    .with_context(|| format!("failed to load geosite json: {}", file.display()))?,
                _ => {
                    return Err(anyhow!(
                        "unsupported geosite file extension '{}' (use .dat or .json): {}",
                        ext,
                        file.display()
                    ))
                }
            }
        }
        // Drop any matchers that ended up with zero domains.  This happens when an
        // attribute-filtered tag (e.g. "steam@cn") was requested but no domain in the
        // dat entry carried that attribute — the or_default() in load_dat would have
        // created an empty entry that would silently match nothing.
        db.tags.retain(|_, m| !m.is_empty());

        // Validate that every requested tag produced at least one domain.
        for tag in requested_tags {
            if !db.tags.contains_key(tag.as_str()) {
                let (base, attr) = split_tag_attr(tag);
                if let Some(attr) = attr {
                    return Err(anyhow!(
                        "geosite tag '{tag}': no domains with '@{attr}' attribute found \
                         in the '{base}' category — the configured dat file may not include \
                         attribute annotations; use v2fly/domain-list-community's geosite.dat \
                         or replace '{tag}' with '{base}' to match all domains in the category"
                    ));
                }
                return Err(anyhow!(
                    "geosite tag '{tag}' not found in any configured geosite file"
                ));
            }
        }
        Ok(db)
    }

    /// Returns `true` when `domain` matches any rule stored under `tag`.
    ///
    /// `domain` must already be normalized (lowercase, no trailing dot).
    /// `tag` must be lowercase.
    pub fn matches(&self, tag: &str, domain: &str) -> bool {
        // No result cache: full/suffix are O(labels) hash probes and keyword/regex are
        // O(patterns). This sits behind the per-qname route cache, so the (tag, domain)
        // reuse a cache would need is rare here — benchmarks showed a cache is pure
        // overhead for full/suffix tags and a net loss for fuzzy tags on cold streams.
        self.tags.get(tag).is_some_and(|m| {
            m.lookup_specific(domain).is_some() || m.lookup_fuzzy(domain).is_some()
        })
    }

    /// Iterator over loaded (tag, matcher_count) pairs, for startup logging.
    pub fn tag_counts(&self) -> impl Iterator<Item = (&str, usize)> {
        self.tags.iter().map(|(k, v)| (k.as_str(), v.len()))
    }
}

/// Split a tag expression into `(base_tag, attribute_filter)`.
///
/// `"cn"` → `("cn", None)`
/// `"steam@cn"` → `("steam", Some("cn"))`
fn split_tag_attr(tag: &str) -> (&str, Option<&str>) {
    match tag.split_once('@') {
        Some((base, attr)) if !attr.is_empty() => (base, Some(attr)),
        _ => (tag, None),
    }
}

// .dat parser.

impl GeoSiteDb {
    fn load_dat(&mut self, path: &Path, requested_tags: &HashSet<String>) -> Result<()> {
        // Build base_tag → [(full_tag_expr, attr_filter)] so each dat entry can
        // populate multiple matchers in one pass.
        //
        // Plain tag "cn"      → base_map["cn"]    = [("cn", None)]
        // Filtered "steam@cn" → base_map["steam"] = [("steam@cn", Some("cn"))]
        //
        // Attribute filtering (TAG@ATTR) follows the v2fly/domain-list-community
        // convention: the dat stores a single GeoSite entry whose country_code is the
        // base tag (e.g. "STEAM"), and individual Domain records that belong to the
        // filtered subset carry a Domain.Attribute field with the matching key (e.g.
        // key="cn"). Only those domain records are added to the TAG@ATTR matcher.
        let mut base_map: HashMap<String, Vec<(String, Option<String>)>> = HashMap::new();
        for tag in requested_tags {
            let (base, attr) = split_tag_attr(tag);
            base_map
                .entry(base.to_string())
                .or_default()
                .push((tag.clone(), attr.map(str::to_string)));
        }

        let data = std::fs::read(path)?;
        let mut pos = 0usize;
        while pos < data.len() {
            let (field_byte, n) = read_varint(&data[pos..])
                .with_context(|| format!("truncated field tag at offset {pos}"))?;
            pos += n;
            let wire_type = (field_byte & 0x07) as u8;
            if wire_type != 2 {
                pos = skip_field(&data, pos, wire_type)?;
                continue;
            }
            let (entry_len, n) = read_varint(&data[pos..])
                .with_context(|| format!("truncated entry length at offset {pos}"))?;
            pos += n;
            let entry_end = pos
                .checked_add(entry_len as usize)
                .filter(|&e| e <= data.len())
                .ok_or_else(|| anyhow!("entry length overflows file at offset {pos}"))?;

            if field_byte == 0x0A {
                // Field 1, length-delimited: GeoSite message.
                let entry_data = &data[pos..entry_end];
                // Phase 1: cheap scan to find country_code, skip if not needed.
                if let Some(code) = find_entry_tag(entry_data)? {
                    if let Some(exprs) = base_map.get(&code) {
                        // Phase 2: full parse for each requested expression that maps to
                        // this base tag. Attribute-filtered expressions get only matching
                        // domains; plain tags (attr_filter = None) get everything.
                        for (tag_expr, attr_filter) in exprs {
                            let matchers = self.tags.entry(tag_expr.clone()).or_default();
                            parse_entry_domains(matchers, entry_data, attr_filter.as_deref())?;
                        }
                    }
                }
            }
            pos = entry_end;
        }
        Ok(())
    }
}

/// Phase-1 scan: read only the `country_code` field from a GeoSite entry.
fn find_entry_tag(data: &[u8]) -> Result<Option<String>> {
    let mut pos = 0usize;
    while pos < data.len() {
        let (field_byte, n) = read_varint(&data[pos..])?;
        pos += n;
        let wire_type = (field_byte & 0x07) as u8;
        if field_byte == 0x0A {
            let (s, _n) = read_len_str(&data[pos..])?;
            return Ok(Some(s.to_lowercase()));
        }
        pos = skip_field(data, pos, wire_type)?;
    }
    Ok(None)
}

/// Phase-2 parse: extract all Domain messages and add matchers.
///
/// When `attr_filter` is `Some(attr)`, only domains that carry that attribute are added.
fn parse_entry_domains(
    matchers: &mut TagMatchers,
    data: &[u8],
    attr_filter: Option<&str>,
) -> Result<()> {
    let mut pos = 0usize;
    while pos < data.len() {
        let (field_byte, n) = read_varint(&data[pos..])?;
        pos += n;
        let wire_type = (field_byte & 0x07) as u8;
        match field_byte {
            0x0A => {
                // country_code: skip (already read in phase 1).
                let (len, n) = read_varint(&data[pos..])?;
                pos = usize::try_from(len)
                    .ok()
                    .and_then(|l| n.checked_add(l))
                    .and_then(|s| pos.checked_add(s))
                    .filter(|&e| e <= data.len())
                    .ok_or_else(|| anyhow!("country_code field overflows geosite buffer"))?;
            }
            0x12 => {
                // Domain message (field 2, length-delimited).
                let (len, n) = read_varint(&data[pos..])?;
                pos = pos
                    .checked_add(n)
                    .ok_or_else(|| anyhow!("domain message header overflows geosite buffer"))?;
                let end = usize::try_from(len)
                    .ok()
                    .and_then(|l| pos.checked_add(l))
                    .filter(|&e| e <= data.len())
                    .ok_or_else(|| anyhow!("domain message extends past entry boundary"))?;
                parse_domain_message(matchers, &data[pos..end], attr_filter)?;
                pos = end;
            }
            _ => {
                pos = skip_field(data, pos, wire_type)?;
            }
        }
    }
    Ok(())
}

/// Parse a single protobuf Domain message and add it to `matchers`.
///
/// When `attr_filter` is `Some(attr)`, the domain is only added if its repeated
/// Attribute list (field 3) contains an entry whose key equals `attr`.
fn parse_domain_message(
    matchers: &mut TagMatchers,
    data: &[u8],
    attr_filter: Option<&str>,
) -> Result<()> {
    let mut pos = 0usize;
    let mut dtype: u8 = 2; // default: RootDomain/subdomain
    let mut value: Option<String> = None;
    // Start as true when no attribute filter is needed; set to true on first match otherwise.
    let mut attr_ok = attr_filter.is_none();
    while pos < data.len() {
        let (field_byte, n) = read_varint(&data[pos..])?;
        pos += n;
        let wire_type = (field_byte & 0x07) as u8;
        match field_byte {
            0x08 => {
                // type varint (0=keyword, 1=regex, 2=rootdomain/subdomain, 3=full)
                let (v, n) = read_varint(&data[pos..])?;
                pos += n;
                dtype = v as u8;
            }
            0x12 => {
                // value string
                let (s, n) = read_len_str(&data[pos..])?;
                pos += n;
                value = Some(s.to_lowercase());
            }
            0x1A => {
                // Attribute message (field 3, length-delimited).
                let (len, n) = read_varint(&data[pos..])?;
                let msg_start = pos
                    .checked_add(n)
                    .ok_or_else(|| anyhow!("attribute header overflows domain message"))?;
                let msg_end = usize::try_from(len)
                    .ok()
                    .and_then(|l| msg_start.checked_add(l))
                    .filter(|&e| e <= data.len())
                    .ok_or_else(|| anyhow!("attribute message extends past domain boundary"))?;
                if !attr_ok {
                    if let Some(attr) = attr_filter {
                        if read_attribute_key(&data[msg_start..msg_end])?.as_deref() == Some(attr) {
                            attr_ok = true;
                        }
                    }
                }
                pos = msg_end;
            }
            _ => {
                pos = skip_field(data, pos, wire_type)?;
            }
        }
    }
    let Some(v) = value else { return Ok(()) };
    if !attr_ok {
        return Ok(());
    }
    apply_domain(matchers, dtype, &v)
}

/// Extract the key field from a protobuf Attribute message.
/// Returns the lowercased key string, or `None` if field 1 was absent.
fn read_attribute_key(data: &[u8]) -> Result<Option<String>> {
    let mut pos = 0usize;
    while pos < data.len() {
        let (field_byte, n) = read_varint(&data[pos..])?;
        pos += n;
        let wire_type = (field_byte & 0x07) as u8;
        if field_byte == 0x0A {
            // field 1, string: the attribute key
            let (s, n) = read_len_str(&data[pos..])?;
            pos += n;
            let _ = pos; // suppress unused-assignment warning
            return Ok(Some(s.to_lowercase()));
        }
        pos = skip_field(data, pos, wire_type)?;
    }
    Ok(None)
}

// .json parser.

impl GeoSiteDb {
    fn load_json(&mut self, path: &Path, requested_tags: &HashSet<String>) -> Result<()> {
        let text = std::fs::read_to_string(path)?;
        let list: serde_json::Value = serde_json::from_str(&text).context("invalid JSON")?;
        let entries = list
            .get("entries")
            .and_then(|v| v.as_array())
            .ok_or_else(|| anyhow!("missing 'entries' array in geosite JSON"))?;
        for entry in entries {
            let tag = entry
                .get("tag")
                .and_then(|v| v.as_str())
                .ok_or_else(|| anyhow!("entry missing 'tag' string"))?
                .to_lowercase();
            if !requested_tags.contains(&tag) {
                continue;
            }
            let domains = match entry.get("domains").and_then(|v| v.as_array()) {
                Some(d) => d,
                None => continue,
            };
            let matchers = self.tags.entry(tag).or_default();
            for domain_val in domains {
                if let Some(s) = domain_val.as_str() {
                    parse_json_domain(matchers, s)
                        .with_context(|| format!("invalid domain entry: {s}"))?;
                }
            }
        }
        Ok(())
    }
}

fn parse_json_domain(matchers: &mut TagMatchers, s: &str) -> Result<()> {
    if let Some(rest) = s.strip_prefix("domain:") {
        matchers.insert_suffix(
            crate::domain::normalize_domain(rest).unwrap_or_else(|| rest.to_lowercase()),
            (),
        );
    } else if let Some(rest) = s.strip_prefix("full:") {
        matchers.insert_full(
            crate::domain::normalize_domain(rest).unwrap_or_else(|| rest.to_lowercase()),
            (),
        );
    } else if let Some(rest) = s.strip_prefix("keyword:") {
        matchers.insert_keyword(rest.to_lowercase(), ());
    } else if let Some(rest) = s.strip_prefix("regexp:") {
        let re =
            Regex::new(rest).with_context(|| format!("invalid regex in geosite JSON: {rest}"))?;
        matchers.insert_regex(re, ());
    } else {
        // Bare entry = subdomain match.
        matchers.insert_suffix(
            crate::domain::normalize_domain(s).unwrap_or_else(|| s.to_lowercase()),
            (),
        );
    }
    Ok(())
}

/// Apply a parsed domain entry to `matchers` by type code.
fn apply_domain(matchers: &mut TagMatchers, dtype: u8, value: &str) -> Result<()> {
    let normalized = crate::domain::normalize_domain(value).unwrap_or_else(|| value.to_lowercase());
    match dtype {
        0 => matchers.insert_keyword(normalized, ()),
        1 => {
            let re = Regex::new(value)
                .with_context(|| format!("invalid regex in geosite dat: {value}"))?;
            matchers.insert_regex(re, ());
        }
        2 => matchers.insert_suffix(normalized, ()),
        3 => matchers.insert_full(normalized, ()),
        _ => {}
    }
    Ok(())
}

// Protobuf wire helpers.

fn read_varint(data: &[u8]) -> Result<(u64, usize)> {
    let mut result = 0u64;
    let mut shift = 0u32;
    for (i, &b) in data.iter().enumerate() {
        if shift >= 64 {
            return Err(anyhow!("varint overflow in geosite dat"));
        }
        // 10th byte (shift=63): only bit 63 is available; payload > 1 overflows u64.
        if shift == 63 && b & 0x7F > 1 {
            return Err(anyhow!("varint overflow in geosite dat"));
        }
        result |= ((b & 0x7F) as u64) << shift;
        if b & 0x80 == 0 {
            return Ok((result, i + 1));
        }
        shift += 7;
    }
    Err(anyhow!("truncated varint in geosite dat"))
}

fn read_len_str(data: &[u8]) -> Result<(&str, usize)> {
    let (len, n) = read_varint(data)?;
    let end = usize::try_from(len)
        .ok()
        .and_then(|l| n.checked_add(l))
        .filter(|&e| e <= data.len())
        .ok_or_else(|| {
            anyhow!(
                "string length {len} extends past buffer ({} bytes)",
                data.len()
            )
        })?;
    let s = std::str::from_utf8(&data[n..end]).context("non-UTF-8 string in geosite")?;
    Ok((s, end))
}

fn skip_field(data: &[u8], pos: usize, wire_type: u8) -> Result<usize> {
    match wire_type {
        0 => {
            let mut p = pos;
            loop {
                if p >= data.len() {
                    return Err(anyhow!("truncated varint while skipping geosite field"));
                }
                let done = data[p] & 0x80 == 0;
                p += 1;
                if done {
                    return Ok(p);
                }
            }
        }
        1 => pos
            .checked_add(8)
            .filter(|&e| e <= data.len())
            .ok_or_else(|| anyhow!("64-bit field overflows geosite buffer")),
        2 => {
            let (len, n) = read_varint(&data[pos..])?;
            pos.checked_add(n)
                .and_then(|p| p.checked_add(len as usize))
                .filter(|&e| e <= data.len())
                .ok_or_else(|| anyhow!("length-delimited field overflows geosite buffer"))
        }
        5 => pos
            .checked_add(4)
            .filter(|&e| e <= data.len())
            .ok_or_else(|| anyhow!("32-bit field overflows geosite buffer")),
        t => Err(anyhow!("unknown protobuf wire type {t} in geosite dat")),
    }
}

// Tests.

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn split_tag_attr_no_at() {
        assert_eq!(split_tag_attr("cn"), ("cn", None));
    }

    #[test]
    fn split_tag_attr_with_attr() {
        assert_eq!(split_tag_attr("steam@cn"), ("steam", Some("cn")));
    }

    #[test]
    fn split_tag_attr_empty_attr_treated_as_no_filter() {
        // "steam@" — empty attr means split_once returns ("steam", ""), not Some("")
        assert_eq!(split_tag_attr("steam@"), ("steam@", None));
    }

    fn make_domain_bytes(suffix_value: &str, attr_key: Option<&str>) -> Vec<u8> {
        let mut bytes = vec![
            0x08, 0x02, // type = 2 (RootDomain/suffix)
        ];
        // value string
        let v = suffix_value.as_bytes();
        bytes.push(0x12);
        bytes.push(v.len() as u8);
        bytes.extend_from_slice(v);
        // optional attribute
        if let Some(key) = attr_key {
            let k = key.as_bytes();
            // Attribute { key: "cn" (field 1), bool_value: true (field 2) }
            let mut attr_msg = vec![0x0A, k.len() as u8];
            attr_msg.extend_from_slice(k);
            attr_msg.extend_from_slice(&[0x10, 0x01]); // bool_value = true
            bytes.push(0x1A); // field 3, wire type 2
            bytes.push(attr_msg.len() as u8);
            bytes.extend(attr_msg);
        }
        bytes
    }

    #[test]
    fn attribute_filter_includes_only_matching_domains() {
        let with_cn = make_domain_bytes("google.com", Some("cn"));
        let without_attr = make_domain_bytes("bing.com", None);

        // No filter: both included.
        let mut m = TagMatchers::default();
        parse_domain_message(&mut m, &with_cn, None).unwrap();
        parse_domain_message(&mut m, &without_attr, None).unwrap();
        assert!(m.lookup_specific("google.com").is_some());
        assert!(m.lookup_specific("bing.com").is_some());

        // @cn filter: only google.com (which has @cn) included.
        let mut m_cn = TagMatchers::default();
        parse_domain_message(&mut m_cn, &with_cn, Some("cn")).unwrap();
        parse_domain_message(&mut m_cn, &without_attr, Some("cn")).unwrap();
        assert!(m_cn.lookup_specific("google.com").is_some());
        assert!(m_cn.lookup_specific("bing.com").is_none());
    }

    #[test]
    fn attribute_filter_suffix_match_works() {
        let with_cn = make_domain_bytes("steam.com", Some("cn"));
        let mut m = TagMatchers::default();
        parse_domain_message(&mut m, &with_cn, Some("cn")).unwrap();
        // RootDomain = subdomain match: the domain itself and subdomains match.
        assert!(m.lookup_specific("store.steam.com").is_some());
        assert!(m.lookup_specific("steam.com").is_some());
        assert!(m.lookup_specific("notsteam.com").is_none());
    }

    // Run with: cargo test --release geosite_cache_bench -- --ignored --nocapture
    #[test]
    #[ignore]
    fn geosite_cache_bench() {
        use moka::sync::Cache;

        // Pure-suffix tag (realistic: a geosite category is tens of thousands of rootdomains).
        let mut suffix_tag: DomainMatcher<()> = DomainMatcher::default();
        for i in 0..50_000u32 {
            suffix_tag.insert_suffix(format!("host{i}.site{}.com", i % 1009), ());
        }
        // Fuzzy tag: keyword + regex matchers (the only genuinely O(patterns) case).
        let mut fuzzy_tag: DomainMatcher<()> = DomainMatcher::default();
        for i in 0..24u32 {
            fuzzy_tag.insert_keyword(format!("kw{i}"), ());
        }
        for i in 0..8u32 {
            fuzzy_tag.insert_regex(Regex::new(&format!(r"track{i}[0-9]+\.example")).unwrap(), ());
        }

        // Strategy bodies (replicate each caching policy over the public matcher API).
        let no_cache = |m: &DomainMatcher<()>, d: &str| -> bool {
            m.lookup_specific(d).is_some() || m.lookup_fuzzy(d).is_some()
        };
        let cache_all = |m: &DomainMatcher<()>, c: &Cache<String, bool>, d: &str| -> bool {
            let mut key = String::with_capacity(3 + d.len());
            key.push_str("t\0");
            key.push_str(d);
            if let Some(v) = c.get(key.as_str()) {
                return v;
            }
            let r = m.lookup_specific(d).is_some() || m.lookup_fuzzy(d).is_some();
            c.insert(key, r);
            r
        };
        // Rejected strategy: cache the fuzzy result (only ever applied to a fuzzy tag here).
        let fuzzy_only = |m: &DomainMatcher<()>, c: &Cache<String, bool>, d: &str| -> bool {
            if m.lookup_specific(d).is_some() {
                return true;
            }
            let mut key = String::with_capacity(3 + d.len());
            key.push_str("t\0");
            key.push_str(d);
            if let Some(v) = c.get(key.as_str()) {
                return v;
            }
            let r = m.lookup_fuzzy(d).is_some();
            c.insert(key, r);
            r
        };

        fn bench(label: &str, iters: usize, distinct: &[String], f: &mut dyn FnMut(&str) -> bool) {
            for d in distinct.iter().take(distinct.len().min(1000)) {
                std::hint::black_box(f(d));
            }
            let t = std::time::Instant::now();
            let mut acc = 0usize;
            for k in 0..iters {
                let d = &distinct[k % distinct.len()];
                if std::hint::black_box(f(d.as_str())) {
                    acc += 1;
                }
            }
            let ns = t.elapsed().as_nanos() as f64 / iters as f64;
            eprintln!("  {label:30} {ns:8.1} ns/op  (truthy={acc})");
        }

        let iters = 2_000_000usize;
        // Repeated stream (high hit rate on any cache) — proxies traffic with a warm route cache absent.
        let repeated: Vec<String> = (0..5_000u32)
            .map(|i| format!("www.host{i}.site{}.com", i % 1009))
            .collect();
        // Cold stream: every query is a distinct, never-before-seen name (cache never hits).
        let cold: Vec<String> = (0..iters as u32)
            .map(|i| format!("x{i}.cold{}.test", i % 7919))
            .collect();

        eprintln!("\n== pure-suffix tag (50k entries) ==");
        eprintln!("-- repeated stream (5k distinct) --");
        bench("no-cache (==current)", iters, &repeated, &mut |d| no_cache(&suffix_tag, d));
        {
            let c = Cache::new(100_000);
            bench("cache-all (old)", iters, &repeated, &mut |d| cache_all(&suffix_tag, &c, d));
        }

        eprintln!("\n== fuzzy tag (24 keyword + 8 regex) ==");
        eprintln!("-- repeated stream (5k distinct, high repeat) --");
        bench("no-cache (delete)", iters, &repeated, &mut |d| no_cache(&fuzzy_tag, d));
        {
            let c = Cache::new(100_000);
            bench("fuzzy-cached (current)", iters, &repeated, &mut |d| fuzzy_only(&fuzzy_tag, &c, d));
        }
        eprintln!("-- cold stream (all-unique, cache never hits) --");
        bench("no-cache (delete)", iters, &cold, &mut |d| no_cache(&fuzzy_tag, d));
        {
            let c = Cache::new(100_000);
            bench("fuzzy-cached (current)", iters, &cold, &mut |d| fuzzy_only(&fuzzy_tag, &c, d));
        }
        eprintln!();
    }
}
