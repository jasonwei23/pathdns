//! GeoSite domain database: loads `.dat` (protobuf wire format) and `.json` files.
//!
//! ## File formats
//! - `.dat`: V2Ray / Xray binary `GeoSiteList` protobuf; each top-level field is a
//!   `GeoSite` message with a `country_code` string and a repeated `Domain` message.
//!   Domain types: `0=keyword`, `1=regexp`, `2=rootdomain (suffix)`, `3=full`.
//! - `.json`: `{"entries":[{"tag":"...","domains":[...]}]}`. Domain prefix rules:
//!   `full:`, `domain:` (suffix), `keyword:`, `regexp:`, bare = suffix.
//!
//! ## Selective loading
//! Only tags referenced by the config are parsed. Unneeded entries are skipped with
//! minimal work (phase-1 country_code scan, then entry skipped). If a requested tag
//! is absent from every loaded file, `load` returns a startup error naming the tag.
//!
//! ## Per-tag matching (checked in order)
//! 1. **Full**: exact domain match (`HashSet` O(1))
//! 2. **Suffix**: label-aligned suffix match (`HashMap` walk, like `DomainList`)
//! 3. **Keyword**: substring match (linear scan)
//! 4. **Regex**: regular expression match (linear scan)
//!
//! All stored names are normalized to lowercase ASCII via `domain::normalize_domain`.

use crate::domain::SuffixTable;
use anyhow::{anyhow, Context, Result};
use moka::sync::Cache;
use regex::Regex;
use std::collections::{HashMap, HashSet};
use std::path::Path;

// Per-tag matcher storage.

#[derive(Default)]
struct TagMatchers {
    full: HashSet<String>,
    suffix: SuffixTable,
    keyword: Vec<String>,
    regex: Vec<Regex>,
}

impl TagMatchers {
    fn matches(&self, domain: &str) -> bool {
        // 1. Exact full match.
        if self.full.contains(domain) {
            return true;
        }
        // 2. Label-aligned suffix walk via shared SuffixTable.
        if self.suffix.contains_suffix(domain) {
            return true;
        }
        // 3. Keyword substring match.
        for kw in &self.keyword {
            if domain.contains(kw.as_str()) {
                return true;
            }
        }
        // 4. Regex match.
        for re in &self.regex {
            if re.is_match(domain) {
                return true;
            }
        }
        false
    }

    fn total_count(&self) -> usize {
        self.full.len() + self.suffix.len() + self.keyword.len() + self.regex.len()
    }
}

// Public API.

/// Compiled GeoSite database. Holds matchers for a selected subset of tags only.
pub struct GeoSiteDb {
    tags: HashMap<String, TagMatchers>,
    /// L2 result cache: `"tag\0domain" -> bool`. Avoids full matcher walk on repeated
    /// queries. Keyed by the full strings (not a hash) so distinct (tag, domain) pairs
    /// can never alias to the same entry.
    result_cache: Cache<String, bool>,
}

impl GeoSiteDb {
    /// Load `requested_tags` from `files`. Tags are compared case-insensitively.
    ///
    /// Returns an error if any requested tag is absent from all files, or if a file
    /// cannot be parsed. Loading is selective: entries for unrequested tags are skipped
    /// after reading their `country_code` field.
    pub fn load(files: &[std::path::PathBuf], requested_tags: &HashSet<String>) -> Result<Self> {
        let mut db = Self {
            tags: HashMap::new(),
            result_cache: Cache::new(0), // placeholder; resized below after loading
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
        // Validate that every requested tag was found in at least one file.
        for tag in requested_tags {
            if !db.tags.contains_key(tag.as_str()) {
                return Err(anyhow!(
                    "geosite tag '{}' not found in any configured --geosite-file",
                    tag
                ));
            }
        }
        // Build the result cache now that total_count is known.
        let total: usize = db.tags.values().map(|m| m.total_count()).sum();
        let capacity = (2 * total).clamp(10_000, 1_000_000) as u64;
        db.result_cache = Cache::new(capacity);
        Ok(db)
    }

    /// Returns `true` when `domain` matches any rule stored under `tag`.
    ///
    /// `domain` must already be normalized (lowercase, no trailing dot).
    /// `tag` must be lowercase.
    pub fn matches(&self, tag: &str, domain: &str) -> bool {
        let mut cache_key = String::with_capacity(tag.len() + 1 + domain.len());
        cache_key.push_str(tag);
        cache_key.push('\0');
        cache_key.push_str(domain);
        if let Some(cached) = self.result_cache.get(cache_key.as_str()) {
            return cached;
        }
        let result = self.tags.get(tag).is_some_and(|m| m.matches(domain));
        self.result_cache.insert(cache_key, result);
        result
    }

    /// Iterator over loaded (tag, matcher_count) pairs, for startup logging.
    pub fn tag_counts(&self) -> impl Iterator<Item = (&str, usize)> {
        self.tags.iter().map(|(k, v)| (k.as_str(), v.total_count()))
    }
}

// .dat parser.

impl GeoSiteDb {
    fn load_dat(&mut self, path: &Path, requested_tags: &HashSet<String>) -> Result<()> {
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
                    if requested_tags.contains(&code) {
                        // Phase 2: full parse of domain matchers for this entry.
                        let matchers = self.tags.entry(code).or_default();
                        parse_entry_domains(matchers, entry_data)?;
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
fn parse_entry_domains(matchers: &mut TagMatchers, data: &[u8]) -> Result<()> {
    let mut pos = 0usize;
    while pos < data.len() {
        let (field_byte, n) = read_varint(&data[pos..])?;
        pos += n;
        let wire_type = (field_byte & 0x07) as u8;
        match field_byte {
            0x0A => {
                // country_code: skip (already read in phase 1).
                let (len, n) = read_varint(&data[pos..])?;
                pos += n + len as usize;
            }
            0x12 => {
                // Domain message (field 2, length-delimited).
                let (len, n) = read_varint(&data[pos..])?;
                pos += n;
                let end = pos + len as usize;
                if end > data.len() {
                    return Err(anyhow!("domain message extends past entry boundary"));
                }
                parse_domain_message(matchers, &data[pos..end])?;
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
fn parse_domain_message(matchers: &mut TagMatchers, data: &[u8]) -> Result<()> {
    let mut pos = 0usize;
    let mut dtype: u8 = 2; // default: RootDomain/suffix
    let mut value: Option<String> = None;
    while pos < data.len() {
        let (field_byte, n) = read_varint(&data[pos..])?;
        pos += n;
        let wire_type = (field_byte & 0x07) as u8;
        match field_byte {
            0x08 => {
                // type varint (0=keyword, 1=regex, 2=rootdomain/suffix, 3=full)
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
            _ => {
                pos = skip_field(data, pos, wire_type)?;
            }
        }
    }
    let Some(v) = value else { return Ok(()) };
    apply_domain(matchers, dtype, &v)
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
        matchers
            .suffix
            .insert(crate::domain::normalize_domain(rest).unwrap_or_else(|| rest.to_lowercase()));
    } else if let Some(rest) = s.strip_prefix("full:") {
        matchers
            .full
            .insert(crate::domain::normalize_domain(rest).unwrap_or_else(|| rest.to_lowercase()));
    } else if let Some(rest) = s.strip_prefix("keyword:") {
        matchers.keyword.push(rest.to_lowercase());
    } else if let Some(rest) = s.strip_prefix("regexp:") {
        let re =
            Regex::new(rest).with_context(|| format!("invalid regex in geosite JSON: {rest}"))?;
        matchers.regex.push(re);
    } else {
        // Bare entry = suffix match.
        matchers
            .suffix
            .insert(crate::domain::normalize_domain(s).unwrap_or_else(|| s.to_lowercase()));
    }
    Ok(())
}

/// Apply a parsed domain entry to `matchers` by type code.
fn apply_domain(matchers: &mut TagMatchers, dtype: u8, value: &str) -> Result<()> {
    let normalized = crate::domain::normalize_domain(value).unwrap_or_else(|| value.to_lowercase());
    match dtype {
        0 => matchers.keyword.push(normalized),
        1 => {
            let re = Regex::new(value)
                .with_context(|| format!("invalid regex in geosite dat: {value}"))?;
            matchers.regex.push(re);
        }
        2 => {
            matchers.suffix.insert(normalized);
        }
        3 => {
            matchers.full.insert(normalized);
        }
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
    let end = n + len as usize;
    if end > data.len() {
        return Err(anyhow!(
            "string length {len} extends past buffer ({} bytes)",
            data.len()
        ));
    }
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
