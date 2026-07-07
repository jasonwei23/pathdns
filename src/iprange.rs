//! Sorted, merged IP-range set for `behavior: ipcidr` rule-sets.
//!
//! Both address families are normalized into one 128-bit space (IPv4 via the
//! standard "IPv4-mapped IPv6" form, `::ffff:a.b.c.d`) so a single sorted
//! `Vec<(u128, u128)>` of merged, non-overlapping inclusive ranges covers both
//! — mirroring mihomo's current `netipx.IPSet`-based implementation (a
//! from/to sorted-range set with binary-search containment), not a prefix
//! trie. mihomo's own `.mrs` ipcidr body is a list of `(from, to)` ranges for
//! exactly this reason: no CIDR decomposition is needed to load it.

use anyhow::{anyhow, Context, Result};
use std::net::IpAddr;

/// A compiled, queryable set of IP ranges. Build via [`IpRangeSetBuilder`].
#[derive(Debug, Clone, Default)]
pub struct IpRangeSet {
    /// Sorted by `from`, non-overlapping, merged (touching/overlapping ranges combined).
    ranges: Vec<(u128, u128)>,
}

impl IpRangeSet {
    /// Returns `true` when `ip` falls within any stored range.
    pub fn contains(&self, ip: IpAddr) -> bool {
        let v = to_u128(ip);
        let idx = self.ranges.partition_point(|&(from, _)| from <= v);
        idx > 0 && v <= self.ranges[idx - 1].1
    }

    /// Number of merged ranges (for startup/dashboard logging).
    pub fn len(&self) -> usize {
        self.ranges.len()
    }
}

/// Accumulates `(from, to)` ranges (in the unified 128-bit space, any order,
/// overlaps allowed) and compiles them into a sorted, merged [`IpRangeSet`].
#[derive(Debug, Default)]
pub struct IpRangeSetBuilder {
    ranges: Vec<(u128, u128)>,
}

impl IpRangeSetBuilder {
    pub fn push_range(&mut self, from: u128, to: u128) {
        if from <= to {
            self.ranges.push((from, to));
        }
    }

    /// Parse and add one CIDR (`a.b.c.d/n`) or bare IP (implicit host route,
    /// `/32` or `/128`) text line.
    pub fn push_cidr_line(&mut self, line: &str) -> Result<()> {
        let (from, to) = parse_cidr_range(line)?;
        self.push_range(from, to);
        Ok(())
    }

    pub fn build(mut self) -> IpRangeSet {
        self.ranges.sort_unstable_by_key(|&(from, _)| from);
        let mut merged: Vec<(u128, u128)> = Vec::with_capacity(self.ranges.len());
        for (from, to) in self.ranges {
            match merged.last_mut() {
                // Merge when overlapping or adjacent (to + 1 == from).
                Some(last) if from <= last.1.saturating_add(1) => {
                    if to > last.1 {
                        last.1 = to;
                    }
                }
                _ => merged.push((from, to)),
            }
        }
        IpRangeSet { ranges: merged }
    }
}

/// Normalize an address into the unified 128-bit comparison space (IPv4 via
/// the standard IPv4-mapped-IPv6 form).
pub fn to_u128(ip: IpAddr) -> u128 {
    match ip {
        IpAddr::V4(v4) => u128::from(v4.to_ipv6_mapped()),
        IpAddr::V6(v6) => u128::from(v6),
    }
}

/// Parse `a.b.c.d/n` (or a bare IP, treated as a full-length host route) into
/// an inclusive `(from, to)` range in the unified 128-bit space. Accepts IPv6
/// forms the same way.
pub fn parse_cidr_range(line: &str) -> Result<(u128, u128)> {
    let (addr, prefix) = match line.split_once('/') {
        Some((a, p)) => (a, Some(p)),
        None => (line, None),
    };
    let ip: IpAddr = addr.parse().context("not an IP address")?;
    let family_bits: u32 = if ip.is_ipv4() { 32 } else { 128 };
    let prefix_len: u32 = match prefix {
        Some(p) => p.parse().context("not a valid prefix length")?,
        None => family_bits,
    };
    if prefix_len > family_bits {
        return Err(anyhow!(
            "prefix length {prefix_len} exceeds {family_bits} for this address family"
        ));
    }

    let base = to_u128(ip);
    let host_bits = family_bits - prefix_len;
    // `host_bits` is at most 32 (v4) or 128 (v6); only the v6 /0 case reaches
    // 128, which would overflow a `<< 128` shift, so it's special-cased.
    let mask: u128 = if host_bits >= 128 {
        0
    } else {
        !0u128 << host_bits
    };
    let from = base & mask;
    let to = base | !mask;
    Ok((from, to))
}
