//! ipset / nftset management via native Linux netlink (NETLINK_NETFILTER).
//!
//! `IpSetManager` exposes one operation: `add_filter_ips`, which enqueues IPs
//! for background addition to a filter entry's ipset (identified by its
//! `(rule_idx, filter_idx)` position — rules and filter entries have no name
//! of their own). `route.final`'s primary/secondary decision is a separate,
//! in-memory ipcidr-behavior `route.ruleset` check — see `crate::iprange` and
//! `RuleSetDb::matches_ip`.
//!
//! IP additions are batched: a background thread drains a bounded channel, sorts jobs by
//! (set, ip), deduplicates adjacent duplicates, and sends them in a single multi-element
//! netlink message per set.

mod client;
mod codec;
mod config;
mod socket;
mod worker;

use crate::config::IpSetConfig;
use anyhow::{anyhow, Result};
use client::NetfilterClient;
use config::SetName;
use std::collections::HashSet;
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering as AtomicOrdering};
use std::sync::{mpsc, Arc};
use worker::{spawn_add_worker, AddJob};

/// Fixed-index warning categories for `warn_once`.  Using an enum-indexed array
/// instead of a `HashSet<String>` prevents the warned-set from growing without bound.
#[derive(Clone, Copy)]
enum WarnKind {
    AddQueueFull = 0,
    AddWorkerExited = 1,
}
const WARN_KIND_COUNT: usize = 2;

#[derive(Debug)]
pub struct IpSetManager {
    /// Keyed by `(rule_idx, filter_idx)` — see `crate::config::IpSetConfig`.
    add_rules: Vec<(usize, usize, SetName)>,
    /// NftSet entries (with mask) that carry the `NFT_SET_INTERVAL` kernel flag.
    /// Looked up at startup; controls whether adds are written as prefix ranges.
    interval_nft_sets: HashSet<SetName>,
    /// Per-category once-flag; avoids log spam without unbounded string growth.
    warned: [std::sync::atomic::AtomicBool; WARN_KIND_COUNT],
    /// Count of IPs dropped: either the add queue was full at enqueue time, or the
    /// background worker's own retry backlog overflowed (see `worker::run_add_worker`).
    dropped_count: Arc<AtomicU64>,
    add_tx: Option<mpsc::SyncSender<AddJob>>,
}

impl IpSetManager {
    pub fn new(cfg: &IpSetConfig) -> Result<Self> {
        let add_rules = cfg
            .add_rules
            .iter()
            .map(|(rule_idx, filter_idx, raw, is_v6)| {
                let max_prefix = if *is_v6 { 128 } else { 32 };
                SetName::parse(raw, max_prefix).map(|set| (*rule_idx, *filter_idx, set))
            })
            .collect::<Result<Vec<_>>>()?;
        let dropped_count = Arc::new(AtomicU64::new(0));
        let add_tx = if !add_rules.is_empty() {
            Some(spawn_add_worker(dropped_count.clone()))
        } else {
            None
        };

        // Local, startup-only client used solely to query NFT_SET_INTERVAL
        // flags below; not retained.
        let mut netfilter_client = NetfilterClient::new()?;

        // At startup, query the NFT_SET_INTERVAL flag for every NftSet entry — both
        // masked (prefix ranges) and unmasked (single hosts). Interval sets require
        // the range representation (two interval endpoints) for *any* element: a
        // bare host written to an interval set is otherwise stored as an open-ended
        // interval start, matching far more addresses than intended. Querying once
        // here avoids a per-IP lookup at runtime.
        let mut interval_nft_sets: HashSet<SetName> = HashSet::new();
        for (_, _, set) in &add_rules {
            if let SetName::NftSet {
                family,
                table,
                set: set_name,
                ..
            } = set
            {
                match netfilter_client.query_nft_interval_flag(*family, table, set_name) {
                    Ok(true) => {
                        interval_nft_sets.insert(set.clone());
                    }
                    Ok(false) => {}
                    Err(e) => {
                        crate::log_error!(
                            "netlink op=query_interval status=failed \
                             set={table}@{set_name} error={e:#}"
                        );
                    }
                }
            }
        }

        Ok(Self {
            add_rules,
            interval_nft_sets,
            warned: std::array::from_fn(|_| std::sync::atomic::AtomicBool::new(false)),
            dropped_count,
            add_tx,
        })
    }

    pub fn add_filter_ips(&self, rule_idx: usize, filter_idx: usize, ips: &[IpAddr]) {
        if let Some(set) = self.filter_set(rule_idx, filter_idx) {
            self.add_ips(set, ips);
        }
    }

    /// Total IPs dropped: add queue was full at enqueue time, or the worker's
    /// retry backlog overflowed while netlink kept failing.
    pub fn dropped_ips(&self) -> u64 {
        self.dropped_count.load(AtomicOrdering::Relaxed)
    }

    fn filter_set(&self, rule_idx: usize, filter_idx: usize) -> Option<&SetName> {
        self.add_rules
            .iter()
            .find(|(r, f, _)| *r == rule_idx && *f == filter_idx)
            .map(|(_, _, set)| set)
    }

    fn add_ips(&self, set: &SetName, ips: &[IpAddr]) {
        for ip in ips {
            if is_special_use(*ip) {
                continue;
            }
            let interval = self.interval_nft_sets.contains(set);
            let Some(add_tx) = &self.add_tx else {
                continue;
            };
            match add_tx.try_send(AddJob {
                set: set.clone(),
                ip: *ip,
                interval,
            }) {
                Ok(()) => {}
                Err(mpsc::TrySendError::Full(_)) => {
                    let dropped = self.dropped_count.fetch_add(1, AtomicOrdering::Relaxed) + 1;
                    self.warn_once(
                        WarnKind::AddQueueFull,
                        anyhow!("ipset/nftset add queue is full; {dropped} IPs dropped so far"),
                    );
                }
                Err(mpsc::TrySendError::Disconnected(_)) => {
                    self.warn_once(
                        WarnKind::AddWorkerExited,
                        anyhow!("ipset/nftset add worker exited; IPs will not be added"),
                    );
                }
            }
        }
    }

    fn warn_once(&self, kind: WarnKind, err: anyhow::Error) {
        let slot = &self.warned[kind as usize];
        if slot
            .compare_exchange(
                false,
                true,
                std::sync::atomic::Ordering::Relaxed,
                std::sync::atomic::Ordering::Relaxed,
            )
            .is_ok()
        {
            crate::log_error!("netlink status=failed error={err:#}");
        }
    }
}

pub(super) fn is_io_error(err: &anyhow::Error) -> bool {
    err.chain().any(|e| e.is::<std::io::Error>())
}

/// Returns true for addresses that should never be added to a routing set:
/// loopback, unspecified, private (RFC 1918), link-local, multicast,
/// broadcast, CGNAT (RFC 6598), and documentation ranges (RFC 5737 / 3849).
fn is_special_use(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            if v4.is_loopback()        // 127.0.0.0/8     RFC 1122
                || v4.is_private()     // 10/8, 172.16/12, 192.168/16  RFC 1918
                || v4.is_link_local()  // 169.254.0.0/16  RFC 3927
                || v4.is_broadcast()   // 255.255.255.255  RFC 919
                || v4.is_multicast()   // 224.0.0.0/4     RFC 3171
                || v4.is_documentation()
            // 192.0.2/24, 198.51.100/24, 203.0.113/24  RFC 5737
            {
                return true;
            }
            let o = v4.octets();
            o[0] == 0                              // 0.0.0.0/8  "This Network"  RFC 1122
                || (o[0] == 100 && o[1] & 0xc0 == 0x40) // 100.64.0.0/10  CGNAT  RFC 6598
        }
        IpAddr::V6(v6) => {
            if v6.is_loopback()             // ::1             RFC 4291
                || v6.is_unspecified()      // ::              RFC 4291
                || v6.is_multicast()        // ff00::/8        RFC 4291
                || v6.is_unique_local()     // fc00::/7        RFC 4193
                || v6.is_unicast_link_local()
            // fe80::/10     RFC 4291
            {
                return true;
            }
            // 2001:db8::/32  documentation  RFC 3849
            let s = v6.segments();
            s[0] == 0x2001 && s[1] == 0x0db8
        }
    }
}
