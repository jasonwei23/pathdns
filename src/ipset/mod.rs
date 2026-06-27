//! ipset / nftset management via native Linux netlink (NETLINK_NETFILTER).
//!
//! `IpSetManager` exposes three operations:
//! - `test_response`: tests whether a set of IPs from a DNS reply belong to a configured ipset.
//! - `add_rule_ips`: enqueue IPs for background addition to a named rule's ipset.
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
use config::{SetName, SetPair};
use std::collections::HashSet;
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering as AtomicOrdering};
use std::sync::{mpsc, Mutex};
use worker::{spawn_add_worker, AddJob};

/// Fixed-index warning categories for `warn_once`.  Using an enum-indexed array
/// instead of a `HashSet<String>` prevents the warned-set from growing without bound.
#[derive(Clone, Copy)]
enum WarnKind {
    AddQueueFull = 0,
    AddWorkerExited = 1,
    TestNetlink = 2,
}
const WARN_KIND_COUNT: usize = 3;

#[derive(Debug)]
pub struct IpSetManager {
    test: Option<SetPair>,
    add_rules: Vec<(String, SetPair)>,
    /// NftSet entries (with mask) that carry the `NFT_SET_INTERVAL` kernel flag.
    /// Looked up at startup; controls whether adds are written as prefix ranges.
    interval_nft_sets: HashSet<SetName>,
    /// Per-category once-flag; avoids log spam without unbounded string growth.
    warned: [std::sync::atomic::AtomicBool; WARN_KIND_COUNT],
    /// Count of IPs dropped when the add queue was full.
    dropped_count: AtomicU64,
    /// Shared client used by `test_response`.
    client: Mutex<NetfilterClient>,
    add_tx: Option<mpsc::SyncSender<AddJob>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TestVerdict {
    PrimaryIp,
    SecondaryIp,
    NoIpFound,
    OtherCase,
}

impl IpSetManager {
    pub fn new(cfg: &IpSetConfig) -> Result<Self> {
        let add_rules = cfg
            .add_rules
            .iter()
            .map(|(name, pair)| SetPair::parse(pair).map(|pair| (name.clone(), pair)))
            .collect::<Result<Vec<_>>>()?;
        let add_tx = if !add_rules.is_empty() {
            Some(spawn_add_worker())
        } else {
            None
        };
        let test = cfg.test.as_ref().map(SetPair::parse).transpose()?;

        let mut netfilter_client = NetfilterClient::new()?;

        // At startup, query the NFT_SET_INTERVAL flag for every NftSet entry — both
        // masked (prefix ranges) and unmasked (single hosts). Interval sets require
        // the range representation (two interval endpoints) for *any* element: a
        // bare host written to an interval set is otherwise stored as an open-ended
        // interval start, matching far more addresses than intended. Querying once
        // here avoids a per-IP lookup at runtime.
        let mut interval_nft_sets: HashSet<SetName> = HashSet::new();
        for (_, pair) in &add_rules {
            for set in [pair.v4.as_ref(), pair.v6.as_ref()].into_iter().flatten() {
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
        }

        Ok(Self {
            test,
            add_rules,
            interval_nft_sets,
            warned: std::array::from_fn(|_| std::sync::atomic::AtomicBool::new(false)),
            dropped_count: AtomicU64::new(0),
            client: Mutex::new(netfilter_client),
            add_tx,
        })
    }

    pub fn test_response(&self, ips: &[IpAddr]) -> TestVerdict {
        let Some(test_pair) = &self.test else {
            return TestVerdict::OtherCase;
        };
        if ips.is_empty() {
            return TestVerdict::NoIpFound;
        }

        // Collect only IPs that have a configured set for their address family.
        let testable: Vec<(IpAddr, &SetName)> = ips
            .iter()
            .filter_map(|ip| test_pair.set_for(*ip).map(|set| (*ip, set)))
            .collect();

        if testable.is_empty() {
            return TestVerdict::OtherCase;
        }

        let mut client = match self.client.lock() {
            Ok(g) => g,
            Err(_) => {
                self.warn_once(WarnKind::TestNetlink, anyhow!("netlink client lock poisoned"));
                return TestVerdict::OtherCase;
            }
        };

        // Phase 1: send all test queries up front, collecting sequence numbers.
        // This pipelines N queries into one kernel RTT instead of N.
        let mut pending: Vec<(&SetName, u32)> = Vec::with_capacity(testable.len());
        for (ip, set) in &testable {
            match client.send_test(set, *ip) {
                Ok(seq) => pending.push((set, seq)),
                Err(err) => {
                    if is_io_error(&err) {
                        try_reconnect(&mut client);
                    }
                    self.warn_once(WarnKind::TestNetlink, err);
                    return TestVerdict::OtherCase;
                }
            }
        }

        // Phase 2: receive responses in the same order they were sent.
        // recv_for_seq discards stale messages, so FIFO order is required.
        let mut verdict = TestVerdict::SecondaryIp;
        for (set, seq) in &pending {
            if verdict == TestVerdict::PrimaryIp {
                // Already found a hit; skip remaining recvs.
                // The kernel still sends the responses — they will be
                // silently discarded by the next recv_for_seq call
                // (their seq numbers won't match the next fresh request).
                break;
            }
            match client.recv_test(set, *seq) {
                Ok(true) => verdict = TestVerdict::PrimaryIp,
                Ok(false) => {} // remains SecondaryIp
                Err(err) => {
                    if is_io_error(&err) {
                        try_reconnect(&mut client);
                    }
                    self.warn_once(WarnKind::TestNetlink, err);
                    verdict = TestVerdict::OtherCase;
                    break;
                }
            }
        }

        verdict
    }

    pub fn add_rule_ips(&self, rule: &str, ips: &[IpAddr]) {
        if let Some(pair) = self.rule_pair(rule) {
            self.add_ips(pair, ips);
        }
    }

    /// Total IPs dropped because the add queue was full.
    pub fn dropped_ips(&self) -> u64 {
        self.dropped_count.load(AtomicOrdering::Relaxed)
    }

    fn rule_pair(&self, rule: &str) -> Option<&SetPair> {
        self.add_rules
            .iter()
            .find(|(name, _)| name == rule)
            .map(|(_, pair)| pair)
    }

    fn add_ips(&self, pair: &SetPair, ips: &[IpAddr]) {
        for ip in ips {
            if is_special_use(*ip) {
                continue;
            }
            let Some(set) = pair.set_for(*ip) else {
                continue;
            };
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

fn try_reconnect(client: &mut NetfilterClient) {
    match NetfilterClient::new() {
        Ok(new_client) => *client = new_client,
        Err(err) => {
            crate::log_error!("netlink op=reconnect status=failed error={err:#}");
        }
    }
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
                || v4.is_documentation() // 192.0.2/24, 198.51.100/24, 203.0.113/24  RFC 5737
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
                || v6.is_unicast_link_local() // fe80::/10     RFC 4291
            {
                return true;
            }
            // 2001:db8::/32  documentation  RFC 3849
            let s = v6.segments();
            s[0] == 0x2001 && s[1] == 0x0db8
        }
    }
}

#[cfg(test)]
#[path = "tests/ipset.rs"]
mod tests;
