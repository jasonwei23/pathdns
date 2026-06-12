//! ipset / nftset management via native Linux netlink (NETLINK_NETFILTER).
//!
//! `IpSetManager` exposes three operations:
//! - `test_response`: tests whether a set of IPs from a DNS reply belong to a configured ipset.
//! - `add_group_ips`: enqueue IPs for background addition to a named group's ipset.
//!
//! IP additions are batched: a background thread drains a bounded channel, sorts jobs by
//! (set, ip), deduplicates adjacent duplicates, and sends them in a single multi-element
//! netlink message per set.

#[cfg(target_os = "linux")]
mod client;
#[cfg(target_os = "linux")]
mod codec;
#[cfg(target_os = "linux")]
mod config;
#[cfg(target_os = "linux")]
mod socket;
#[cfg(target_os = "linux")]
mod worker;

#[cfg(target_os = "linux")]
use crate::config::IpSetConfig;
#[cfg(target_os = "linux")]
use anyhow::{anyhow, Result};
#[cfg(target_os = "linux")]
use client::NetfilterClient;
#[cfg(target_os = "linux")]
use config::{SetName, SetPair};
#[cfg(target_os = "linux")]
use std::collections::HashSet;
#[cfg(target_os = "linux")]
use std::net::IpAddr;
#[cfg(target_os = "linux")]
use std::sync::{mpsc, Mutex};
#[cfg(target_os = "linux")]
use worker::{spawn_add_worker, AddJob};

#[cfg(target_os = "linux")]
#[derive(Debug)]
pub struct IpSetManager {
    test: Option<SetPair>,
    add_groups: Vec<(String, SetPair)>,
    blacklist: bool,
    /// NftSet entries (with mask) that carry the `NFT_SET_INTERVAL` kernel flag.
    /// Looked up at startup; controls whether adds are written as prefix ranges.
    interval_nft_sets: HashSet<SetName>,
    warned: Mutex<HashSet<String>>,
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

#[cfg(target_os = "linux")]
impl IpSetManager {
    pub fn new(cfg: &IpSetConfig) -> Result<Self> {
        let add_groups = cfg
            .add_groups
            .iter()
            .map(|(name, pair)| SetPair::parse(pair).map(|pair| (name.clone(), pair)))
            .collect::<Result<Vec<_>>>()?;
        let add_tx = if !add_groups.is_empty() {
            Some(spawn_add_worker())
        } else {
            None
        };
        let test = cfg.test.as_ref().map(SetPair::parse).transpose()?;

        let mut netfilter_client = NetfilterClient::new()?;

        // At startup, query the NFT_SET_INTERVAL flag for every masked NftSet entry.
        // This avoids a per-IP query at runtime.
        let mut interval_nft_sets: HashSet<SetName> = HashSet::new();
        for (_, pair) in &add_groups {
            for set in [pair.v4.as_ref(), pair.v6.as_ref()].into_iter().flatten() {
                if let SetName::NftSet { family, table, set: set_name, mask: Some(_) } = set {
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
            add_groups,
            blacklist: cfg.blacklist,
            interval_nft_sets,
            warned: Mutex::new(HashSet::new()),
            client: Mutex::new(netfilter_client),
            add_tx,
        })
    }

    pub fn test_response(&self, ips: &[IpAddr]) -> TestVerdict {
        if self.test.is_none() {
            return TestVerdict::OtherCase;
        }
        if ips.is_empty() {
            return TestVerdict::NoIpFound;
        }

        let mut verdict = TestVerdict::SecondaryIp;
        let mut any_testable = false;
        for ip in ips {
            match self.test_ip(*ip) {
                Ok(Some(true)) => {
                    verdict = TestVerdict::PrimaryIp;
                    break;
                }
                Ok(Some(false)) => {
                    any_testable = true;
                }
                Ok(None) => {
                    // No set configured for this address family; skip.
                }
                Err(err) => {
                    self.warn_once("test", err);
                    verdict = TestVerdict::OtherCase;
                    break;
                }
            }
        }
        // If no IP could be tested against a configured set, we have no basis to classify.
        if !any_testable && verdict == TestVerdict::SecondaryIp {
            verdict = TestVerdict::OtherCase;
        }

        verdict
    }

    pub fn add_group_ips(&self, group: &str, ips: &[IpAddr]) {
        if let Some(pair) = self.group_pair(group) {
            self.add_ips(pair, ips);
        }
    }

    fn test_ip(&self, ip: IpAddr) -> Result<Option<bool>> {
        let Some(test) = &self.test else {
            return Ok(None);
        };
        let Some(set) = test.set_for(ip) else {
            return Ok(None);
        };
        self.client
            .lock()
            .map_err(|_| anyhow!("netlink client lock poisoned"))?
            .test(set, ip)
            .map(Some)
    }

    fn group_pair(&self, group: &str) -> Option<&SetPair> {
        self.add_groups
            .iter()
            .find(|(name, _)| name == group)
            .map(|(_, pair)| pair)
    }

    fn add_ips(&self, pair: &SetPair, ips: &[IpAddr]) {
        for ip in ips {
            if self.blacklist && is_blacklisted(*ip) {
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
                Err(e) => {
                    let msg = if matches!(e, mpsc::TrySendError::Full(_)) {
                        "ipset/nftset add queue is full; falling back to sync add"
                    } else {
                        "ipset/nftset add worker exited; falling back to sync add"
                    };
                    self.warn_once("add", anyhow!("{msg}"));
                    match self.client.lock() {
                        Ok(mut c) => {
                            if let Err(err) = c.add_many(set, &[*ip], interval) {
                                self.warn_once("add", err);
                            }
                        }
                        Err(_) => {
                            self.warn_once("add", anyhow!("netlink client lock poisoned"));
                        }
                    }
                }
            }
        }
    }

    fn warn_once(&self, op: &str, err: anyhow::Error) {
        let key = format!("{op}: {err:#}");
        let Ok(mut warned) = self.warned.lock() else {
            crate::log_error!("netlink op={} status=failed error={err:#}", op);
            return;
        };
        if warned.insert(key) {
            crate::log_error!("netlink op={} status=failed error={err:#}", op);
        }
    }
}

#[cfg(not(target_os = "linux"))]
pub struct IpSetManager;

#[cfg(not(target_os = "linux"))]
impl IpSetManager {
    pub fn new(_cfg: &crate::config::IpSetConfig) -> anyhow::Result<Self> {
        anyhow::bail!("ipset/nftset is only supported on Linux")
    }
    pub fn summary(&self) -> String {
        String::new()
    }
    pub fn test_response(&self, _ips: &[std::net::IpAddr]) -> TestVerdict {
        unreachable!()
    }
    pub fn add_group_ips(&self, _group: &str, _ips: &[std::net::IpAddr]) {}
}

#[cfg(target_os = "linux")]
fn is_blacklisted(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => {
            let octets = ip.octets();
            octets[0] == 127 || octets[0] == 0
        }
        IpAddr::V6(ip) => ip.is_unspecified() || ip.is_loopback(),
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::config::SetName;
    use super::worker::{dedup_jobs, AddJob};
    use std::net::{IpAddr, Ipv4Addr};

    fn make_jobs(pairs: &[(&str, IpAddr)]) -> Vec<AddJob> {
        pairs
            .iter()
            .map(|(set, ip)| AddJob {
                set: SetName::IpSet {
                    name: set.to_string(),
                    mask: None,
                },
                ip: *ip,
                interval: false,
            })
            .collect()
    }

    #[test]
    fn dedup_jobs_removes_adjacent_duplicates_after_sort() {
        let ip = IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4));
        let mut jobs = make_jobs(&[("s", ip), ("s", ip), ("s", ip)]);
        jobs.sort_by(|a, b| a.set.cmp(&b.set).then_with(|| a.ip.cmp(&b.ip)));
        dedup_jobs(&mut jobs);
        assert_eq!(jobs.len(), 1);
    }

    #[test]
    fn dedup_jobs_keeps_different_ips() {
        let ip1 = IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4));
        let ip2 = IpAddr::V4(Ipv4Addr::new(5, 6, 7, 8));
        let mut jobs = make_jobs(&[("s", ip1), ("s", ip2)]);
        jobs.sort_by(|a, b| a.set.cmp(&b.set).then_with(|| a.ip.cmp(&b.ip)));
        dedup_jobs(&mut jobs);
        assert_eq!(jobs.len(), 2);
    }
}
