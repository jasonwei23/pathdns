//! Background add worker.
//!
//! A bounded channel delivers `AddJob` entries from the main thread.
//! The worker drains all available jobs from the channel in one go, sorts
//! them by (set, ip), deduplicates adjacent entries, then processes each
//! contiguous run for the same set:
//!
//! - **ipset**: fire-and-forget send (no NLM_F_ACK, no recv round-trip).
//! - **nftset**: all sets are sent first, then all acks are received in one
//!   pass — collapsing N serial RTTs into approximately one kernel RTT.

use super::client::NetfilterClient;
use super::config::SetName;
use std::collections::HashSet;
use std::net::IpAddr;
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

pub(super) const ADD_QUEUE_SIZE: usize = 16384;

#[derive(Debug, Clone)]
pub(super) struct AddJob {
    pub(super) set: SetName,
    pub(super) ip: IpAddr,
    /// Whether the target nftset carries the `NFT_SET_INTERVAL` flag.
    /// Always `false` for ipset entries.
    pub(super) interval: bool,
}

pub(super) fn spawn_add_worker() -> mpsc::SyncSender<AddJob> {
    let (tx, rx) = mpsc::sync_channel(ADD_QUEUE_SIZE);
    let _ = thread::Builder::new()
        .name("ipset-add".into())
        .spawn(move || run_add_worker(rx));
    tx
}

fn run_add_worker(rx: mpsc::Receiver<AddJob>) {
    let mut warned: HashSet<String> = HashSet::new();
    let mut batch: Vec<AddJob> = Vec::new();
    // Reusable buffer for nftset chunks; cleared each iteration.
    let mut nftset_chunks: Vec<(SetName, Vec<IpAddr>, bool)> = Vec::new();

    // Outer loop: reconnect on socket errors rather than exiting permanently.
    'reconnect: loop {
        let mut client = loop {
            match NetfilterClient::new() {
                Ok(c) => break c,
                Err(err) => {
                    crate::log_error!(
                        "netlink op=add_worker status=connect_failed error={err:#}"
                    );
                    thread::sleep(Duration::from_secs(1));
                }
            }
        };

        loop {
            let job = match rx.recv() {
                Ok(job) => job,
                Err(_) => return, // sender dropped; exit permanently
            };
            batch.push(job);
            // Drain all currently available jobs before processing — larger batches
            // mean fewer sort/dedup passes and better pipelining on the netlink side.
            while let Ok(job) = rx.try_recv() {
                batch.push(job);
            }

            batch.sort_by(|a, b| a.set.cmp(&b.set).then_with(|| a.ip.cmp(&b.ip)));
            dedup_jobs(&mut batch);

            let mut first_err: Option<String> = None;
            let mut need_reconnect = false;

            // Walk contiguous runs of the same set.
            // ipset runs are sent immediately (fire-and-forget).
            // nftset runs are accumulated for a single pipelined send+recv pass.
            let mut pos = 0usize;
            while pos < batch.len() {
                let set = batch[pos].set.clone();
                let interval = batch[pos].interval;
                let chunk_start = pos;
                pos += 1;
                while pos < batch.len() && batch[pos].set == set {
                    pos += 1;
                }
                let ips: Vec<IpAddr> = batch[chunk_start..pos].iter().map(|j| j.ip).collect();

                match &set {
                    SetName::IpSet { .. } => {
                        if let Err(err) = client.add_many(&set, &ips, interval) {
                            if is_io_error(&err) {
                                need_reconnect = true;
                            }
                            first_err.get_or_insert_with(|| format!("{err:#}"));
                        }
                    }
                    SetName::NftSet { .. } => {
                        nftset_chunks.push((set, ips, interval));
                    }
                }

                if need_reconnect {
                    break;
                }
            }

            // Send all nftset messages in one go, then drain all acks — one kernel
            // RTT for the entire batch regardless of how many distinct sets are present.
            if !need_reconnect {
                if let Err(err) = client.add_nftset_pipelined(&nftset_chunks) {
                    if is_io_error(&err) {
                        need_reconnect = true;
                    }
                    first_err.get_or_insert_with(|| format!("{err:#}"));
                }
            }

            if let Some(key) = first_err {
                if warned.insert(key.clone()) {
                    crate::log_error!("netlink op=add_batch status=failed error={key}");
                }
            }
            batch.clear();
            nftset_chunks.clear();

            if need_reconnect {
                // Brief pause before reconnecting so we don't spin on a broken kernel.
                thread::sleep(Duration::from_millis(100));
                continue 'reconnect;
            }
        }
    }
}

fn is_io_error(err: &anyhow::Error) -> bool {
    err.chain().any(|e| e.is::<std::io::Error>())
}

/// Remove adjacent duplicate (set, ip) pairs.
///
/// Callers must sort by (set, ip) before calling so that all duplicates
/// are adjacent.
pub(super) fn dedup_jobs(jobs: &mut Vec<AddJob>) {
    jobs.dedup_by(|a, b| a.set == b.set && a.ip == b.ip);
}
