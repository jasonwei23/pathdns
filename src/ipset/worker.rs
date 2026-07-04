//! Background add worker.
//!
//! A bounded channel delivers `AddJob` entries from the main thread.
//! The worker drains all available jobs from the channel in one go, sorts
//! them by (set, ip), deduplicates adjacent entries, then sends one add per
//! distinct set.  Both ipset and nftset adds are fire-and-forget: the kernel
//! commits the add inside the `send()` syscall, so there is no recv round-trip.

use super::client::NetfilterClient;
use super::config::SetName;
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{mpsc, Arc};
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

/// `dropped_count` is shared with `IpSetManager::dropped_ips()`: unlike the bounded
/// channel (full → drop at enqueue time, already counted there), the worker's own
/// retry backlog (`retained`, below) has no channel to lean on, so its overflow is
/// counted through the same counter here.
pub(super) fn spawn_add_worker(dropped_count: Arc<AtomicU64>) -> mpsc::SyncSender<AddJob> {
    let (tx, rx) = mpsc::sync_channel(ADD_QUEUE_SIZE);
    let _ = thread::Builder::new()
        .name("ipset-add".into())
        .spawn(move || run_add_worker(rx, dropped_count));
    tx
}

fn run_add_worker(rx: mpsc::Receiver<AddJob>, dropped_count: Arc<AtomicU64>) {
    let mut batch: Vec<AddJob> = Vec::new();

    // Outer loop: reconnect on socket errors rather than exiting permanently.
    'reconnect: loop {
        let mut client = loop {
            match NetfilterClient::new() {
                Ok(c) => break c,
                Err(err) => {
                    crate::log_error!("netlink op=add_worker status=connect_failed error={err:#}");
                    thread::sleep(Duration::from_secs(1));
                }
            }
        };

        // Reset per-session warning flag so the first error after each reconnect is logged.
        let mut warned_add_err = false;

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
            // Chunks not attempted (because the socket already failed earlier in
            // this batch) or that themselves failed with an IO error are kept
            // here and merged back into `batch` below, so a transient netlink
            // error for one set doesn't silently drop queued adds for other,
            // unrelated sets in the same batch — they're retried after reconnect.
            let mut retained: Vec<AddJob> = Vec::new();

            // Walk contiguous runs of the same set and fire each off. Both ipset and
            // nftset adds are send-only (the kernel commits inside the send() syscall),
            // so there is no recv round-trip to overlap — one send per distinct set.
            let mut pos = 0usize;
            while pos < batch.len() {
                let set = batch[pos].set.clone();
                let interval = batch[pos].interval;
                let chunk_start = pos;
                pos += 1;
                while pos < batch.len() && batch[pos].set == set {
                    pos += 1;
                }

                if need_reconnect {
                    retained.extend_from_slice(&batch[chunk_start..pos]);
                    continue;
                }

                let ips: Vec<IpAddr> = batch[chunk_start..pos].iter().map(|j| j.ip).collect();

                if let Err(err) = client.add_many(&set, &ips, interval) {
                    if super::is_io_error(&err) {
                        need_reconnect = true;
                        retained.extend_from_slice(&batch[chunk_start..pos]);
                    }
                    first_err.get_or_insert_with(|| format!("{err:#}"));
                }
            }

            if let Some(key) = first_err {
                if !warned_add_err {
                    warned_add_err = true;
                    crate::log_error!("netlink op=add_batch status=failed error={key}");
                }
            }

            // Cap the retry backlog: unlike the channel (bounded, drops at enqueue),
            // nothing else bounds `retained` — if netlink keeps opening but every add
            // keeps failing (need_reconnect every pass) while fresh jobs keep arriving
            // from the channel, this would otherwise grow without limit. Truncate to
            // the same size as the channel itself and count the overflow.
            if retained.len() > ADD_QUEUE_SIZE {
                let overflow = (retained.len() - ADD_QUEUE_SIZE) as u64;
                retained.truncate(ADD_QUEUE_SIZE);
                dropped_count.fetch_add(overflow, Ordering::Relaxed);
            }
            batch = retained;

            if need_reconnect {
                // Brief pause before reconnecting so we don't spin on a broken kernel.
                thread::sleep(Duration::from_millis(100));
                continue 'reconnect;
            }
        }
    }
}

/// Remove adjacent duplicate (set, ip) pairs.
///
/// Callers must sort by (set, ip) before calling so that all duplicates
/// are adjacent.
pub(super) fn dedup_jobs(jobs: &mut Vec<AddJob>) {
    jobs.dedup_by(|a, b| a.set == b.set && a.ip == b.ip);
}
