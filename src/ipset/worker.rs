//! Background add worker.
//!
//! A bounded channel delivers `AddJob` entries from the main thread.
//! The worker batches them, sorts by (set, ip), deduplicates adjacent
//! duplicates, then calls `NetfilterClient::add_many` with `BlindAdd`
//! for each unique set.  The worker owns its own `NetfilterClient`
//! (separate from the one held by `IpSetManager` for sync fallback).

use super::client::NetfilterClient;
use super::config::SetName;
use std::collections::HashSet;
use std::net::IpAddr;
use std::sync::mpsc;
use std::thread;

pub(super) const ADD_QUEUE_SIZE: usize = 16384;
pub(super) const ADD_BATCH_SIZE: usize = 64;

#[derive(Debug, Clone)]
pub(super) struct AddJob {
    pub(super) set: SetName,
    pub(super) ip: IpAddr,
}

pub(super) fn spawn_add_worker() -> mpsc::SyncSender<AddJob> {
    let (tx, rx) = mpsc::sync_channel(ADD_QUEUE_SIZE);
    let _ = thread::Builder::new()
        .name("ipset-add".into())
        .spawn(move || run_add_worker(rx));
    tx
}

fn run_add_worker(rx: mpsc::Receiver<AddJob>) {
    let mut client = match NetfilterClient::new() {
        Ok(c) => c,
        Err(err) => {
            crate::log_error!("netlink op=add_worker status=failed error={err:#}");
            return;
        }
    };
    let mut warned: HashSet<String> = HashSet::new();
    let mut batch: Vec<AddJob> = Vec::with_capacity(ADD_BATCH_SIZE);

    while let Ok(job) = rx.recv() {
        batch.push(job);
        while batch.len() < ADD_BATCH_SIZE {
            match rx.try_recv() {
                Ok(job) => batch.push(job),
                Err(_) => break,
            }
        }

        batch.sort_by(|a, b| a.set.cmp(&b.set).then_with(|| a.ip.cmp(&b.ip)));
        dedup_jobs(&mut batch);

        let mut first_err: Option<String> = None;

        // Process each contiguous run of jobs for the same set together.
        let mut pos = 0usize;
        while pos < batch.len() {
            let set = batch[pos].set.clone();
            let chunk_start = pos;
            pos += 1;
            while pos < batch.len() && batch[pos].set == set {
                pos += 1;
            }
            let ips: Vec<IpAddr> = batch[chunk_start..pos].iter().map(|j| j.ip).collect();
            if let Err(err) = client.add_many(&set, &ips) {
                first_err.get_or_insert_with(|| format!("{err:#}"));
            }
        }

        if let Some(key) = first_err {
            if warned.insert(key.clone()) {
                crate::log_error!("netlink op=add_batch status=failed error={key}");
            }
        }
        batch.clear();
    }
}

/// Remove adjacent duplicate (set, ip) pairs.
///
/// Callers must sort by (set, ip) before calling so that all duplicates
/// are adjacent.
pub(super) fn dedup_jobs(jobs: &mut Vec<AddJob>) {
    jobs.dedup_by(|a, b| a.set == b.set && a.ip == b.ip);
}
