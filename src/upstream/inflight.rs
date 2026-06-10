//! Shared in-flight query registry for multiplexing transports.
//!
//! UDP socket pools and the TCP/TLS mux both correlate concurrent queries with
//! responses through a 16-bit upstream DNS ID.  This module owns that mechanism
//! in one place: ID allocation (race-free via `DashMap::entry`), the per-upstream
//! inflight cap, RAII cleanup, and response validation/delivery.
//!
//! ## Anti-spoofing order of operations
//! `complete` peeks the entry first and only removes it after the response
//! question matches the registered question.  A stale or spoofed response that
//! recycles a live ID therefore cannot destroy the live waiter's sender; the
//! real response can still arrive and be delivered.

use crate::dns;
use anyhow::{anyhow, Result};
use bytes::{Bytes, BytesMut};
use dashmap::DashMap;
use rustc_hash::FxBuildHasher;
use std::sync::atomic::{AtomicU32, Ordering};
use tokio::sync::oneshot;

struct Entry {
    tx: oneshot::Sender<Bytes>,
    client_id: u16,
    question: Bytes,
}

/// Outcome of [`InflightRegistry::complete`], for caller-side logging.
pub(super) enum Completion {
    /// Question validated; waiter completed; response bytes consumed from the buffer.
    Delivered,
    /// Not a reply, unparsable ID, or no waiter registered under the ID.
    NoWaiter,
    /// Question mismatch: the entry is kept and the response dropped (stale/spoofed).
    Mismatch(u16),
}

pub(super) struct InflightRegistry {
    entries: DashMap<u16, Entry, FxBuildHasher>,
    /// Counter seeded from system time at startup; mixed through `mix16` before use
    /// so that upstream query IDs are non-sequential and unpredictable.
    next_id: AtomicU32,
    /// Maximum concurrent in-flight queries (0 = unlimited).
    max_inflight: usize,
}

impl InflightRegistry {
    pub(super) fn new(max_inflight: usize) -> Self {
        Self {
            entries: DashMap::with_hasher(FxBuildHasher),
            next_id: AtomicU32::new(super::random_id_seed()),
            max_inflight,
        }
    }

    /// Register a query: allocate an unused upstream ID and store the responder.
    /// The returned guard removes the entry on drop (timeout/error paths); a
    /// delivered response removes it first, making the guard's removal a no-op.
    pub(super) fn register(
        &self,
        name: &str,
        client_id: u16,
        question: Bytes,
    ) -> Result<(u16, oneshot::Receiver<Bytes>, InflightGuard<'_>)> {
        if self.max_inflight > 0 && self.entries.len() >= self.max_inflight {
            return Err(anyhow!(
                "upstream {name} inflight cap ({}) reached",
                self.max_inflight
            ));
        }
        let (tx, rx) = oneshot::channel();
        let mut tx = Some(tx);
        for _ in 0..u16::MAX {
            let id = super::mix16(self.next_id.fetch_add(1, Ordering::Relaxed));
            match self.entries.entry(id) {
                dashmap::mapref::entry::Entry::Vacant(e) => {
                    let Some(tx) = tx.take() else {
                        return Err(anyhow!("upstream {name} sender already registered"));
                    };
                    e.insert(Entry {
                        tx,
                        client_id,
                        question,
                    });
                    return Ok((id, rx, InflightGuard { registry: self, id }));
                }
                dashmap::mapref::entry::Entry::Occupied(_) => continue,
            }
        }
        Err(anyhow!("upstream {name} inflight table is full"))
    }

    /// Validate the response in `buf[..len]` and, when the question matches the
    /// registered entry, rewrite the ID back to the client's and complete the
    /// waiter.  On delivery the response bytes are split out of `buf`.
    pub(super) fn complete(&self, buf: &mut BytesMut, len: usize) -> Completion {
        let packet = &buf[..len];
        if !dns::is_reply(packet) {
            return Completion::NoWaiter;
        }
        let Ok(id) = dns::get_id(packet) else {
            return Completion::NoWaiter;
        };
        // Peek first; only remove after question validation (see module docs).
        let Some(entry) = self.entries.get(&id) else {
            return Completion::NoWaiter;
        };
        let resp_question = dns::question_end(packet)
            .and_then(|end| packet.get(12..end))
            .unwrap_or(&[]);
        if !dns::questions_match(resp_question, &entry.question) {
            return Completion::Mismatch(id); // entry stays; real response can still arrive
        }
        drop(entry); // release shared ref before taking ownership
        if let Some((_, entry)) = self.entries.remove(&id) {
            let _ = dns::set_id(&mut buf[..len], entry.client_id);
            let _ = entry.tx.send(buf.split_to(len).freeze());
            return Completion::Delivered;
        }
        Completion::NoWaiter
    }

    /// Drop all pending entries; waiters observe a closed channel.
    /// Used by connection-oriented transports when the connection dies.
    pub(super) fn clear(&self) {
        self.entries.clear();
    }
}

/// RAII guard: removes the registered entry when dropped.
pub(super) struct InflightGuard<'a> {
    registry: &'a InflightRegistry,
    id: u16,
}

impl Drop for InflightGuard<'_> {
    fn drop(&mut self) {
        self.registry.entries.remove(&self.id);
    }
}
