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
use bytes::Bytes;
use dashmap::DashMap;
use rustc_hash::FxBuildHasher;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use tokio::sync::{oneshot, OwnedSemaphorePermit};

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
    /// Semaphore-based inflight cap: each in-flight query holds one permit for its
    /// entire lifetime (from `register` until the guard is dropped).  Using an
    /// `OwnedSemaphorePermit` stored in the guard eliminates the TOCTOU race that
    /// a `len() >= cap` check-then-insert pattern would have.  None when unlimited.
    cap: Option<Arc<tokio::sync::Semaphore>>,
}

impl InflightRegistry {
    pub(super) fn new(max_inflight: usize) -> Self {
        let cap = if max_inflight > 0 {
            Some(Arc::new(tokio::sync::Semaphore::new(max_inflight)))
        } else {
            None
        };
        Self {
            entries: DashMap::with_hasher(FxBuildHasher),
            next_id: AtomicU32::new(super::random_id_seed()),
            cap,
        }
    }

    /// Register a query: allocate an unused upstream ID and store the responder.
    /// The returned guard removes the entry on drop (timeout/error paths); a
    /// delivered response removes it first, making the guard's removal a no-op.
    /// When a per-upstream cap is configured, the guard also holds a semaphore
    /// permit that is released atomically on drop.
    pub(super) fn register(
        &self,
        name: &str,
        client_id: u16,
        question: Bytes,
    ) -> Result<(u16, oneshot::Receiver<Bytes>, InflightGuard<'_>)> {
        let permit = if let Some(sem) = &self.cap {
            match sem.clone().try_acquire_owned() {
                Ok(p) => Some(p),
                Err(_) => return Err(anyhow!("upstream {name} inflight cap reached")),
            }
        } else {
            None
        };
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
                    return Ok((
                        id,
                        rx,
                        InflightGuard {
                            registry: self,
                            id,
                            _permit: permit,
                        },
                    ));
                }
                dashmap::mapref::entry::Entry::Occupied(_) => continue,
            }
        }
        Err(anyhow!("upstream {name} inflight table is full"))
    }

    /// Validate the response in `packet` and, when the question matches the
    /// registered entry, rewrite the ID back to the client's and complete the
    /// waiter.  `packet` is the exact received datagram bytes (one message);
    /// taking a slice lets the single-recv and `recvmmsg` batch paths share this.
    pub(super) fn complete(&self, packet: &mut [u8]) -> Completion {
        if !dns::is_reply(packet) {
            return Completion::NoWaiter;
        }
        // Opcode must be standard QUERY (0); len >= 12 guaranteed by is_reply.
        if (packet[2] >> 3) & 0x0f != 0 {
            return Completion::NoWaiter;
        }
        // Must have exactly one question.
        if u16::from_be_bytes([packet[4], packet[5]]) != 1 {
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
            let _ = dns::set_id(packet, entry.client_id);
            let _ = entry.tx.send(Bytes::copy_from_slice(packet));
            return Completion::Delivered;
        }
        Completion::NoWaiter
    }

    /// Returns `true` when no queries are currently in flight.
    pub(super) fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Drop all pending entries; waiters observe a closed channel.
    /// Used by connection-oriented transports when the connection dies.
    pub(super) fn clear(&self) {
        self.entries.clear();
    }
}

/// RAII guard: removes the registered entry on drop (timeout / error paths).
/// A delivered response removes the entry first via `complete`, making the
/// removal here a no-op.  The optional semaphore permit is also released on
/// drop, returning capacity to the inflight cap.
pub(super) struct InflightGuard<'a> {
    registry: &'a InflightRegistry,
    id: u16,
    _permit: Option<OwnedSemaphorePermit>,
}

impl Drop for InflightGuard<'_> {
    fn drop(&mut self) {
        self.registry.entries.remove(&self.id);
        // _permit drops here, atomically returning one slot to the semaphore
    }
}

#[cfg(test)]
#[path = "tests/inflight.rs"]
mod tests;
