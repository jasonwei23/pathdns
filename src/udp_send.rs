//! Batch UDP send using Linux sendmmsg(2), plus shared sockaddr helpers.
//!
//! The receive side lives in `udp_uring` (io_uring multishot recvmsg). This module
//! owns the send half: a pre-allocated `SendBatch` whose iovec/mmsghdr/sockaddr
//! arrays are wired up once and reused for every `sendmmsg`, so dispatching a batch
//! of responses costs zero heap allocations.

use crate::server::AppState;
pub(crate) use crate::sys::SendMmsgBatch as SendBatch;
use bytes::Bytes;
use std::os::fd::AsRawFd;
use std::{collections::VecDeque, net::SocketAddr, sync::atomic::Ordering};
use tokio::io::Interest;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;

/// Hard upper bound on batch size.
pub const MAX_BATCH: usize = 64;
/// Responses dispatched per `sendmmsg` syscall.
pub const BATCH_SIZE: usize = 32;
/// Maximum responses queued while the kernel send buffer is saturated.
/// Once full, excess responses are dropped and counted in `udp_send_drops`.
pub(crate) const PENDING_SEND_CAP: usize = 256;

// ── sendmmsg helpers ──────────────────────────────────────────────────────────

/// Attempt to send `items` via sendmmsg using pre-allocated buffers in `bs`.
///
/// `items.len()` must not exceed `bs`'s capacity (the caller chunks by `batch_size`).
/// Returns the number of items sent: `0` if nothing was sent, `items.len()` if all
/// were sent. Does not spawn tasks; the caller queues unsent items.
pub(crate) fn try_send_items(
    fd: libc::c_int,
    bs: &mut SendBatch,
    items: &[(Bytes, SocketAddr)],
) -> std::io::Result<usize> {
    if items.is_empty() {
        return Ok(0);
    }
    bs.send(fd, items.iter().map(|(resp, peer)| (resp.as_ref(), *peer)))
}

#[inline]
fn pending_send_batch_len(pending_len: usize, active_batch_size: usize, capacity: usize) -> usize {
    pending_len.min(active_batch_size).min(capacity)
}

/// Record one dropped UDP response (send error), bumping both the error and drop counters.
#[inline]
fn record_send_failure(state: &AppState) {
    state
        .querylog
        .counters
        .udp_send_errors
        .fetch_add(1, Ordering::Relaxed);
    state
        .querylog
        .counters
        .udp_send_drops
        .fetch_add(1, Ordering::Relaxed);
}

/// Drain as much of `pending` as possible without blocking.
///
/// Uses `socket.try_io(Interest::WRITABLE, ...)` so tokio's writable-readiness bit is
/// cleared on WouldBlock, preventing a busy-spin in the caller's select. Stops as soon
/// as the kernel buffer is full (WouldBlock); remaining items stay in `pending` and are
/// retried when the writable arm fires next.
pub(crate) fn drain_pending_sends(
    socket: &UdpSocket,
    fd: libc::c_int,
    bs: &mut SendBatch,
    active_batch_size: usize,
    pending: &mut VecDeque<(Bytes, SocketAddr)>,
    state: &AppState,
) {
    while !pending.is_empty() {
        let n = pending_send_batch_len(pending.len(), active_batch_size, bs.capacity());
        // Use as_slices() to get the two contiguous segments of the VecDeque without
        // the O(n) memmove that make_contiguous() would perform when the ring buffer
        // has wrapped.
        let (a, b) = pending.as_slices();
        let result = socket.try_io(Interest::WRITABLE, || {
            bs.send(
                fd,
                a.iter()
                    .chain(b.iter())
                    .take(n)
                    .map(|(resp, peer)| (resp.as_ref(), *peer)),
            )
        });

        match result {
            Ok(sent) => {
                for _ in 0..sent {
                    pending.pop_front();
                }
                if sent < n {
                    // Partial: kernel buffer is now full; stop until next writable.
                    break;
                }
            }
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
            Err(_) => {
                // Permanent error on msgs[0]: discard it so the deque makes progress.
                // The DNS client will retry after its own timeout.
                record_send_failure(state);
                pending.pop_front();
            }
        }
    }
}

/// Send a single response from an async slow-path task.
///
/// The hot UDP path batches replies with `sendmmsg`, but cache misses complete in
/// independent resolver tasks. Try the immediate non-blocking send first so the
/// common ready-socket case avoids registering/waking a Tokio writable future.
pub(crate) async fn send_one_response(
    socket: &UdpSocket,
    resp: &Bytes,
    peer: SocketAddr,
    state: &AppState,
) {
    match socket.try_send_to(resp, peer) {
        Ok(n) if n == resp.len() => return,
        Ok(_) => {
            record_send_failure(state);
            return;
        }
        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
        Err(_) => {
            record_send_failure(state);
            return;
        }
    }

    match socket.send_to(resp, peer).await {
        Ok(n) if n == resp.len() => {}
        Ok(_) | Err(_) => record_send_failure(state),
    }
}

/// Per-socket outbound flusher: block for a reply, opportunistically drain up to
/// `batch_size` more that are already queued, then dispatch them in one `sendmmsg`
/// (advancing past any short count). Shared by the upstream-query and client-reply
/// send paths; the only per-path differences are the item type, the actual send call
/// (`send` vs `send_connected`, supplied by `send_chunk`), and what to do on a send
/// error (`on_drop`, called with the number of items dropped).
pub(crate) async fn run_send_flush_loop<T, S, E>(
    socket: &UdpSocket,
    mut rx: mpsc::Receiver<T>,
    batch_size: usize,
    mut send_chunk: S,
    on_drop: E,
) where
    S: FnMut(&mut SendBatch, libc::c_int, &[T]) -> std::io::Result<usize>,
    E: Fn(usize),
{
    let fd = socket.as_raw_fd();
    let mut batch = SendBatch::new(batch_size);
    let mut staging: Vec<T> = Vec::with_capacity(batch_size);
    while let Some(first) = rx.recv().await {
        staging.clear();
        staging.push(first);
        while staging.len() < batch_size {
            match rx.try_recv() {
                Ok(item) => staging.push(item),
                Err(_) => break,
            }
        }
        let mut off = 0;
        while off < staging.len() {
            match socket
                .async_io(Interest::WRITABLE, || {
                    send_chunk(&mut batch, fd, &staging[off..])
                })
                .await
            {
                Ok(0) => break,
                Ok(n) => off += n,
                Err(_) => {
                    on_drop(staging.len() - off);
                    break;
                }
            }
        }
    }
}

// ── Unit tests ────────────────────────────────────────────────────────────────
