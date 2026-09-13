//! Batched-recvmmsg UDP receive path.
//!
//! Each shard drains its socket with `recvmmsg(2)` batches on a plain
//! `tokio::net::UdpSocket`, looping while a batch comes back full (more datagrams
//! are likely still queued) and stopping on a short read or `WouldBlock`. This
//! needs no kernel-registered/pinned memory — the batch's backing storage is a
//! plain heap allocation sized `batch_capacity * MAX_PKT`, reused across calls.
//!
//! The per-packet control area also carries `SO_RXQ_OVFL` (kernel receive-overflow
//! drops); `SO_MEMINFO` occupancy is sampled here too, for the dashboard.
//!
//! Packet processing (fast-path cache lookup, slow-path spawn) and the send side
//! (batched `sendmmsg` + bounded pending queue, in `udp_send`) are shared with the
//! rest of the server, so only "how datagrams arrive" is special here.

use crate::{
    config::UdpDiagnostics,
    dns,
    resolver::{handle_packet_slow_preparsed, try_fast_path_into, FastPathOutcome, ResponseArena},
    server::AppState,
    sys::{self, UdpRecvBatch},
    udp_send::{
        drain_pending_sends, send_one_response, try_send_items, SendBatch, MAX_BATCH,
        PENDING_SEND_CAP,
    },
    upstream::ClientProto,
};
use anyhow::{Context, Result};
use bytes::Bytes;
use std::collections::VecDeque;
use std::mem;
use std::net::SocketAddr;
use std::os::fd::AsRawFd;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::Interest;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;

/// Receive slot payload size. This holds an inbound *query*, which is tiny — even
/// with EDNS options a query is well under 1 KiB; 2 KiB is ample headroom. (The
/// large EDNS buffer a client advertises governs *response* size, not the query.)
/// Larger datagrams are flagged truncated and dropped.
const MAX_PKT: usize = 2048;
/// Per-slot control-message space. Holds the `SO_RXQ_OVFL` cmsg (u32) plus the
/// `SCM_TIMESTAMPNS` cmsg (timespec); `CMSG_SPACE(4)+CMSG_SPACE(16)` ≈ 72 bytes.
const CONTROL_LEN: usize = 128;

// recvmmsg batch capacity per shard is configured via `runtime.udp-recv-batch`
// (default 64). Memory per shard is a plain, pageable `batch * MAX_PKT` bytes
// (default 64 * 2 KiB = 128 KiB) — this scales with bind addresses × interfaces ×
// worker-threads, since each gets its own shard and batch buffer, but unlike a
// kernel-registered io_uring buffer ring it is ordinary reclaimable heap memory.
// A too-small batch just means the inner drain loop calls recvmmsg one more time
// per wakeup under sustained high-outstanding-query load — cheap relative to a
// larger allocation, so raise this only if the extra syscalls show up in profiles.
/// Fast-path response arena chunk size per UDP shard — see
/// `resolver::try_fast_path_into`. 64 KiB amortizes one allocation across
/// roughly 500+ typical cache-hit responses.
const FAST_PATH_ARENA_CHUNK: usize = 64 * 1024;
/// Per-shard slow-path reply queue depth. Bounded by the inflight cap in practice;
/// when momentarily full, a completing task sends its reply directly instead of
/// queueing, so replies are never dropped here.
const SLOW_REPLY_CAP: usize = 1024;
/// Per-shard admission wait queue. It is deliberately bounded: overload must
/// not turn into one sleeping Tokio task (and one copied packet) per datagram.
const ADMISSION_QUEUE_CAP: usize = 1024;

// ── Socket diagnostics (SO_RXQ_OVFL / SO_MEMINFO) ─────────────────────────────

/// Parsed socket-level control data for one delivered datagram.
#[derive(Default)]
struct ControlInfo {
    /// `SO_RXQ_OVFL`: cumulative receive-buffer overflow drop count.
    rxq_overflow: Option<u32>,
    /// `SO_TIMESTAMPNS`: kernel receive timestamp (CLOCK_REALTIME).
    timestamp: Option<libc::timespec>,
}

/// Walk a packet's control area once, extracting the SO_RXQ_OVFL and SO_TIMESTAMPNS
/// cmsgs (both socket-level, enabled on the listen socket).
fn parse_control(control: &[u8]) -> ControlInfo {
    let mut info = ControlInfo::default();
    let alignment = mem::align_of::<libc::cmsghdr>();
    let header_len = align_up(mem::size_of::<libc::cmsghdr>(), alignment);
    let mut offset = 0usize;

    while control.len().saturating_sub(offset) >= header_len {
        let Some(cmsg_len) = read_usize_ne(&control[offset..]) else {
            break;
        };
        if cmsg_len < header_len {
            break;
        }
        let Some(end) = offset.checked_add(cmsg_len) else {
            break;
        };
        if end > control.len() {
            break;
        }
        let level_offset = offset + mem::size_of::<usize>();
        let type_offset = level_offset + mem::size_of::<libc::c_int>();
        let (Some(level), Some(cmsg_type)) = (
            read_c_int_ne(&control[level_offset..]),
            read_c_int_ne(&control[type_offset..]),
        ) else {
            break;
        };
        let payload = &control[offset + header_len..end];
        if level == libc::SOL_SOCKET {
            match cmsg_type {
                libc::SO_RXQ_OVFL => {
                    if let Some(bytes) = payload.get(..mem::size_of::<u32>()) {
                        let mut value = [0u8; mem::size_of::<u32>()];
                        value.copy_from_slice(bytes);
                        info.rxq_overflow = Some(u32::from_ne_bytes(value));
                    }
                }
                libc::SCM_TIMESTAMPNS => {
                    info.timestamp = sys::read_timespec(payload);
                }
                _ => {}
            }
        }
        let Some(next) = align_up(cmsg_len, alignment).checked_add(offset) else {
            break;
        };
        if next <= offset {
            break;
        }
        offset = next;
    }
    info
}

fn align_up(value: usize, alignment: usize) -> usize {
    let mask = alignment.saturating_sub(1);
    value.saturating_add(mask) & !mask
}

fn read_usize_ne(bytes: &[u8]) -> Option<usize> {
    let mut value = [0u8; mem::size_of::<usize>()];
    let len = value.len();
    value.copy_from_slice(bytes.get(..len)?);
    Some(usize::from_ne_bytes(value))
}

fn read_c_int_ne(bytes: &[u8]) -> Option<libc::c_int> {
    let mut value = [0u8; mem::size_of::<libc::c_int>()];
    let len = value.len();
    value.copy_from_slice(bytes.get(..len)?);
    Some(libc::c_int::from_ne_bytes(value))
}

/// Microseconds elapsed from a kernel CLOCK_REALTIME receive timestamp to `now`,
/// clamped to a u32 (negatives from clock skew become 0).
fn recv_latency_us(now: &libc::timespec, ts: &libc::timespec) -> u32 {
    // Use i128 because CLOCK_REALTIME can jump after a clock correction; subtracting
    // extreme valid time_t values must not overflow and abort a debug/test build.
    let ns = (i128::from(now.tv_sec) - i128::from(ts.tv_sec)) * 1_000_000_000
        + (i128::from(now.tv_nsec) - i128::from(ts.tv_nsec));
    (ns / 1_000).clamp(0, i128::from(u32::MAX)) as u32
}

/// Current receive-queue occupancy as a percentage of the socket's receive buffer,
/// read via `SO_MEMINFO` (`rmem_alloc` / `rcvbuf`). `None` if unavailable. A figure
/// climbing toward 100 is the early-warning signal that precedes `SO_RXQ_OVFL` drops.
fn socket_rmem_pct(fd: libc::c_int) -> Option<u32> {
    // SK_MEMINFO_VARS is small (<16); over-size the buffer so newer kernels that add
    // fields still fit. Index 0 = rmem_alloc (bytes queued), index 1 = rcvbuf (limit).
    let mut info = [0u32; 16];
    if sys::get_socket_u32s(fd, libc::SOL_SOCKET, libc::SO_MEMINFO, &mut info).ok()? < 2 {
        return None;
    }
    let (rmem_alloc, rcvbuf) = (info[0], info[1]);
    if rcvbuf == 0 {
        return None;
    }
    Some(((rmem_alloc as u64 * 100) / rcvbuf as u64) as u32)
}

// ── Serve loop ────────────────────────────────────────────────────────────────

/// Process one received datagram: fast-path cache hit → queue response; miss →
/// spawn the slow resolver task.
#[inline]
fn process_packet(
    pkt: &[u8],
    peer: SocketAddr,
    state: &Arc<AppState>,
    socket: &Arc<UdpSocket>,
    send_buf: &mut ResponseArena,
    send_items: &mut Vec<(Bytes, SocketAddr)>,
    slow: &SlowPathSenders,
) {
    match try_fast_path_into(pkt, peer, ClientProto::Udp, state, send_buf) {
        FastPathOutcome::Response { resp } => {
            let resp = dns::maybe_truncate_for_udp(resp, pkt);
            send_items.push((resp, peer));
        }
        FastPathOutcome::Drop => {}
        FastPathOutcome::Miss { info, probe } => {
            let packet = Bytes::copy_from_slice(pkt);
            let permit = match state.limit.clone().try_acquire_owned() {
                Ok(p) => p,
                Err(_) => {
                    let queue_ms = state.hot.load().cfg.inflight_queue_ms;
                    if queue_ms > 0 {
                        let pending = PendingQuery {
                            packet,
                            peer,
                            info,
                            probe,
                            deadline: tokio::time::Instant::now() + Duration::from_millis(queue_ms),
                        };
                        if slow.admission.try_send(pending).is_ok() {
                            state
                                .querylog
                                .counters
                                .inflight_queued
                                .fetch_add(1, Ordering::Relaxed);
                            return;
                        }
                    }
                    state
                        .querylog
                        .counters
                        .inflight_drops
                        .fetch_add(1, Ordering::Relaxed);
                    if let Ok(sf) = dns::servfail_reply(pkt, info.question_end) {
                        send_items.push((Bytes::from(sf), peer));
                    }
                    return;
                }
            };
            let state2 = state.clone();
            let socket2 = socket.clone();
            let reply_tx = slow.replies.clone();
            tokio::spawn(async move {
                let query = packet.clone();
                let send_state = state2.clone();
                if let Ok(Some(resp)) = handle_packet_slow_preparsed(
                    packet,
                    peer,
                    ClientProto::Udp,
                    state2,
                    info,
                    probe,
                    Some(permit),
                )
                .await
                {
                    let resp = dns::maybe_truncate_for_udp(resp, &query);
                    // Hand the reply to the per-shard flusher so concurrently-completing
                    // cache misses coalesce into one sendmmsg. If the queue is momentarily
                    // full, fall back to an immediate send rather than block or drop.
                    if let Err(mpsc::error::TrySendError::Full((resp, peer))) =
                        reply_tx.try_send((resp, peer))
                    {
                        send_one_response(&socket2, &resp, peer, &send_state).await;
                    }
                }
            });
        }
    }
}

struct SlowPathSenders {
    replies: mpsc::Sender<(Bytes, SocketAddr)>,
    admission: mpsc::Sender<PendingQuery>,
}

struct PendingQuery {
    packet: Bytes,
    peer: SocketAddr,
    info: dns::FastQueryInfo,
    probe: crate::cache::CacheProbe,
    deadline: tokio::time::Instant,
}

fn spawn_slow_query(
    pending: PendingQuery,
    permit: tokio::sync::OwnedSemaphorePermit,
    state: Arc<AppState>,
    socket: Arc<UdpSocket>,
    reply_tx: mpsc::Sender<(Bytes, SocketAddr)>,
) {
    tokio::spawn(async move {
        let query = pending.packet.clone();
        let send_state = state.clone();
        if let Ok(Some(resp)) = handle_packet_slow_preparsed(
            pending.packet,
            pending.peer,
            ClientProto::Udp,
            state,
            pending.info,
            pending.probe,
            Some(permit),
        )
        .await
        {
            let resp = dns::maybe_truncate_for_udp(resp, &query);
            if let Err(mpsc::error::TrySendError::Full((resp, peer))) =
                reply_tx.try_send((resp, pending.peer))
            {
                send_one_response(&socket, &resp, peer, &send_state).await;
            }
        }
    });
}

async fn admission_loop(
    mut rx: mpsc::Receiver<PendingQuery>,
    state: Arc<AppState>,
    socket: Arc<UdpSocket>,
    reply_tx: mpsc::Sender<(Bytes, SocketAddr)>,
) {
    while let Some(pending) = rx.recv().await {
        let permit = tokio::time::timeout_at(pending.deadline, state.limit.clone().acquire_owned())
            .await
            .ok()
            .and_then(Result::ok);
        if let Some(permit) = permit {
            spawn_slow_query(
                pending,
                permit,
                state.clone(),
                socket.clone(),
                reply_tx.clone(),
            );
        } else {
            state
                .querylog
                .counters
                .inflight_drops
                .fetch_add(1, Ordering::Relaxed);
            if let Ok(resp) = dns::servfail_reply(&pending.packet, pending.info.question_end) {
                let resp = Bytes::from(resp);
                if let Err(mpsc::error::TrySendError::Full((resp, peer))) =
                    reply_tx.try_send((resp, pending.peer))
                {
                    send_one_response(&socket, &resp, peer, &state).await;
                }
            }
        }
    }
}

/// Per-shard flusher for slow-path (cache-miss) replies: drains the reply queue and
/// coalesces concurrently-completing responses into one `sendmmsg`. At low load each
/// wakeup carries a single reply (≈ a direct send); under load many flush per syscall.
async fn slow_reply_flush_loop(
    socket: Arc<UdpSocket>,
    rx: mpsc::Receiver<(Bytes, SocketAddr)>,
    state: Arc<AppState>,
) {
    crate::udp_send::run_send_flush_loop(
        &socket,
        rx,
        crate::udp_send::BATCH_SIZE,
        |bs, fd, items: &[(Bytes, SocketAddr)]| {
            bs.send(fd, items.iter().map(|(r, p)| (r.as_ref(), *p)))
        },
        move |dropped| {
            state
                .querylog
                .counters
                .udp_send_errors
                .fetch_add(1, Ordering::Relaxed);
            state
                .querylog
                .counters
                .udp_send_drops
                .fetch_add(dropped as u64, Ordering::Relaxed);
        },
    )
    .await;
}

/// Send queued fast-path responses via batched `sendmmsg`, pushing anything the
/// kernel couldn't take into the bounded pending queue.
///
/// A single recvmmsg drain can yield far more datagrams than `batch_size`, so sends
/// are issued in `batch_size`-sized chunks — `bs`'s send slots are only sized for one
/// batch. The first chunk the kernel can't fully accept
/// ends the loop and the remainder is queued.
fn flush_sends(
    fd: libc::c_int,
    bs: &mut SendBatch,
    batch_size: usize,
    send_items: &[(Bytes, SocketAddr)],
    pending_sends: &mut VecDeque<(Bytes, SocketAddr)>,
    state: &Arc<AppState>,
) {
    let mut idx = 0;
    while idx < send_items.len() {
        let end = (idx + batch_size).min(send_items.len());
        let chunk = &send_items[idx..end];
        let sent = match try_send_items(fd, bs, chunk) {
            Ok(sent) => sent,
            Err(error) => {
                if error.kind() != std::io::ErrorKind::WouldBlock {
                    state
                        .querylog
                        .counters
                        .udp_send_errors
                        .fetch_add(1, Ordering::Relaxed);
                }
                0
            }
        };
        if sent < chunk.len() {
            // Kernel send buffer is full: queue this chunk's remainder plus every
            // later chunk into the bounded pending queue, then stop.
            let unsent = &send_items[idx + sent..];
            let space = PENDING_SEND_CAP.saturating_sub(pending_sends.len());
            let to_queue = unsent.len().min(space);
            let drop_count = unsent.len() - to_queue;
            if drop_count > 0 {
                state
                    .querylog
                    .counters
                    .udp_send_drops
                    .fetch_add(drop_count as u64, Ordering::Relaxed);
            }
            for (resp, peer) in &unsent[..to_queue] {
                pending_sends.push_back((resp.clone(), *peer));
            }
            return;
        }
        idx = end;
    }
}

/// Diagnostics folded out of one `recvmmsg` batch's worth of control areas.
#[derive(Default)]
struct DrainStats {
    truncated: usize,
    rx_overflow: Option<u32>,
    recv_lat_us: u32,
}

/// Process the `n` messages a single `recvmmsg` call just delivered into `batch`,
/// invoking `process_packet` for each good datagram and folding cmsg diagnostics
/// (when enabled) into the returned stats.
#[allow(clippy::too_many_arguments)]
fn process_batch(
    batch: &UdpRecvBatch,
    n: usize,
    diagnostics: UdpDiagnostics,
    state: &Arc<AppState>,
    socket: &Arc<UdpSocket>,
    send_buf: &mut ResponseArena,
    send_items: &mut Vec<(Bytes, SocketAddr)>,
    slow_senders: &SlowPathSenders,
) -> DrainStats {
    let mut stats = DrainStats::default();
    // One clock read per batch; per-packet latency is measured against it. Only
    // needed when SO_TIMESTAMPNS cmsgs are actually being delivered.
    let now = if diagnostics >= UdpDiagnostics::Full {
        sys::clock_realtime().unwrap_or(libc::timespec {
            tv_sec: 0,
            tv_nsec: 0,
        })
    } else {
        libc::timespec {
            tv_sec: 0,
            tv_nsec: 0,
        }
    };
    for i in 0..n {
        if diagnostics >= UdpDiagnostics::Basic {
            let ctl = parse_control(batch.control(i));
            if let Some(v) = ctl.rxq_overflow {
                stats.rx_overflow = Some(v);
            }
            if let Some(ts) = ctl.timestamp {
                stats.recv_lat_us = stats.recv_lat_us.max(recv_latency_us(&now, &ts));
            }
        }
        let Some(peer) = batch.peer(i) else { continue };
        match batch.payload(i) {
            None => stats.truncated += 1,
            Some([]) => {}
            Some(payload) => process_packet(
                payload,
                peer,
                state,
                socket,
                send_buf,
                send_items,
                slow_senders,
            ),
        }
    }
    stats
}

/// Batched-recvmmsg serve loop for one SO_REUSEPORT shard.
pub(crate) async fn serve_udp_recvmmsg(
    socket: Arc<UdpSocket>,
    state: Arc<AppState>,
    batch_size: usize,
) -> Result<()> {
    let batch_size = batch_size.clamp(1, MAX_BATCH);
    let fd = socket.as_raw_fd();

    // recvmmsg batch capacity from config.
    let (recv_batch, diagnostics) = {
        let hot = state.hot.load();
        (hot.cfg.udp_recv_batch, hot.cfg.udp_diagnostics)
    };
    let control_len = if diagnostics >= UdpDiagnostics::Basic {
        CONTROL_LEN
    } else {
        0
    };
    let mut recv = UdpRecvBatch::new(recv_batch, MAX_PKT, control_len);

    let mut bs = SendBatch::new(batch_size);
    let mut send_items: Vec<(Bytes, SocketAddr)> = Vec::with_capacity(batch_size);
    let mut pending_sends: VecDeque<(Bytes, SocketAddr)> = VecDeque::new();
    let mut send_buf = ResponseArena::new(FAST_PATH_ARENA_CHUNK);
    // Slow-path (cache-miss) replies complete in independent tasks; route them
    // through a per-shard flusher that coalesces them into batched sendmmsg sends,
    // mirroring the fast path's batching.
    let (reply_tx, reply_rx) = mpsc::channel::<(Bytes, SocketAddr)>(SLOW_REPLY_CAP);
    tokio::spawn(slow_reply_flush_loop(
        socket.clone(),
        reply_rx,
        state.clone(),
    ));
    let (admission_tx, admission_rx) = mpsc::channel(ADMISSION_QUEUE_CAP);
    tokio::spawn(admission_loop(
        admission_rx,
        state.clone(),
        socket.clone(),
        reply_tx.clone(),
    ));
    let slow_senders = SlowPathSenders {
        replies: reply_tx,
        admission: admission_tx,
    };
    // Last-seen cumulative SO_RXQ_OVFL value; deltas feed udp_rx_overflow.
    let mut last_rxq_ovfl: u32 = 0;
    // Throttle SO_MEMINFO sampling to ~1 Hz.
    let mut last_meminfo = Instant::now();

    loop {
        // Park on readability; also wake on writable when there are queued sends
        // so a saturated send buffer can't stall the pending queue.
        if pending_sends.is_empty() {
            socket.readable().await?;
        } else {
            tokio::select! {
                r = socket.readable() => { r?; }
                w = socket.writable() => {
                    w?;
                    drain_pending_sends(&socket, fd, &mut bs, batch_size, &mut pending_sends, &state);
                    continue;
                }
            }
        }

        send_items.clear();
        // Drain every currently-queued datagram: loop calling recvmmsg (each attempt
        // wrapped in try_io so tokio's readiness bit is cleared correctly) while a
        // call returns a full batch — more is likely still queued — stopping on a
        // short read or WouldBlock.
        loop {
            let n = match socket.try_io(Interest::READABLE, || recv.recv(fd)) {
                Ok(n) => n,
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(e) => return Err(e).context("recvmmsg"),
            };
            let stats = process_batch(
                &recv,
                n,
                diagnostics,
                &state,
                &socket,
                &mut send_buf,
                &mut send_items,
                &slow_senders,
            );
            if stats.truncated > 0 {
                state
                    .querylog
                    .counters
                    .udp_truncated
                    .fetch_add(stats.truncated as u64, Ordering::Relaxed);
            }
            // SO_RXQ_OVFL: fold the cumulative kernel drop count into a running delta.
            if let Some(cur) = stats.rx_overflow {
                let delta = cur.wrapping_sub(last_rxq_ovfl);
                if delta > 0 {
                    state
                        .querylog
                        .counters
                        .udp_rx_overflow
                        .fetch_add(delta as u64, Ordering::Relaxed);
                }
                last_rxq_ovfl = cur;
            }
            // SO_TIMESTAMPNS: keep the rolling per-second peak kernel→userspace latency.
            if stats.recv_lat_us > 0 {
                state
                    .querylog
                    .counters
                    .udp_recv_lat_us_acc
                    .fetch_max(stats.recv_lat_us, Ordering::Relaxed);
            }
            if n < recv.capacity() {
                break;
            }
        }
        // SO_MEMINFO: sample receive-buffer occupancy ~1 Hz (peak across shards).
        if diagnostics >= UdpDiagnostics::Basic && last_meminfo.elapsed() >= Duration::from_secs(1)
        {
            if let Some(pct) = socket_rmem_pct(fd) {
                state
                    .querylog
                    .counters
                    .udp_rmem_pct_acc
                    .fetch_max(pct, Ordering::Relaxed);
            }
            last_meminfo = Instant::now();
        }

        flush_sends(
            fd,
            &mut bs,
            batch_size,
            &send_items,
            &mut pending_sends,
            &state,
        );
        if !pending_sends.is_empty() {
            drain_pending_sends(&socket, fd, &mut bs, batch_size, &mut pending_sends, &state);
        }
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::fd::AsRawFd;

    #[test]
    fn recvmmsg_round_trip_payload_and_peer() {
        let server = std::net::UdpSocket::bind(("127.0.0.1", 0)).unwrap();
        server.set_nonblocking(true).unwrap();
        let addr = server.local_addr().unwrap();

        let sender = std::net::UdpSocket::bind(("127.0.0.1", 0)).unwrap();
        let sender_addr = sender.local_addr().unwrap();
        sender.send_to(&[0x55u8; 16], addr).unwrap();

        let mut batch = UdpRecvBatch::new(8, 2048, 0);
        // The datagram may not have arrived instantly on a loopback socket;
        // retry briefly rather than flake under load.
        let mut n = 0;
        for _ in 0..1000 {
            match batch.recv(server.as_raw_fd()) {
                Ok(got) => {
                    n = got;
                    break;
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(std::time::Duration::from_millis(1));
                }
                Err(e) => panic!("recv failed: {e}"),
            }
        }
        assert_eq!(n, 1);
        assert_eq!(batch.payload(0), Some(&[0x55u8; 16][..]));
        assert_eq!(batch.peer(0), Some(sender_addr));
    }
}
