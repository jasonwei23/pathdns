#![cfg(target_os = "linux")]
//! Batch UDP receive/send using Linux recvmmsg(2)/sendmmsg(2).
//!
//! Pre-allocates ALL recv and send buffers (iovec, mmsghdr, sockaddr_storage)
//! in `BatchState` once at startup and reuses them across every batch iteration.
//! Zero heap allocations on the fast path.
//!
//! # SAFETY invariant for BatchState
//! `recv_bufs`, `recv_sockaddrs`, `recv_iovecs`, `send_names`, and `send_iovecs`
//! must not be moved or reallocated after the corresponding `*msgs` entries are
//! initialized.  Enforced by pre-sizing every Vec to exactly `batch_size` at
//! construction time and never pushing more.

use crate::{
    dns,
    resolver::{
        handle_packet_slow_preparsed, spawn_cache_refresh, try_fast_path_into, FastPathOutcome,
    },
    server::AppState,
    upstream::ClientProto,
};
use anyhow::{Context, Result};
use bytes::Bytes;
use bytes::BytesMut;
use std::{
    collections::VecDeque,
    mem,
    net::SocketAddr,
    os::fd::AsRawFd,
    sync::{atomic::Ordering, Arc},
};
use tokio::io::Interest;
use tokio::net::UdpSocket;

/// Hard upper bound on batch size; user value is clamped to this.
pub const MAX_BATCH: usize = 64;
/// Per-slot receive buffer size — DNS queries fit comfortably; EDNS max is 4096.
const MAX_PKT: usize = 4096;
/// Maximum responses queued while the kernel send buffer is saturated.
/// Once full, excess responses are dropped and counted in `udp_send_drops`.
const PENDING_SEND_CAP: usize = 256;

// ── Pre-allocated per-socket batch state ─────────────────────────────────────

struct BatchState {
    /// Maximum batch size; recv and send sides are both allocated to this many slots.
    batch_size: usize,

    // Recv side — pointers in recv_msgs are pre-wired into these Vecs.
    recv_bufs:  Vec<Vec<u8>>,                  // [batch_size][MAX_PKT]
    recv_addrs: Vec<libc::sockaddr_storage>,   // sender addresses filled by recvmmsg
    // SAFETY-CRITICAL: recv_msgs[i].msg_hdr.msg_iov points into this Vec.
    // Removing this field would leave those pointers dangling → silent memory
    // corruption on the next recvmmsg call.  Do not remove.
    #[allow(dead_code)]
    recv_iovecs: Vec<libc::iovec>,
    recv_msgs:   Vec<libc::mmsghdr>,

    // Send side — pointers in send_msgs are pre-wired into send_names/send_iovecs.
    send_names:  Vec<libc::sockaddr_storage>,  // dest addresses written before sendmmsg
    send_iovecs: Vec<libc::iovec>,             // iov_base/len updated before sendmmsg
    send_msgs:   Vec<libc::mmsghdr>,
}

// SAFETY: BatchState owns all memory it points to.  The raw pointers in the
// *msgs fields point into allocations that live inside the same BatchState and
// are never moved (Vecs are pre-sized and never pushed beyond capacity).  No
// other thread ever holds a copy of these pointers.
unsafe impl Send for BatchState {}

impl BatchState {
    fn new(batch_size: usize) -> Self {
        let batch_size = batch_size.min(MAX_BATCH).max(1);
        let namelen_full = mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;

        // ── Recv side ────────────────────────────────────────────────────────
        let mut recv_bufs: Vec<Vec<u8>> =
            (0..batch_size).map(|_| vec![0u8; MAX_PKT]).collect();
        let mut recv_addrs: Vec<libc::sockaddr_storage> =
            (0..batch_size).map(|_| unsafe { mem::zeroed() }).collect();

        // Allocate all Vecs to final capacity BEFORE storing any raw pointers,
        // so that the heap addresses are stable when we wire them up below.
        let mut recv_iovecs: Vec<libc::iovec> =
            vec![unsafe { mem::zeroed() }; batch_size];
        let mut recv_msgs: Vec<libc::mmsghdr> =
            vec![unsafe { mem::zeroed() }; batch_size];

        for i in 0..batch_size {
            recv_iovecs[i].iov_base = recv_bufs[i].as_mut_ptr() as *mut libc::c_void;
            recv_iovecs[i].iov_len  = MAX_PKT;
            recv_msgs[i].msg_hdr.msg_name    = &mut recv_addrs[i] as *mut _ as *mut libc::c_void;
            recv_msgs[i].msg_hdr.msg_namelen = namelen_full;
            recv_msgs[i].msg_hdr.msg_iov     = &mut recv_iovecs[i] as *mut _;
            recv_msgs[i].msg_hdr.msg_iovlen  = 1 as _; // c_int on musl, size_t on glibc
        }

        // ── Send side ─────────────────────────────────────────────────────────
        let mut send_names: Vec<libc::sockaddr_storage> =
            (0..batch_size).map(|_| unsafe { mem::zeroed() }).collect();
        let mut send_iovecs: Vec<libc::iovec> =
            vec![unsafe { mem::zeroed() }; batch_size];
        let mut send_msgs: Vec<libc::mmsghdr> =
            vec![unsafe { mem::zeroed() }; batch_size];

        for i in 0..batch_size {
            // msg_name and msg_iov are pre-wired; only msg_namelen, iov_base, iov_len
            // need updating before each sendmmsg call (they depend on packet content).
            send_msgs[i].msg_hdr.msg_name   = &mut send_names[i] as *mut _ as *mut libc::c_void;
            send_msgs[i].msg_hdr.msg_iov    = &mut send_iovecs[i] as *mut _;
            send_msgs[i].msg_hdr.msg_iovlen = 1 as _;
        }

        Self {
            batch_size,
            recv_bufs, recv_addrs, recv_iovecs, recv_msgs,
            send_names, send_iovecs, send_msgs,
        }
    }

    /// Restore recv msg_namelen before each recvmmsg call.
    /// The kernel overwrites msg_namelen with the actual sender-address length;
    /// we must reset it to the buffer capacity for the next call to have room.
    #[inline]
    fn reset_recv_namelen(&mut self, n: usize) {
        let cap = mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;
        for msg in &mut self.recv_msgs[..n] {
            msg.msg_hdr.msg_namelen = cap;
        }
    }
}

// ── Address helpers ───────────────────────────────────────────────────────────

/// Write `peer` into a zeroed `sockaddr_storage` and return the actual address length.
///
/// `sockaddr_in`/`sockaddr_in6` have all-public fields — struct literal syntax
/// is safe for these types (no musl padding issue, unlike `msghdr`/`sockaddr_storage`).
fn write_sockaddr(peer: SocketAddr, sa: &mut libc::sockaddr_storage) -> libc::socklen_t {
    // Zero the full storage so unused bytes are deterministic (important for musl
    // which may check the entire buffer).
    unsafe { std::ptr::write_bytes(sa, 0, 1) };
    match peer {
        SocketAddr::V4(v4) => {
            let p = sa as *mut _ as *mut libc::sockaddr_in;
            unsafe {
                (*p).sin_family = libc::AF_INET as libc::sa_family_t;
                (*p).sin_port   = v4.port().to_be();
                (*p).sin_addr.s_addr = u32::from_ne_bytes(v4.ip().octets());
            }
            mem::size_of::<libc::sockaddr_in>() as libc::socklen_t
        }
        SocketAddr::V6(v6) => {
            let p = sa as *mut _ as *mut libc::sockaddr_in6;
            unsafe {
                (*p).sin6_family   = libc::AF_INET6 as libc::sa_family_t;
                (*p).sin6_port     = v6.port().to_be();
                (*p).sin6_addr.s6_addr = v6.ip().octets();
                (*p).sin6_flowinfo = v6.flowinfo();
                (*p).sin6_scope_id = v6.scope_id();
            }
            mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t
        }
    }
}

/// Parse the kernel-written sockaddr_storage back to a SocketAddr.
///
/// # Safety
/// `sa` must have been filled by recvmmsg with `salen > 0`.
unsafe fn read_sockaddr(
    sa: &libc::sockaddr_storage,
    salen: libc::socklen_t,
) -> Option<SocketAddr> {
    if salen == 0 {
        return None;
    }
    match sa.ss_family as libc::c_int {
        libc::AF_INET if salen as usize >= mem::size_of::<libc::sockaddr_in>() => {
            let s = &*(sa as *const _ as *const libc::sockaddr_in);
            let ip = std::net::Ipv4Addr::from(s.sin_addr.s_addr.to_ne_bytes());
            Some(SocketAddr::from((ip, u16::from_be(s.sin_port))))
        }
        libc::AF_INET6 if salen as usize >= mem::size_of::<libc::sockaddr_in6>() => {
            let s = &*(sa as *const _ as *const libc::sockaddr_in6);
            let ip = std::net::Ipv6Addr::from(s.sin6_addr.s6_addr);
            Some(SocketAddr::V6(std::net::SocketAddrV6::new(
                ip,
                u16::from_be(s.sin6_port),
                s.sin6_flowinfo,
                s.sin6_scope_id,
            )))
        }
        _ => None,
    }
}

// ── recvmmsg helper ───────────────────────────────────────────────────────────

/// # Safety
/// `bs.recv_msgs[..n]` must have valid iov/name pointers (guaranteed by BatchState).
unsafe fn recv_batch(fd: libc::c_int, bs: &mut BatchState, n: usize) -> std::io::Result<usize> {
    let ret = libc::recvmmsg(
        fd,
        bs.recv_msgs.as_mut_ptr(),
        n as libc::c_uint,
        libc::MSG_DONTWAIT as _,
        std::ptr::null_mut(),
    );
    if ret < 0 {
        let e = std::io::Error::last_os_error();
        // EINTR: a signal interrupted the syscall before it ran.  Treat as
        // WouldBlock so the caller breaks from the drain loop and re-arms at
        // the top — rather than propagating a fatal error that kills this task.
        if e.kind() == std::io::ErrorKind::Interrupted {
            return Err(std::io::Error::from(std::io::ErrorKind::WouldBlock));
        }
        Err(e)
    } else {
        Ok(ret as usize)
    }
}

// ── sendmmsg helpers ──────────────────────────────────────────────────────────

/// Fill one pre-allocated send slot with address and payload pointers.
/// Shared by `try_send_items` and `drain_pending_sends`.
#[inline]
fn fill_send_slot(bs: &mut BatchState, i: usize, resp: &Bytes, peer: SocketAddr) {
    let salen = write_sockaddr(peer, &mut bs.send_names[i]);
    bs.send_msgs[i].msg_hdr.msg_namelen = salen;
    bs.send_iovecs[i].iov_base = resp.as_ptr() as *mut libc::c_void;
    bs.send_iovecs[i].iov_len  = resp.len();
    bs.send_msgs[i].msg_len    = 0; // ignored on input by the kernel
}

/// Attempt to send `items` via sendmmsg using pre-allocated buffers in `bs`.
///
/// Returns the index of the first item that was NOT sent: `0` if nothing was
/// sent, `items.len()` if all were sent.  Does NOT spawn any tasks; the caller
/// queues unsent items into the pending-send deque.
fn try_send_items(fd: libc::c_int, bs: &mut BatchState, items: &[(Bytes, SocketAddr)]) -> usize {
    let n = items.len();
    if n == 0 {
        return 0;
    }
    for (i, (resp, peer)) in items.iter().enumerate() {
        fill_send_slot(bs, i, resp, *peer);
    }
    // sendmmsg returns -1 when msgs[0] fails (nothing sent); otherwise the
    // number of messages actually sent.  On any error treat as nothing sent.
    let sent = unsafe { libc::sendmmsg(fd, bs.send_msgs.as_mut_ptr(), n as libc::c_uint, 0) };
    if sent < 0 { 0 } else { sent as usize }
}

/// Drain as much of `pending` as possible without blocking.
///
/// Uses `socket.try_io(Interest::WRITABLE, ...)` so tokio's writable-readiness
/// bit is cleared on WouldBlock, preventing a busy-spin in the outer select.
/// Stops as soon as the kernel buffer is full (WouldBlock); remaining items stay
/// in `pending` and are retried when the writable arm fires next.
fn drain_pending_sends(
    socket: &UdpSocket,
    fd: libc::c_int,
    bs: &mut BatchState,
    pending: &mut VecDeque<(Bytes, SocketAddr)>,
) {
    while !pending.is_empty() {
        let n = pending.len().min(bs.batch_size);
        // Use as_slices() to get the two contiguous segments of the VecDeque
        // without the O(n) memmove that make_contiguous() would perform when
        // the ring buffer has wrapped.
        let (a, b) = pending.as_slices();
        for (i, (resp, peer)) in a.iter().chain(b.iter()).take(n).enumerate() {
            fill_send_slot(bs, i, resp, *peer);
        }

        let result = socket.try_io(Interest::WRITABLE, || {
            let sent = unsafe {
                libc::sendmmsg(fd, bs.send_msgs.as_mut_ptr(), n as libc::c_uint, 0)
            };
            if sent < 0 {
                Err(std::io::Error::last_os_error())
            } else {
                Ok(sent as usize)
            }
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
                pending.pop_front();
            }
        }
    }
}

// ── Main async loop ───────────────────────────────────────────────────────────

/// Batch UDP receive/send loop using recvmmsg(2)/sendmmsg(2).
///
/// Each outer-loop iteration:
///  1. Park until readable; if there are pending sends, also wake on writable.
///  2. Drain pending-send queue (kernel buffer may have freed up).
///  3. Drain recv: call recvmmsg in a try_io loop until EAGAIN.
///     - The effective vlen is re-read from hot config each iteration.
///     - If the configured size is larger than the current BatchState capacity,
///       BatchState is rebuilt in-place (Option B hot-reload: full up/down scaling).
///  4. For each received packet, run try_fast_path_into synchronously.
///  5. Send fast-path responses via sendmmsg (zero allocations).
///  6. Unsent responses are pushed into a bounded pending-send queue
///     (capacity = PENDING_SEND_CAP) rather than spawning per-message tasks.
///     Overflow is dropped and counted in `udp_send_drops`.
///  7. Spawn tasks only for slow-path misses (cache miss → upstream).
pub(crate) async fn serve_udp_batch(
    socket:     Arc<UdpSocket>,
    state:      Arc<AppState>,
    batch_size: usize,
) -> Result<()> {
    let batch_size = batch_size.min(MAX_BATCH).max(1);
    let mut bs = BatchState::new(batch_size);
    let mut resp_buf   = BytesMut::with_capacity(512);
    let mut send_items: Vec<(Bytes, SocketAddr)> = Vec::with_capacity(batch_size);
    let mut pending_sends: VecDeque<(Bytes, SocketAddr)> = VecDeque::new();

    let fd = socket.as_raw_fd();

    loop {
        // Park until readable, or until writable if we have pending sends to drain.
        // No `biased` here: under a sustained read flood, a biased select would
        // never poll the writable future, preventing Tokio from re-arming the
        // WRITABLE readiness bit after a prior try_io(WRITABLE)→WouldBlock clears
        // it, causing drain_pending_sends to become a permanent no-op.
        if pending_sends.is_empty() {
            socket.readable().await?;
        } else {
            tokio::select! {
                r = socket.readable()  => r?,
                w = socket.writable()  => w?,
            }
        }

        // Attempt to drain the pending-send queue (kernel buffer may have room now).
        drain_pending_sends(&socket, fd, &mut bs, &mut pending_sends);

        // Drain recv: keep calling recvmmsg until EAGAIN.
        // try_io clears the readiness bit on WouldBlock so tokio re-arms the
        // edge-triggered notification; calling recvmmsg outside try_io causes
        // a busy-spin.
        loop {
            // Re-read batch size from config on each iteration.
            // If the configured size exceeds current BatchState capacity, rebuild it
            // so that hot-reload can scale up as well as down.
            let configured = {
                let h = state.hot.load();
                h.cfg.udp_batch_size.min(MAX_BATCH).max(1)
            };
            if configured > bs.batch_size {
                bs = BatchState::new(configured);
                // Grow send_items capacity to match the new batch size.
                if configured > send_items.capacity() {
                    send_items.reserve(configured - send_items.len());
                }
            }
            let n = configured;

            bs.reset_recv_namelen(n);

            let n_recv = match socket.try_io(Interest::READABLE, || {
                // SAFETY: bs satisfies the BatchState invariant documented above.
                unsafe { recv_batch(fd, &mut bs, n) }
            }) {
                Ok(n) => n,
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(e) => return Err(e).context("recvmmsg"),
            };

            if n_recv == 0 {
                break;
            }

            send_items.clear();

            for i in 0..n_recv {
                // Drop datagrams truncated by the kernel (larger than MAX_PKT).
                // recvmmsg sets MSG_TRUNC in msg_flags when the datagram didn't fit.
                if bs.recv_msgs[i].msg_hdr.msg_flags & libc::MSG_TRUNC != 0 {
                    state
                        .querylog
                        .counters
                        .udp_truncated
                        .fetch_add(1, Ordering::Relaxed);
                    continue;
                }
                let pkt_len = bs.recv_msgs[i].msg_len as usize;
                if pkt_len == 0 {
                    continue;
                }
                let namelen = bs.recv_msgs[i].msg_hdr.msg_namelen;
                let peer = match unsafe { read_sockaddr(&bs.recv_addrs[i], namelen) } {
                    Some(a) => a,
                    None => continue,
                };
                let pkt = &bs.recv_bufs[i][..pkt_len];

                resp_buf.clear();
                match try_fast_path_into(pkt, peer, &state, &mut resp_buf) {
                    FastPathOutcome::Response { resp, refresh } => {
                        if let Some(r) = refresh {
                            spawn_cache_refresh(r, &state);
                        }
                        let resp = dns::maybe_truncate_for_udp(resp, pkt);
                        send_items.push((resp, peer));
                    }
                    FastPathOutcome::Drop => {}
                    FastPathOutcome::Miss { info } => {
                        // Bug #9 fix: copy only the actual packet bytes (typically
                        // 50–200 bytes) rather than the entire 4096-byte recv slot.
                        let packet = Bytes::copy_from_slice(pkt);

                        let permit = match state.limit.clone().try_acquire_owned() {
                            Ok(p) => p,
                            Err(_) => {
                                state
                                    .querylog
                                    .counters
                                    .inflight_drops
                                    .fetch_add(1, Ordering::Relaxed);
                                if let Ok(sf) = dns::servfail_reply(pkt, info.question_end) {
                                    send_items.push((Bytes::from(sf), peer));
                                }
                                continue;
                            }
                        };

                        let state2  = state.clone();
                        let socket2 = socket.clone();
                        tokio::spawn(async move {
                            let query = packet.clone();
                            match handle_packet_slow_preparsed(
                                packet,
                                peer,
                                ClientProto::Udp,
                                state2,
                                info,
                                Some(permit),
                            )
                            .await
                            {
                                Ok(Some(resp)) => {
                                    let resp = dns::maybe_truncate_for_udp(resp, &query);
                                    let _ = socket2.send_to(&resp, peer).await;
                                }
                                Ok(None) | Err(_) => {}
                            }
                        });
                    }
                }
            }

            if !send_items.is_empty() {
                let first_unsent = try_send_items(fd, &mut bs, &send_items);
                // Push unsent items into the bounded pending-send queue instead of
                // spawning one task per message.  If the queue is full, drop newest
                // (oldest are more likely to still be within the client's timeout).
                let unsent = &send_items[first_unsent..];
                if !unsent.is_empty() {
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
                }
            }

            // Attempt to drain pending sends after each recv batch.  This ensures
            // progress even when the outer select! always resolves the readable arm
            // and the writable future is never polled to re-arm EPOLLOUT.
            if !pending_sends.is_empty() {
                drain_pending_sends(&socket, fd, &mut bs, &mut pending_sends);
            }
        }
    }
}

// ── Unit tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, UdpSocket as StdUdp};

    fn make_dns_query(id: u8) -> Vec<u8> {
        vec![
            id, 0,             // ID
            0x01, 0x00,        // QR=0 RD=1
            0x00, 0x01,        // QDCOUNT=1
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // AN/NS/AR = 0
            4, b't', b'e', b's', b't', 0,         // QNAME: "test"
            0x00, 0x01,        // QTYPE A
            0x00, 0x01,        // QCLASS IN
        ]
    }

    #[test]
    fn recvmmsg_receives_32_in_one_call() {
        let server = StdUdp::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        server.set_nonblocking(true).unwrap();
        let addr = server.local_addr().unwrap();

        let sender = StdUdp::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();

        let n = 32usize;
        for i in 0..n {
            sender.send_to(&make_dns_query(i as u8), addr).unwrap();
        }

        std::thread::sleep(std::time::Duration::from_millis(10));

        let fd = AsRawFd::as_raw_fd(&server);
        let mut bs = BatchState::new(n);
        bs.reset_recv_namelen(n);

        let received = unsafe { recv_batch(fd, &mut bs, n) }.expect("recvmmsg failed");
        assert_eq!(received, n, "expected {n} packets from recvmmsg");

        let mut seen = [false; 32];
        for i in 0..n {
            let len = bs.recv_msgs[i].msg_len as usize;
            assert!(len > 0, "slot {i} msg_len is 0");
            let idx = bs.recv_bufs[i][0] as usize;
            assert!(idx < 32, "unexpected first byte {idx}");
            seen[idx] = true;
        }
        assert!(seen.iter().all(|&b| b), "not all 32 distinct packets received");
    }

    #[test]
    fn truncated_packet_sets_msg_trunc_flag() {
        // Send a datagram larger than MAX_PKT (4096). The kernel will truncate it
        // to MAX_PKT bytes and set MSG_TRUNC in msg_flags.
        let server = StdUdp::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        server.set_nonblocking(true).unwrap();
        let addr = server.local_addr().unwrap();

        let sender = StdUdp::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let big_pkt = vec![0xABu8; MAX_PKT + 1]; // 4097 bytes — exceeds slot size
        sender.send_to(&big_pkt, addr).unwrap();

        std::thread::sleep(std::time::Duration::from_millis(10));

        let fd = AsRawFd::as_raw_fd(&server);
        let mut bs = BatchState::new(1);
        bs.reset_recv_namelen(1);

        let received = unsafe { recv_batch(fd, &mut bs, 1) }.expect("recvmmsg failed");
        assert_eq!(received, 1);
        // msg_len reflects the truncated byte count (== MAX_PKT, not 4097).
        assert_eq!(bs.recv_msgs[0].msg_len as usize, MAX_PKT);
        // MSG_TRUNC must be set so we know to discard this packet.
        assert_ne!(
            bs.recv_msgs[0].msg_hdr.msg_flags & libc::MSG_TRUNC,
            0,
            "MSG_TRUNC was not set for a datagram larger than MAX_PKT"
        );
    }

    #[test]
    fn sockaddr_roundtrip_v4() {
        let orig: SocketAddr = "127.0.0.1:5353".parse().unwrap();
        let mut storage: libc::sockaddr_storage = unsafe { mem::zeroed() };
        let salen = write_sockaddr(orig, &mut storage);
        let result = unsafe { read_sockaddr(&storage, salen) };
        assert_eq!(result, Some(orig));
    }

    #[test]
    fn sockaddr_roundtrip_v6() {
        let orig: SocketAddr = "[::1]:5353".parse().unwrap();
        let mut storage: libc::sockaddr_storage = unsafe { mem::zeroed() };
        let salen = write_sockaddr(orig, &mut storage);
        let result = unsafe { read_sockaddr(&storage, salen) };
        assert_eq!(result, Some(orig));
    }
}
