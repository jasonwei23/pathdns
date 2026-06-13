#![cfg(target_os = "linux")]
//! Batch UDP receive/send using Linux recvmmsg(2)/sendmmsg(2).
//!
//! Pre-allocates all recv/addr/iovec/mmsghdr buffers once at startup and
//! reuses them across every batch iteration to avoid per-packet allocation.
//!
//! # SAFETY invariant for BatchState
//! `recv_bufs` and `sockaddrs` must not be moved or reallocated after `iovecs`
//! and `msgs` are initialized.  Enforced by pre-sizing Vecs to exactly
//! `batch_size` elements at construction time and never pushing more.

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

// ── Pre-allocated per-socket batch state ─────────────────────────────────────

struct BatchState {
    batch_size: usize,
    recv_bufs:  Vec<Vec<u8>>,
    sockaddrs:  Vec<libc::sockaddr_storage>,
    // Kept alive because msgs[i].msg_hdr.msg_iov points into this Vec.
    #[allow(dead_code)]
    iovecs:     Vec<libc::iovec>,
    msgs:       Vec<libc::mmsghdr>,
}

// SAFETY: BatchState owns all memory it points to.  The raw pointers in
// `iovecs` and `msgs` point into `recv_bufs` and `sockaddrs` which are owned
// heap allocations that live inside the same BatchState.  No other thread
// ever holds a copy of these pointers.
unsafe impl Send for BatchState {}

impl BatchState {
    fn new(batch_size: usize) -> Self {
        let batch_size = batch_size.min(MAX_BATCH).max(1);

        // Heap-allocate receive buffers first; their addresses must be stable
        // before we store raw pointers to them.
        let mut recv_bufs: Vec<Vec<u8>> = (0..batch_size)
            .map(|_| vec![0u8; MAX_PKT])
            .collect();

        // sockaddr_storage has private musl padding — must zeroed(), not struct literal.
        let mut sockaddrs: Vec<libc::sockaddr_storage> =
            (0..batch_size).map(|_| unsafe { mem::zeroed() }).collect();

        // Initialize all iovecs and mmsghdr entries to zero first, then wire up
        // pointers in a second pass.  This ensures all Vecs have their final
        // heap addresses before any raw pointer is stored.
        let mut iovecs: Vec<libc::iovec> =
            vec![unsafe { mem::zeroed() }; batch_size];
        let mut msgs: Vec<libc::mmsghdr> =
            vec![unsafe { mem::zeroed() }; batch_size];

        let namelen = mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;
        for i in 0..batch_size {
            iovecs[i].iov_base = recv_bufs[i].as_mut_ptr() as *mut libc::c_void;
            iovecs[i].iov_len  = MAX_PKT;

            msgs[i].msg_hdr.msg_name    = &mut sockaddrs[i] as *mut _ as *mut libc::c_void;
            msgs[i].msg_hdr.msg_namelen = namelen;
            msgs[i].msg_hdr.msg_iov     = &mut iovecs[i] as *mut _;
            // msg_iovlen: c_int on musl, size_t on glibc — `as _` infers the target type.
            msgs[i].msg_hdr.msg_iovlen  = 1 as _;
        }

        Self { batch_size, recv_bufs, sockaddrs, iovecs, msgs }
    }

    /// Restore msg_namelen before each recvmmsg call.
    /// The kernel overwrites it with the actual sender-address length; we must
    /// reset it to the buffer capacity so the next call has room.
    #[inline]
    fn reset_namelen(&mut self) {
        let cap = mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;
        for msg in &mut self.msgs {
            msg.msg_hdr.msg_namelen = cap;
        }
    }
}

// ── recvmmsg helper ───────────────────────────────────────────────────────────

/// # Safety
/// `bs.msgs[..bs.batch_size]` must have valid iov/name pointers (guaranteed by
/// BatchState construction).
unsafe fn recv_batch(fd: libc::c_int, bs: &mut BatchState) -> std::io::Result<usize> {
    let n = libc::recvmmsg(
        fd,
        bs.msgs.as_mut_ptr(),
        bs.batch_size as libc::c_uint,
        libc::MSG_DONTWAIT as _,
        std::ptr::null_mut(),
    );
    if n < 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(n as usize)
    }
}

// ── sendmmsg helper ───────────────────────────────────────────────────────────

/// Temporary sockaddr union for outgoing messages.
enum SockaddrBuf {
    V4(libc::sockaddr_in),
    V6(libc::sockaddr_in6),
}

fn sockaddr_from_std(peer: SocketAddr) -> SockaddrBuf {
    match peer {
        SocketAddr::V4(v4) => SockaddrBuf::V4(libc::sockaddr_in {
            sin_family: libc::AF_INET as libc::sa_family_t,
            sin_port:   v4.port().to_be(),
            sin_addr:   libc::in_addr {
                s_addr: u32::from_ne_bytes(v4.ip().octets()),
            },
            sin_zero: [0; 8],
        }),
        SocketAddr::V6(v6) => SockaddrBuf::V6(libc::sockaddr_in6 {
            sin6_family:   libc::AF_INET6 as libc::sa_family_t,
            sin6_port:     v6.port().to_be(),
            sin6_flowinfo: v6.flowinfo(),
            sin6_addr:     libc::in6_addr { s6_addr: v6.ip().octets() },
            sin6_scope_id: v6.scope_id(),
        }),
    }
}

/// Send all accumulated fast-path responses in one sendmmsg call.
///
/// sendmmsg returns -1 only when msgs[0] fails (nothing sent).
/// Returns n < count when the first n messages were sent and the rest were not
/// attempted.  Any unsent messages fall back to async `socket.send_to`.
fn send_batch(socket: &Arc<UdpSocket>, items: &[(Bytes, SocketAddr)]) {
    if items.is_empty() {
        return;
    }

    let sa_bufs: Vec<SockaddrBuf> = items.iter().map(|(_, p)| sockaddr_from_std(*p)).collect();
    let mut iovecs: Vec<libc::iovec>   = Vec::with_capacity(items.len());
    let mut msgs: Vec<libc::mmsghdr>   = Vec::with_capacity(items.len());

    for (i, (resp, _)) in items.iter().enumerate() {
        iovecs.push(libc::iovec {
            iov_base: resp.as_ptr() as *mut libc::c_void,
            iov_len:  resp.len(),
        });
        let (name_ptr, name_len) = match &sa_bufs[i] {
            SockaddrBuf::V4(s) => (
                s as *const _ as *mut libc::c_void,
                mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
            ),
            SockaddrBuf::V6(s) => (
                s as *const _ as *mut libc::c_void,
                mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t,
            ),
        };
        let mut m: libc::mmsghdr = unsafe { mem::zeroed() };
        m.msg_hdr.msg_name    = name_ptr;
        m.msg_hdr.msg_namelen = name_len;
        m.msg_hdr.msg_iov     = &iovecs[i] as *const _ as *mut libc::iovec;
        m.msg_hdr.msg_iovlen  = 1 as _;
        msgs.push(m);
    }

    let fd = socket.as_raw_fd();
    let sent = unsafe {
        libc::sendmmsg(fd, msgs.as_mut_ptr(), msgs.len() as libc::c_uint, 0)
    };

    let first_unsent = if sent < 0 {
        let e = std::io::Error::last_os_error();
        if e.kind() == std::io::ErrorKind::WouldBlock {
            0 // kernel buffer full: fall back for all
        } else {
            1 // permanent error on msgs[0]: skip it, retry the rest
        }
    } else {
        sent as usize
    };

    // Spawn async fallback for any messages that were not sent.
    for (resp, peer) in &items[first_unsent..] {
        let socket = socket.clone();
        let resp   = resp.clone();
        let peer   = *peer;
        tokio::spawn(async move {
            let _ = socket.send_to(&resp, peer).await;
        });
    }
}

// ── sockaddr_storage → SocketAddr ────────────────────────────────────────────

/// # Safety
/// `sa` must have been written by recvmmsg with `salen > 0`.
unsafe fn sockaddr_to_std(
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

// ── Main async loop ───────────────────────────────────────────────────────────

/// Batch UDP receive/send loop using recvmmsg(2)/sendmmsg(2).
///
/// Each iteration:
///  1. Await readability.
///  2. Drain: call recvmmsg in a try_io loop until EAGAIN.
///  3. For each received packet, run try_fast_path_into synchronously.
///  4. Collect fast-path responses into a send list.
///  5. Spawn tasks for slow-path misses (cache miss → upstream).
///  6. Send all fast-path responses in one sendmmsg call.
pub(crate) async fn serve_udp_batch(
    socket:     Arc<UdpSocket>,
    state:      Arc<AppState>,
    batch_size: usize,
) -> Result<()> {
    let batch_size = batch_size.min(MAX_BATCH).max(1);
    let mut bs     = BatchState::new(batch_size);
    let mut resp_buf  = BytesMut::with_capacity(512);
    let mut send_items: Vec<(Bytes, SocketAddr)> = Vec::with_capacity(batch_size);

    let fd = socket.as_raw_fd();

    loop {
        // Park until the socket has at least one datagram.
        socket.readable().await?;

        // Drain: keep calling recvmmsg until EAGAIN.
        // try_io clears the readiness bit on WouldBlock so tokio re-arms the
        // edge-triggered notification; calling recvmmsg outside try_io causes
        // a busy-spin.
        loop {
            bs.reset_namelen();

            let n_recv = match socket.try_io(Interest::READABLE, || {
                // SAFETY: bs satisfies the invariant documented on BatchState.
                unsafe { recv_batch(fd, &mut bs) }
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
                let pkt_len = bs.msgs[i].msg_len as usize;
                if pkt_len == 0 {
                    continue;
                }
                let namelen = bs.msgs[i].msg_hdr.msg_namelen;
                let peer = match unsafe { sockaddr_to_std(&bs.sockaddrs[i], namelen) } {
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
                        // 50–200 bytes) rather than the full 4096-byte recv slot.
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
                send_batch(&socket, &send_items);
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
        // Minimal valid-looking DNS query header + 1 question
        vec![
            id, 0,             // ID (id, 0)
            0x01, 0x00,        // QR=0 RD=1
            0x00, 0x01,        // QDCOUNT=1
            0x00, 0x00,        // ANCOUNT=0
            0x00, 0x00,        // NSCOUNT=0
            0x00, 0x00,        // ARCOUNT=0
            // QNAME: 4 "test" 0
            4, b't', b'e', b's', b't', 0,
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

        // Give the kernel a moment (loopback is nearly instant but not zero).
        std::thread::sleep(std::time::Duration::from_millis(10));

        let fd = AsRawFd::as_raw_fd(&server);
        let mut bs = BatchState::new(n);
        bs.reset_namelen();

        let received = unsafe { recv_batch(fd, &mut bs) }.expect("recvmmsg failed");
        assert_eq!(received, n, "expected {n} packets from recvmmsg");

        // Verify each slot has non-zero length.
        let mut seen = [false; 32];
        for i in 0..n {
            let len = bs.msgs[i].msg_len as usize;
            assert!(len > 0, "slot {i} msg_len is 0");
            let idx = bs.recv_bufs[i][0] as usize;
            assert!(idx < 32, "unexpected first byte {idx}");
            seen[idx] = true;
        }
        assert!(seen.iter().all(|&b| b), "not all 32 distinct packets received");
    }

    #[test]
    fn sockaddr_roundtrip_v4() {
        let orig: SocketAddr = "127.0.0.1:5353".parse().unwrap();
        let buf = sockaddr_from_std(orig);
        let (storage, salen) = match &buf {
            SockaddrBuf::V4(s) => {
                let mut st: libc::sockaddr_storage = unsafe { mem::zeroed() };
                unsafe {
                    std::ptr::copy_nonoverlapping(
                        s as *const _ as *const u8,
                        &mut st as *mut _ as *mut u8,
                        mem::size_of::<libc::sockaddr_in>(),
                    );
                }
                (st, mem::size_of::<libc::sockaddr_in>() as libc::socklen_t)
            }
            _ => panic!("expected V4"),
        };
        let result = unsafe { sockaddr_to_std(&storage, salen) };
        assert_eq!(result, Some(orig));
    }

    #[test]
    fn sockaddr_roundtrip_v6() {
        let orig: SocketAddr = "[::1]:5353".parse().unwrap();
        let buf = sockaddr_from_std(orig);
        let (storage, salen) = match &buf {
            SockaddrBuf::V6(s) => {
                let mut st: libc::sockaddr_storage = unsafe { mem::zeroed() };
                unsafe {
                    std::ptr::copy_nonoverlapping(
                        s as *const _ as *const u8,
                        &mut st as *mut _ as *mut u8,
                        mem::size_of::<libc::sockaddr_in6>(),
                    );
                }
                (st, mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t)
            }
            _ => panic!("expected V6"),
        };
        let result = unsafe { sockaddr_to_std(&storage, salen) };
        assert_eq!(result, Some(orig));
    }
}
