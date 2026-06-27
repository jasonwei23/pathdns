//! io_uring multishot-recvmsg UDP receive path.
//!
//! This is the **only** UDP receive path — there is no recvmmsg fallback. The
//! kernel must support multishot recvmsg + provided buffer rings (Linux 6.0+);
//! `supported()` verifies this at startup and the listener refuses to run otherwise.
//!
//! A single `IORING_OP_RECVMSG` submitted with `IORING_RECV_MULTISHOT` keeps
//! delivering datagrams into a kernel-managed **provided buffer ring** — one CQE
//! per packet, no per-packet recv syscall. The ring fd is registered with Tokio via
//! `AsyncFd`, so the worker parks on the reactor and wakes when completions land.
//! The per-packet control area also carries `SO_RXQ_OVFL` (kernel receive-overflow
//! drops); `SO_MEMINFO` occupancy is sampled here too, for the dashboard.
//!
//! Packet processing (fast-path cache lookup, slow-path spawn) and the send side
//! (batched `sendmmsg` + bounded pending queue, in `udp_send`) are shared with the
//! rest of the server, so only "how datagrams arrive" is special here.

use crate::{
    dns,
    resolver::{handle_packet_slow_preparsed, try_fast_path_into, FastPathOutcome},
    server::AppState,
    sys,
    udp_send::{
        drain_pending_sends, send_one_response, try_send_items, SendBatch, MAX_BATCH,
        PENDING_SEND_CAP,
    },
    upstream::ClientProto,
};
use anyhow::{anyhow, Context, Result};
use bytes::{Bytes, BytesMut};
use io_uring::{cqueue, opcode, types, IoUring};
use std::alloc::{alloc_zeroed, dealloc, Layout};
use std::collections::VecDeque;
use std::mem;
use std::net::SocketAddr;
use std::os::fd::{AsRawFd, RawFd};
use std::sync::atomic::{AtomicU16, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};
use tokio::io::unix::AsyncFd;
use tokio::io::Interest;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;

/// Receive slot payload size. This holds an inbound *query*, which is tiny — even
/// with EDNS options a query is well under 1 KiB; 2 KiB is ample headroom. (The
/// large EDNS buffer a client advertises governs *response* size, not the query.)
/// Larger datagrams are flagged truncated and dropped.
const MAX_PKT: usize = 2048;
/// Per-buffer control-message space. Holds the `SO_RXQ_OVFL` cmsg (u32) plus the
/// `SCM_TIMESTAMPNS` cmsg (timespec); `CMSG_SPACE(4)+CMSG_SPACE(16)` ≈ 72 bytes.
const CONTROL_LEN: usize = 128;

// Provided buffers per shard are configured via `runtime.uring-recv-buffers`
// (default 256). Each holds one query plus its recvmsg header, address and control
// area, so memory per shard ≈ bufs * (MAX_PKT + ~290) ≈ 0.58 MiB at the default.
/// Per-shard slow-path reply queue depth. Bounded by the inflight cap in practice;
/// when momentarily full, a completing task sends its reply directly instead of
/// queueing, so replies are never dropped here.
const SLOW_REPLY_CAP: usize = 1024;
/// Buffer group id for the provided buffer ring (one ring per shard, id is local).
const BGID: u16 = 0;
/// Size of `struct io_uring_recvmsg_out` (4 × u32) prepended to each delivered
/// buffer by multishot recvmsg. Stable kernel ABI.
const RECVMSG_OUT_HDR: usize = 16;
/// Bytes reserved for the source address in each buffer (a full `sockaddr_storage`).
const NAME_LEN: usize = mem::size_of::<libc::sockaddr_storage>();

// ── Provided buffer ring ──────────────────────────────────────────────────────

/// A kernel-shared provided-buffer ring plus its backing datagram storage.
///
/// The ring is an array of `io_uring_buf` entries (page-aligned, as the ABI
/// requires). We publish buffers by writing an entry at `tail & mask` and releasing
/// the shared tail; the kernel fills the next free buffer and returns its `bid` in
/// each CQE, after which we recycle it.
struct ProvidedBufRing {
    ring_mem: *mut u8,
    ring_layout: Layout,
    entries: u16,
    mask: u16,
    tail: u16,
    bufs: Vec<u8>,
    buf_len: usize,
}

impl ProvidedBufRing {
    fn new(entries: u16, buf_len: usize) -> Result<Self> {
        if !entries.is_power_of_two() {
            return Err(anyhow!("io_uring buffer ring size must be a non-zero power of two"));
        }
        if buf_len == 0 {
            return Err(anyhow!("io_uring receive buffer must not be empty"));
        }
        if u32::try_from(buf_len).is_err() {
            return Err(anyhow!("io_uring receive buffer is too large: {buf_len}"));
        }
        let page = sys::page_size().max(4096);
        let size = (entries as usize)
            .checked_mul(mem::size_of::<types::BufRingEntry>())
            .ok_or_else(|| anyhow!("io_uring buffer ring allocation size overflow"))?;
        let backing_len = (entries as usize)
            .checked_mul(buf_len)
            .ok_or_else(|| anyhow!("io_uring receive buffer allocation size overflow"))?;
        let ring_layout = Layout::from_size_align(size, page)
            .map_err(|e| anyhow!("io_uring buf ring layout: {e}"))?;
        // SAFETY: layout has non-zero size; alloc_zeroed initialises every entry.
        let ring_mem = unsafe { alloc_zeroed(ring_layout) };
        if ring_mem.is_null() {
            return Err(anyhow!("io_uring buf ring allocation failed"));
        }
        Ok(Self {
            ring_mem,
            ring_layout,
            entries,
            mask: entries - 1,
            tail: 0,
            bufs: vec![0u8; backing_len],
            buf_len,
        })
    }

    /// Register this ring with the kernel for buffer group `BGID`.
    fn register(&self, submitter: &io_uring::Submitter) -> Result<()> {
        // SAFETY: `ring_mem` is allocated with the kernel-required alignment in
        // `new()` and is owned by this struct for at least as long as the io_uring
        // that registered it.
        unsafe {
            submitter
                .register_buf_ring_with_flags(self.ring_mem as u64, self.entries, BGID, 0)
                .context("register_buf_ring (needs Linux 5.19+)")
        }
    }

    #[inline]
    fn buf_addr(&self, bid: u16) -> Option<u64> {
        let offset = (bid as usize).checked_mul(self.buf_len)?;
        self.bufs
            .get(offset)
            .map(|byte| byte as *const u8 as u64)
    }

    /// Stage buffer `bid` into the ring slot at the current tail (does not release).
    ///
    /// Writes only addr/len/bid by copying the leading bytes of a locally-built entry,
    /// never the trailing `resv` field. For slot 0 that field aliases the ring tail the
    /// kernel reads concurrently, so we must never form a `&mut` spanning it.
    ///
    fn put(&mut self, bid: u16) {
        let Some(addr) = self.buf_addr(bid) else {
            return;
        };
        // io_uring_buf is a stable UAPI struct: { u64 addr; u32 len; u16 bid; u16 resv }.
        const BUF_PREFIX: usize = 8 + 4 + 2; // addr + len + bid, excluding resv
        debug_assert_eq!(mem::size_of::<types::BufRingEntry>(), BUF_PREFIX + 2);

        let slot = (self.tail & self.mask) as usize;
        // Build the entry in an exclusively-owned local, then copy only its addr/len/bid
        // prefix into the shared ring slot via a raw store — we never assert `&mut` over
        // the ring memory the kernel may be reading.
        // SAFETY: io_uring buffer-ring entries are plain UAPI structs; all-zero is
        // a valid temporary value before addr/len/bid are set below.
        let mut entry: types::BufRingEntry = unsafe { mem::zeroed() };
        entry.set_addr(addr);
        entry.set_len(self.buf_len as u32);
        entry.set_bid(bid);
        // SAFETY: `slot` is masked into the allocated ring, and `entry` is
        // stack-local so it cannot overlap the shared ring memory.
        unsafe {
            let dst = self.ring_mem.add(slot * mem::size_of::<types::BufRingEntry>());
            std::ptr::copy_nonoverlapping(
                &entry as *const types::BufRingEntry as *const u8,
                dst,
                BUF_PREFIX,
            );
        }
        self.tail = self.tail.wrapping_add(1);
    }

    /// Release the shared tail so the kernel sees all buffers added since the last
    /// publish (store-release pairs with the kernel's acquire load).
    ///
    fn publish(&self) {
        let base = self.ring_mem as *const types::BufRingEntry;
        // SAFETY: `ring_mem` points at the initialised buffer ring allocated in
        // `new()`; `tail()` returns the kernel-shared tail field for that ring.
        unsafe {
            let tail = types::BufRingEntry::tail(base) as *const AtomicU16;
            (*tail).store(self.tail, Ordering::Release);
        }
    }

    /// Fill the ring with every buffer and make them all available.
    ///
    fn init(&mut self) {
        for bid in 0..self.entries {
            self.put(bid);
        }
        self.publish();
    }

    /// The first `len` bytes of buffer `bid` (the delivered recvmsg data region).
    ///
    fn slice(&self, bid: u16, len: usize) -> &[u8] {
        let Some(start) = (bid as usize).checked_mul(self.buf_len) else {
            return &[];
        };
        let Some(end) = start.checked_add(len.min(self.buf_len)) else {
            return &[];
        };
        self.bufs.get(start..end).unwrap_or_default()
    }
}

impl Drop for ProvidedBufRing {
    fn drop(&mut self) {
        // SAFETY: allocated by alloc_zeroed with this exact layout; the owning ring
        // (and thus the registration) is already dropped (declared before us).
        unsafe { dealloc(self.ring_mem, self.ring_layout) };
    }
}

// SAFETY: the raw `ring_mem` pointer is owned exclusively by this struct and only
// accessed behind `&mut self`; moving the struct between threads is sound.
unsafe impl Send for ProvidedBufRing {}

// ── Multishot recv driver ─────────────────────────────────────────────────────

#[derive(Default)]
struct DrainStats {
    packets: usize,
    truncated: usize,
    /// Latest cumulative `SO_RXQ_OVFL` value seen on any packet this drain, if the
    /// kernel attached the cmsg. The caller turns this into a delta.
    rx_overflow: Option<u32>,
    /// Peak kernel→userspace receive latency (µs) across packets this drain.
    recv_lat_us: u32,
}

/// Owns an io_uring instance armed with a multishot recvmsg on one socket.
struct UringRecv {
    // Declared first so it (and the buffer-ring registration) drops before the ring
    // memory in `bufs`.
    ring: IoUring,
    bufs: ProvidedBufRing,
    socket_fd: RawFd,
    // Boxed for a stable address: the kernel reads this msghdr for every delivered
    // packet while the multishot op is live, so it must not move.
    msghdr: Box<libc::msghdr>,
    needs_arm: bool,
}

// SAFETY: the only non-Send field is the boxed msghdr, whose raw pointers we keep
// null (the kernel reads only msg_namelen/msg_controllen). All access is behind
// `&mut self`, so moving the whole driver between worker threads is sound.
unsafe impl Send for UringRecv {}

impl UringRecv {
    fn new(socket_fd: RawFd, entries: u16, payload_max: usize) -> Result<Self> {
        let buf_len = RECVMSG_OUT_HDR + NAME_LEN + CONTROL_LEN + payload_max;
        // CQ sized to hold a full ring's worth of completions between drains; a
        // small SQ suffices since we only ever submit the single multishot op.
        let ring = IoUring::builder()
            .setup_cqsize((entries as u32).next_power_of_two() * 2)
            .build(8)
            .context("io_uring setup")?;
        let bufs = ProvidedBufRing::new(entries, buf_len)?;
        bufs.register(&ring.submitter())?;
        let mut this = Self {
            ring,
            bufs,
            socket_fd,
            msghdr: Box::new(sys::zeroed_msghdr()),
            needs_arm: true,
        };
        // The kernel reads only msg_namelen / msg_controllen from this template to
        // lay out each delivered buffer (header, name, control, payload). The control
        // area carries the SO_RXQ_OVFL cmsg (enabled on the listen socket).
        this.msghdr.msg_namelen = NAME_LEN as libc::socklen_t;
        this.msghdr.msg_controllen = CONTROL_LEN as _;
        // First and only initialisation of the freshly registered ring.
        this.bufs.init();
        Ok(this)
    }

    fn ring_fd(&self) -> RawFd {
        self.ring.as_raw_fd()
    }

    fn needs_arm(&self) -> bool {
        self.needs_arm
    }

    /// Submit (or re-submit) the multishot recvmsg operation.
    fn arm(&mut self) -> Result<()> {
        let sqe = opcode::RecvMsgMulti::new(
            types::Fd(self.socket_fd),
            &*self.msghdr as *const libc::msghdr,
            BGID,
        )
        .build();
        // SAFETY: the msghdr (boxed) and buffer ring outlive the operation.
        unsafe {
            self.ring
                .submission()
                .push(&sqe)
                .map_err(|_| anyhow!("io_uring submission queue full"))?;
        }
        self.ring.submit().context("io_uring submit (arm)")?;
        self.needs_arm = false;
        Ok(())
    }

    /// Drain every available completion, invoking `on_pkt(payload, peer)` for each
    /// good datagram and recycling its buffer. Sets `needs_arm` if the kernel ended
    /// the multishot stream (e.g. buffer exhaustion).
    fn drain<F: FnMut(&[u8], SocketAddr)>(&mut self, mut on_pkt: F) -> DrainStats {
        let mut stats = DrainStats::default();
        let mut ended = false;
        let mut recycled = 0usize;
        // One clock read per drain; per-packet latency is measured against it.
        let now = sys::clock_realtime().unwrap_or(libc::timespec {
            tv_sec: 0,
            tv_nsec: 0,
        });
        let mut cq = self.ring.completion();
        cq.sync();
        for cqe in &mut cq {
            let flags = cqe.flags();
            if !cqueue::more(flags) {
                ended = true;
            }
            let bid = match cqueue::buffer_select(flags) {
                Some(b) => b,
                None => continue, // e.g. a bare -ENOBUFS/-ECANCELED with no buffer
            };
            let res = cqe.result();
            if res <= 0 {
                self.bufs.put(bid);
                recycled += 1;
                continue;
            }
            let buf = self.bufs.slice(bid, res as usize);
            if let Ok(out) = types::RecvMsgOut::parse(buf, &self.msghdr) {
                // Socket-level cmsgs: SO_RXQ_OVFL (cumulative drop count) and
                // SO_TIMESTAMPNS (kernel receive time → drain latency).
                let ctl = parse_control(out.control_data());
                if let Some(v) = ctl.rxq_overflow {
                    stats.rx_overflow = Some(v);
                }
                if let Some(ts) = ctl.timestamp {
                    stats.recv_lat_us = stats.recv_lat_us.max(recv_latency_us(&now, &ts));
                }
                if out.is_payload_truncated() {
                    stats.truncated += 1;
                } else {
                    let peer = sys::read_sockaddr_bytes(out.name_data());
                    let payload = out.payload_data();
                    if let Some(peer) = peer {
                        if !payload.is_empty() {
                            stats.packets += 1;
                            on_pkt(payload, peer);
                        }
                    }
                }
            }
            self.bufs.put(bid);
            recycled += 1;
        }
        drop(cq);
        // Return every consumed buffer to the kernel with a single tail release,
        // rather than one atomic store per packet.
        if recycled > 0 {
            self.bufs.publish();
        }
        if ended {
            self.needs_arm = true;
        }
        stats
    }
}

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
    send_buf: &mut BytesMut,
    send_items: &mut Vec<(Bytes, SocketAddr)>,
    reply_tx: &mpsc::Sender<(Bytes, SocketAddr)>,
) {
    send_buf.clear();
    match try_fast_path_into(pkt, peer, ClientProto::Udp, state, send_buf) {
        FastPathOutcome::Response { resp } => {
            let resp = dns::maybe_truncate_for_udp(resp, pkt);
            send_items.push((resp, peer));
        }
        FastPathOutcome::Drop => {}
        FastPathOutcome::Miss { info } => {
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
                    return;
                }
            };
            let state2 = state.clone();
            let socket2 = socket.clone();
            let reply_tx = reply_tx.clone();
            tokio::spawn(async move {
                let query = packet.clone();
                let send_state = state2.clone();
                if let Ok(Some(resp)) = handle_packet_slow_preparsed(
                    packet,
                    peer,
                    ClientProto::Udp,
                    state2,
                    info,
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

/// Per-shard flusher for slow-path (cache-miss) replies: drains the reply queue and
/// coalesces concurrently-completing responses into one `sendmmsg`. At low load each
/// wakeup carries a single reply (≈ a direct send); under load many flush per syscall.
async fn slow_reply_flush_loop(
    socket: Arc<UdpSocket>,
    mut rx: mpsc::Receiver<(Bytes, SocketAddr)>,
    state: Arc<AppState>,
) {
    let fd = socket.as_raw_fd();
    let mut bs = SendBatch::new(crate::udp_send::BATCH_SIZE);
    let mut staging: Vec<(Bytes, SocketAddr)> = Vec::with_capacity(crate::udp_send::BATCH_SIZE);
    while let Some(first) = rx.recv().await {
        staging.clear();
        staging.push(first);
        while staging.len() < crate::udp_send::BATCH_SIZE {
            match rx.try_recv() {
                Ok(item) => staging.push(item),
                Err(_) => break,
            }
        }
        let mut off = 0;
        while off < staging.len() {
            let res = socket
                .async_io(Interest::WRITABLE, || {
                    bs.send(fd, staging[off..].iter().map(|(r, p)| (r.as_ref(), *p)))
                })
                .await;
            match res {
                Ok(0) => break,
                Ok(n) => off += n,
                Err(_) => {
                    let dropped = (staging.len() - off) as u64;
                    state
                        .querylog
                        .counters
                        .udp_send_errors
                        .fetch_add(1, Ordering::Relaxed);
                    state
                        .querylog
                        .counters
                        .udp_send_drops
                        .fetch_add(dropped, Ordering::Relaxed);
                    break;
                }
            }
        }
    }
}

/// Send queued fast-path responses via batched `sendmmsg`, pushing anything the
/// kernel couldn't take into the bounded pending queue.
///
/// A single multishot drain can yield far more datagrams than `batch_size`, so sends
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

/// io_uring multishot-recvmsg serve loop for one SO_REUSEPORT shard.
pub(crate) async fn serve_udp_uring(
    socket: Arc<UdpSocket>,
    state: Arc<AppState>,
    batch_size: usize,
) -> Result<()> {
    let batch_size = batch_size.clamp(1, MAX_BATCH);
    let fd = socket.as_raw_fd();

    // Provided buffer-ring depth from config (validated to a power of two there).
    let uring_bufs = state.hot.load().cfg.uring_recv_buffers as u16;
    let mut recv = UringRecv::new(fd, uring_bufs, MAX_PKT).context("io_uring: init recv")?;
    recv.arm().context("io_uring: arm multishot recvmsg")?;
    let async_fd = AsyncFd::new(recv.ring_fd()).context("io_uring: register ring fd")?;

    let mut bs = SendBatch::new(batch_size);
    let mut send_items: Vec<(Bytes, SocketAddr)> = Vec::with_capacity(batch_size);
    let mut pending_sends: VecDeque<(Bytes, SocketAddr)> = VecDeque::new();
    let mut send_buf = BytesMut::with_capacity(512);
    // Slow-path (cache-miss) replies complete in independent tasks; route them
    // through a per-shard flusher that coalesces them into batched sendmmsg sends,
    // mirroring the fast path's batching.
    let (reply_tx, reply_rx) = mpsc::channel::<(Bytes, SocketAddr)>(SLOW_REPLY_CAP);
    tokio::spawn(slow_reply_flush_loop(
        socket.clone(),
        reply_rx,
        state.clone(),
    ));
    // Last-seen cumulative SO_RXQ_OVFL value; deltas feed udp_rx_overflow.
    let mut last_rxq_ovfl: u32 = 0;
    // Throttle SO_MEMINFO sampling to ~1 Hz.
    let mut last_meminfo = Instant::now();

    loop {
        // Park on the ring's completion readiness; also wake on writable when there
        // are queued sends so a saturated send buffer can't stall the pending queue.
        if pending_sends.is_empty() {
            let mut guard = async_fd.readable().await?;
            // Clear before draining so completions arriving mid-drain re-arm readiness.
            guard.clear_ready();
        } else {
            tokio::select! {
                g = async_fd.readable() => { g?.clear_ready(); }
                w = socket.writable() => {
                    w?;
                    drain_pending_sends(&socket, fd, &mut bs, batch_size, &mut pending_sends, &state);
                    continue;
                }
            }
        }

        send_items.clear();
        let stats = recv.drain(|payload, peer| {
            process_packet(
                payload,
                peer,
                &state,
                &socket,
                &mut send_buf,
                &mut send_items,
                &reply_tx,
            );
        });
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
        // SO_MEMINFO: sample receive-buffer occupancy ~1 Hz (peak across shards).
        if last_meminfo.elapsed() >= Duration::from_secs(1) {
            if let Some(pct) = socket_rmem_pct(fd) {
                state
                    .querylog
                    .counters
                    .udp_rmem_pct_acc
                    .fetch_max(pct, Ordering::Relaxed);
            }
            last_meminfo = Instant::now();
        }

        // Re-arm if the kernel ended the multishot stream (e.g. ran out of buffers).
        if recv.needs_arm() {
            recv.arm().context("io_uring: re-arm multishot recvmsg")?;
        }

        flush_sends(fd, &mut bs, batch_size, &send_items, &mut pending_sends, &state);
        if !pending_sends.is_empty() {
            drain_pending_sends(&socket, fd, &mut bs, batch_size, &mut pending_sends, &state);
        }
    }
}

// ── Runtime support probe ─────────────────────────────────────────────────────

/// Whether this kernel supports the multishot-recvmsg receive path. Probed once
/// (end-to-end against a loopback socket) and cached for the process lifetime.
pub(crate) fn supported() -> bool {
    static OK: OnceLock<bool> = OnceLock::new();
    *OK.get_or_init(|| probe().unwrap_or(false))
}

/// Build a real ring, arm multishot recvmsg on a throwaway loopback socket, send
/// one datagram, and confirm it comes back. Returns `Some(true)` only on a full
/// round trip — covering buffer-ring (5.19+) and multishot-recvmsg (6.0+) support.
fn probe() -> Option<bool> {
    use std::net::UdpSocket as StdUdp;
    let server = StdUdp::bind(("127.0.0.1", 0)).ok()?;
    let addr = server.local_addr().ok()?;
    let mut recv = UringRecv::new(server.as_raw_fd(), 16, 2048).ok()?;
    recv.arm().ok()?;

    let sender = StdUdp::bind(("127.0.0.1", 0)).ok()?;
    sender.send_to(&[0x55u8; 16], addr).ok()?;

    // Block until the multishot op posts at least one completion (good or error).
    recv.ring.submit_and_wait(1).ok()?;
    let mut got = false;
    recv.drain(|payload, _| got = payload.len() == 16);
    Some(got)
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
#[path = "tests/udp_uring.rs"]
mod tests;
