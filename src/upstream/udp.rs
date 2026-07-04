use super::inflight::{Completion, InflightRegistry};
use super::{apply_ecs_mode, now_ms, tcp_exchange_packet, UpstreamRequest};
use crate::config::EcsMode;
use crate::dns;
use crate::sys;
use anyhow::{anyhow, Context, Result};
use arc_swap::ArcSwap;
use bytes::{Bytes, BytesMut};
use std::net::SocketAddr;
use std::os::unix::io::AsRawFd;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::UdpSocket;

const MAX_DNS_MESSAGE: usize = u16::MAX as usize;

/// Datagrams drained per `recvmmsg` syscall on each upstream socket. Larger batches
/// amortise the syscall over more responses under load; 16 keeps per-socket buffer
/// reservation modest (slots are lazily committed, so unused capacity costs nothing).
const RECV_BATCH: usize = 16;

/// Outbound queries coalesced per `sendmmsg` syscall on each upstream socket.
const SEND_BATCH: usize = 16;

/// Per-socket outbound queue depth. The per-upstream inflight cap bounds how many
/// queries can be queued at once; this just sets the backpressure point.
const SEND_QUEUE_CAP: usize = 1024;

/// Consecutive query timeouts (see `HealthStats::consecutive_failures` in
/// `upstream/mod.rs`) before a UDP upstream's socket pool is recreated.
pub(super) const STALE_SOCKET_REFRESH_THRESHOLD: u32 = 6;

/// Minimum time between socket-pool refresh attempts, so a genuinely-dead
/// upstream doesn't churn sockets on every single failing query.
const REFRESH_COOLDOWN_MS: u64 = 30_000;

pub(super) struct UdpUpstream {
    pub(super) name: String,
    remote: SocketAddr,
    /// Swappable so a stale/blackholed route can be recovered by recreating the
    /// socket (see `trigger_refresh`) without changing the upstream's identity.
    sockets: Vec<ArcSwap<UdpSocket>>,
    /// One outbound queue per socket; a flusher task drains each with `sendmmsg`.
    send_qs: Vec<ArcSwap<tokio::sync::mpsc::Sender<Bytes>>>,
    send_idx: AtomicUsize,
    timeout: Duration,
    inflight: InflightRegistry,
    ecs_mode: EcsMode,
    /// fwmark reused for the TC-bit TCP fallback so it routes like the UDP socket.
    mark: Option<u32>,
    buf_size: usize,
    /// Per-socket generation, bumped only once that specific socket's replacement
    /// has actually succeeded — so a failed refresh attempt for one socket never
    /// orphans another (still-good) socket's recv loop.
    generations: Vec<AtomicU64>,
    /// Fired after a refresh so a recv loop blocked on a since-replaced socket
    /// (which may otherwise never see an error — see `trigger_refresh`) wakes
    /// immediately instead of leaking its task and file descriptor.
    refreshed: tokio::sync::Notify,
    /// Epoch-ms before which another refresh attempt is rejected.
    refresh_not_before_ms: AtomicU64,
    /// Guards against triggering more than one refresh concurrently.
    refreshing: AtomicBool,
}

impl UdpUpstream {
    /// Create a pool of `pool_size` sockets, spawn one recv loop per socket.
    pub(super) async fn create(
        common: super::UpstreamCommonConfig,
        pool_size: usize,
        buf_size: usize,
    ) -> Result<Arc<Self>> {
        let super::UpstreamCommonConfig {
            name,
            remote,
            timeout,
            ecs_mode,
            max_inflight,
            mark,
        } = common;
        let mut sockets = Vec::with_capacity(pool_size);
        let mut send_qs = Vec::with_capacity(pool_size);
        let mut receivers = Vec::with_capacity(pool_size);
        for _ in 0..pool_size {
            let socket = open_socket(remote, buf_size, mark, &name).await?;
            sockets.push(ArcSwap::new(socket));
            let (tx, rx) = tokio::sync::mpsc::channel::<Bytes>(SEND_QUEUE_CAP);
            send_qs.push(ArcSwap::new(Arc::new(tx)));
            receivers.push(rx);
        }
        let generations = (0..pool_size).map(|_| AtomicU64::new(0)).collect();
        let upstream = Arc::new(Self {
            name,
            remote,
            sockets,
            send_qs,
            send_idx: AtomicUsize::new(0),
            timeout,
            inflight: InflightRegistry::new(max_inflight),
            ecs_mode,
            mark,
            buf_size,
            generations,
            refreshed: tokio::sync::Notify::new(),
            refresh_not_before_ms: AtomicU64::new(0),
            refreshing: AtomicBool::new(false),
        });
        for (i, rx) in receivers.into_iter().enumerate() {
            upstream.spawn_recv_supervisor(i, 0);
            let socket = upstream.sockets[i].load_full();
            tokio::spawn(send_flush_loop(socket, rx));
        }
        Ok(upstream)
    }

    pub(super) async fn exchange(&self, req: UpstreamRequest) -> Result<Bytes> {
        let raw_packet = apply_ecs_mode(&req.packet, &self.ecs_mode);
        let mut packet = BytesMut::from(raw_packet.as_ref());
        let question = req.question.clone(); // keep a copy for TC-fallback validation
        let (upstream_id, rx, _guard) =
            self.inflight
                .register(&self.name, req.client_id, req.question)?;
        dns::set_id(&mut packet, upstream_id)?;

        // Freeze so the wire bytes can be handed to the per-socket send flusher
        // (cheap refcounted clone) while this task keeps a copy for the TC TCP
        // fallback below.
        let packet = packet.freeze();
        let socket_idx = self.send_idx.fetch_add(1, Ordering::Relaxed) % self.send_qs.len();
        if self.send_qs[socket_idx]
            .load()
            .send(packet.clone())
            .await
            .is_err()
        {
            return Err(anyhow!("upstream {} send flusher stopped", self.name));
        }

        match tokio::time::timeout(self.timeout, rx).await {
            Ok(Ok(resp)) => {
                if dns::is_truncated(&resp) {
                    match tcp_exchange_packet(
                        self.remote,
                        &packet,
                        self.timeout,
                        &self.name,
                        self.mark,
                    )
                    .await
                    {
                        Ok(mut tcp_resp) => {
                            super::validate_upstream_response(&tcp_resp, upstream_id, &question)
                                .map_err(|e| anyhow!("upstream {}: TCP fallback {e}", self.name))?;
                            dns::set_id(&mut tcp_resp, req.client_id)?;
                            return Ok(Bytes::from(tcp_resp));
                        }
                        Err(err) => {
                            return Err(err);
                        }
                    }
                }
                Ok(resp)
            }
            Ok(Err(_closed)) => Err(anyhow!("upstream {} response channel closed", self.name)),
            Err(elapsed) => Err(anyhow::Error::from(elapsed)
                .context(format!("upstream {} timeout: {}", self.name, self.remote))),
        }
    }

    /// Recreate every socket in the pool (fresh bind + `SO_MARK` + connect), so a
    /// route that changed underneath an already-`connect()`ed socket (e.g. a
    /// policy-routed/VPN path re-established with a new gateway) is picked up
    /// fresh. UDP gives no protocol-level signal for this — unlike TCP, a
    /// half-broken or blackholed path may never surface as a socket error, so the
    /// only available signal is sustained query timeouts (see caller in
    /// `upstream/mod.rs`). Rate-limited and reentrancy-guarded so a persistently
    /// dead upstream doesn't churn sockets on every failing query.
    pub(super) fn trigger_refresh(self: &Arc<Self>) {
        let now = now_ms();
        if now < self.refresh_not_before_ms.load(Ordering::Relaxed) {
            return;
        }
        if self
            .refreshing
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Relaxed)
            .is_err()
        {
            return; // a refresh is already in flight
        }
        self.refresh_not_before_ms
            .store(now + REFRESH_COOLDOWN_MS, Ordering::Relaxed);
        let this = self.clone();
        tokio::spawn(async move {
            this.do_refresh().await;
            this.refreshing.store(false, Ordering::Release);
        });
    }

    async fn do_refresh(self: &Arc<Self>) {
        let mut any_ok = false;
        for i in 0..self.sockets.len() {
            match open_socket(self.remote, self.buf_size, self.mark, &self.name).await {
                Ok(socket) => {
                    self.sockets[i].store(socket.clone());
                    let (tx, rx) = tokio::sync::mpsc::channel::<Bytes>(SEND_QUEUE_CAP);
                    // Dropping the old sender (replaced here) closes the old channel,
                    // so its send_flush_loop task drains and exits on its own — no
                    // explicit signal needed for the write side (unlike the read side
                    // below, which can be blocked indefinitely with no such cue).
                    self.send_qs[i].store(Arc::new(tx));
                    let new_gen = self.generations[i].fetch_add(1, Ordering::Relaxed) + 1;
                    tokio::spawn(send_flush_loop(socket, rx));
                    self.spawn_recv_supervisor(i, new_gen);
                    any_ok = true;
                }
                Err(e) => {
                    crate::log_error!(
                        "upstream name={} event=refresh_socket_failed idx={i} error={e:#}",
                        self.name
                    );
                }
            }
        }
        // Wake any old-generation recv loop still blocked on a replaced socket.
        self.refreshed.notify_waiters();
        crate::log_error!(
            "upstream name={} event=sockets_refreshed any_ok={any_ok}",
            self.name
        );
    }

    /// Spawn the supervised recv loop for one socket slot at generation `my_gen`,
    /// restarting it with exponential backoff on a genuine (non-stale) error.
    fn spawn_recv_supervisor(self: &Arc<Self>, socket_idx: usize, my_gen: u64) {
        let u = self.clone();
        tokio::spawn(async move {
            let mut delay_ms = 50u64;
            while let Err(err) = u.clone().recv_loop(socket_idx, my_gen).await {
                crate::log_error!(
                    "upstream name={} event=recv_loop_exit error={err:#} restarting_in={delay_ms}ms",
                    u.name
                );
                tokio::time::sleep(Duration::from_millis(delay_ms)).await;
                delay_ms = (delay_ms * 2).min(5_000);
            }
        });
    }

    async fn recv_loop(self: Arc<Self>, socket_idx: usize, my_gen: u64) -> Result<()> {
        let mut batch = sys::RecvMmsgBatch::new(RECV_BATCH, MAX_DNS_MESSAGE);
        let mut recv_count = 0u32;
        loop {
            // Superseded by a refresh (this slot's socket was recreated): exit
            // cleanly (not an error) so the supervisor does not retry forever.
            if self.generations[socket_idx].load(Ordering::Relaxed) != my_gen {
                return Ok(());
            }
            let socket = self.sockets[socket_idx].load_full();
            let fd = socket.as_raw_fd();
            // Wait for readability, then drain every queued datagram with a single
            // recvmmsg syscall instead of one recvfrom per packet. Raced against
            // `refreshed` so a refresh wakes this immediately instead of leaving it
            // blocked on a socket that a sibling task already replaced — see
            // `trigger_refresh`'s docs for why a UDP failure can be otherwise silent.
            let received = tokio::select! {
                r = socket.async_io(tokio::io::Interest::READABLE, || batch.recv(fd)) => r,
                _ = self.refreshed.notified() => continue,
            };
            let received = match received {
                Ok(n) => n,
                // ICMP unreachable for this connected upstream surfaces as a socket
                // error. Drain the IP_RECVERR queue and keep going — a dead/unreachable
                // upstream must not tear down the recv loop (the send path already fails
                // fast and triggers banded failover). Other errors are still fatal.
                Err(e) if is_icmp_unreachable(&e) => {
                    drain_error_queue(fd);
                    continue;
                }
                Err(e) => return Err(e.into()),
            };
            for i in 0..received {
                // `None` = the datagram was truncated to the slot size (oversized);
                // skip it, the waiter falls back to its timeout.
                let Some(packet) = batch.message(i) else {
                    continue;
                };
                match self.inflight.complete(packet) {
                    Completion::Delivered => {
                        recv_count += 1;
                        // Yield every 100 dispatched responses to prevent monopolizing
                        // the Tokio worker during sustained bursts.
                        if recv_count >= 100 {
                            recv_count = 0;
                            tokio::task::yield_now().await;
                        }
                    }
                    Completion::Mismatch(_id) => {}
                    Completion::NoWaiter => {}
                }
            }
        }
    }
}

/// Bind, mark, and connect one UDP socket to `remote`. Shared by initial pool
/// creation and `UdpUpstream::do_refresh`.
async fn open_socket(
    remote: SocketAddr,
    buf_size: usize,
    mark: Option<u32>,
    name: &str,
) -> Result<Arc<UdpSocket>> {
    let bind = if remote.is_ipv6() {
        "[::]:0"
    } else {
        "0.0.0.0:0"
    };
    let socket = UdpSocket::bind(bind)
        .await
        .with_context(|| format!("upstream {name} udp bind failed: {bind}"))?;
    // SO_MARK before connect so every datagram on this socket carries the fwmark.
    if let Some(m) = mark {
        super::set_so_mark(socket.as_raw_fd(), m).with_context(|| format!("upstream {name}"))?;
    }
    // IP_RECVERR: deliver ICMP errors (e.g. port/host unreachable for a dead
    // upstream) to the socket error queue with full classification, so the
    // recv loop can drain and survive them instead of being torn down.
    set_recverr(socket.as_raw_fd(), remote.is_ipv6());
    socket
        .connect(remote)
        .await
        .with_context(|| format!("upstream {name} udp connect failed: {remote}"))?;
    super::set_socket_buf_size(&socket, buf_size);
    Ok(Arc::new(socket))
}

/// Drain a socket's outbound query queue, coalescing ready queries into one
/// `sendmmsg` per wakeup (connected socket → no per-message address). On a send
/// error the remaining queries are dropped and fall back to their per-query
/// timeout — the same outcome a synchronous send error produced before.
async fn send_flush_loop(socket: Arc<UdpSocket>, rx: tokio::sync::mpsc::Receiver<Bytes>) {
    crate::udp_send::run_send_flush_loop(
        &socket,
        rx,
        SEND_BATCH,
        |batch, fd, items: &[Bytes]| batch.send_connected(fd, items.iter().map(|b| b.as_ref())),
        |_dropped| {},
    )
    .await;
}

/// Enable `IP_RECVERR` (or `IPV6_RECVERR`) so ICMP errors are queued with full
/// `sock_extended_err` classification rather than only surfacing as a bare errno.
/// Best-effort.
fn set_recverr(fd: libc::c_int, is_ipv6: bool) {
    let (level, opt) = if is_ipv6 {
        (libc::IPPROTO_IPV6, libc::IPV6_RECVERR)
    } else {
        (libc::IPPROTO_IP, libc::IP_RECVERR)
    };
    let on: libc::c_int = 1;
    let _ = sys::set_socket_i32(fd, level, opt, on);
}

/// Errno values a connected UDP socket reports when the kernel received an ICMP
/// unreachable for the upstream — destination problems that must not kill the recv loop.
fn is_icmp_unreachable(e: &std::io::Error) -> bool {
    matches!(
        e.raw_os_error(),
        Some(libc::ECONNREFUSED) | Some(libc::EHOSTUNREACH) | Some(libc::ENETUNREACH)
    )
}

/// Drain and discard every pending entry from the socket error queue (populated by
/// IP_RECVERR); without this they would accumulate. Returns the count drained.
fn drain_error_queue(fd: libc::c_int) -> u32 {
    let mut drained = 0u32;
    let mut data = [0u8; 64];
    let mut control = [0u8; 256];
    loop {
        if sys::recv_error_queue(fd, &mut data, &mut control).is_err() {
            break; // EAGAIN: queue empty
        }
        drained += 1;
    }
    drained
}
