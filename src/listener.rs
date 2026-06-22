//! Linux SO_REUSEPORT sharded UDP/TCP listener sockets.
//!
//! On Linux, `serve_udp` and `serve_tcp` each bind `worker_threads` SO_REUSEPORT sockets
//! and run them in a `JoinSet`. The kernel distributes incoming packets/connections across
//! the socket group with no central bottleneck.
//!
//! UDP receive uses io_uring multishot recvmsg (`udp_uring`); sends are batched with
//! sendmmsg (`udp_send`). Cache hits and filter hits are batched into one sendmmsg call.
//! Only cache misses spawn a task for full async upstream resolution.
//! TCP connections are handled per-connection in a spawned task that calls `handle_packet`.

use crate::resolver::{handle_packet_slow_preparsed, try_fast_path_into, FastPathOutcome};
use crate::server::AppState;
use crate::sys;
use crate::upstream::{set_raw_socket_buf_size, ClientProto};
use anyhow::{anyhow, Context, Result};
use bytes::{Bytes, BytesMut};
use std::net::SocketAddr;
use std::os::fd::{AsRawFd, OwnedFd};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::{Mutex, OwnedSemaphorePermit};
use tokio::task::JoinSet;

/// Bind `worker_threads` SO_REUSEPORT UDP sockets and race them in a `JoinSet`.
///
/// `iface` — when `Some`, each socket is additionally bound to that network
/// interface via `SO_BINDTODEVICE` so the kernel discards packets from other
/// interfaces before they reach userspace.
pub async fn serve_udp(bind: SocketAddr, iface: Option<&str>, state: Arc<AppState>) -> Result<()> {
    let (buf_size, n, batch_size) = {
        let hot = state.hot.load();
        (
            hot.cfg.udp_buf_size,
            hot.cfg.worker_threads.max(1),
            crate::udp_send::BATCH_SIZE,
        )
    };
    let mut sockets = Vec::with_capacity(n);
    for _ in 0..n {
        sockets.push(Arc::new(
            bind_udp_socket_reuse_port(bind, buf_size, iface)
                .with_context(|| format!("failed to bind UDP on {bind}"))?,
        ));
    }
    let addr = sockets[0].local_addr()?;
    // io_uring multishot recvmsg is a hard requirement — there is no recvmmsg
    // fallback. Fail fast with a clear message if the kernel is too old.
    if !crate::udp_uring::supported() {
        return Err(anyhow!(
            "io_uring multishot recvmsg is unavailable — pathdns requires Linux 6.0+ \
             (see README). No recvmmsg fallback is built."
        ));
    }
    if n == 1 {
        if let Some(iface) = iface {
            crate::startup!("listen udp://{} (iface={})", addr, iface);
        } else {
            crate::startup!("listen udp://{}", addr);
        }
        return run_udp_worker(sockets.remove(0), state, batch_size).await;
    }
    if let Some(iface) = iface {
        crate::startup!("listen udp://{} shards={} (iface={})", addr, n, iface);
    } else {
        crate::startup!("listen udp://{} shards={}", addr, n);
    }
    let mut set = JoinSet::new();
    for socket in sockets {
        let s = state.clone();
        set.spawn(run_udp_worker(socket, s, batch_size));
    }
    match set.join_next().await {
        Some(Ok(r)) => r,
        Some(Err(e)) => Err(anyhow!("udp shard panicked: {e}")),
        None => Ok(()),
    }
}

/// Run one UDP shard on the io_uring multishot-recvmsg receive path. Kernel support
/// is verified up front by the caller, so this never falls back.
async fn run_udp_worker(
    socket: Arc<UdpSocket>,
    state: Arc<AppState>,
    batch_size: usize,
) -> Result<()> {
    crate::udp_uring::serve_udp_uring(socket, state, batch_size).await
}

/// Bind `worker_threads` SO_REUSEPORT TCP listeners and race them in a `JoinSet`.
///
/// `iface` — when `Some`, each listener socket is additionally bound to that
/// network interface via `SO_BINDTODEVICE`.
pub async fn serve_tcp(bind: SocketAddr, iface: Option<&str>, state: Arc<AppState>) -> Result<()> {
    let n = state.hot.load().cfg.worker_threads.max(1);
    let mut listeners = Vec::with_capacity(n);
    for _ in 0..n {
        listeners.push(Arc::new(
            bind_tcp_listener_reuse_port(bind, iface)
                .with_context(|| format!("failed to bind TCP on {bind}"))?,
        ));
    }
    let addr = listeners[0].local_addr()?;
    if n == 1 {
        if let Some(iface) = iface {
            crate::startup!("listen tcp://{} (iface={})", addr, iface);
        } else {
            crate::startup!("listen tcp://{}", addr);
        }
        return serve_tcp_listener(listeners.remove(0), state).await;
    }
    if let Some(iface) = iface {
        crate::startup!("listen tcp://{} shards={} (iface={})", addr, n, iface);
    } else {
        crate::startup!("listen tcp://{} shards={}", addr, n);
    }
    let mut set = JoinSet::new();
    for listener in listeners {
        let s = state.clone();
        set.spawn(serve_tcp_listener(listener, s));
    }
    match set.join_next().await {
        Some(Ok(r)) => r,
        Some(Err(e)) => Err(anyhow!("tcp shard panicked: {e}")),
        None => Ok(()),
    }
}

async fn serve_tcp_listener(listener: Arc<TcpListener>, state: Arc<AppState>) -> Result<()> {
    loop {
        let (stream, peer) = listener.accept().await?;
        // Acquire a connection slot before spawning. When the limit is reached, drop
        // the stream immediately (RST) rather than leaving clients waiting.
        let conn_permit: Option<OwnedSemaphorePermit> = if let Some(sem) = &state.tcp_conn_limit {
            match sem.clone().try_acquire_owned() {
                Ok(p) => Some(p),
                Err(_) => continue, // stream dropped here → client receives RST
            }
        } else {
            None
        };
        let state = state.clone();
        tokio::spawn(async move {
            let _ = handle_tcp_conn(stream, peer, state, conn_permit).await;
        });
    }
}

async fn handle_tcp_conn(
    stream: TcpStream,
    peer: std::net::SocketAddr,
    state: Arc<AppState>,
    // Held for the lifetime of this connection; drop releases the slot.
    _conn_permit: Option<OwnedSemaphorePermit>,
) -> Result<()> {
    // Disable Nagle so the 2-byte length prefix and response body are not
    // buffered waiting to fill a segment — critical for DNS response latency.
    let _ = stream.set_nodelay(true);

    let (idle_timeout, read_timeout) = {
        let hot = state.hot.load();
        let idle = (hot.cfg.tcp_idle_timeout_ms > 0)
            .then(|| Duration::from_millis(hot.cfg.tcp_idle_timeout_ms));
        let read = (hot.cfg.tcp_read_timeout_ms > 0)
            .then(|| Duration::from_millis(hot.cfg.tcp_read_timeout_ms));
        (idle, read)
    };

    // Split into independent read and write halves so that slow-path queries
    // (cache misses that need upstream resolution) can be resolved concurrently
    // without blocking the read loop from accepting the next query.
    let (mut read_half, write_half) = stream.into_split();
    let write_half = Arc::new(Mutex::new(write_half));

    // Pre-allocate per-connection buffers reused across fast-path requests.
    let mut resp_buf = BytesMut::with_capacity(512);
    let mut packet_buf = vec![0u8; 512]; // grown on demand, never shrunk
    let mut framing_buf = Vec::<u8>::with_capacity(514); // 2-byte length prefix + response body

    loop {
        // Wait for the 2-byte length prefix, applying the idle timeout.
        // This also catches the "1-byte stall" attack: a client that sends
        // only the first byte of the header is evicted when the timeout fires.
        let mut len_buf = [0u8; 2];
        let len_result = match idle_timeout {
            None => read_half.read_exact(&mut len_buf).await,
            Some(t) => {
                match tokio::time::timeout(t, read_half.read_exact(&mut len_buf)).await {
                    Ok(r) => r,
                    Err(_elapsed) => return Ok(()), // idle timeout — close cleanly
                }
            }
        };
        match len_result {
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(()),
            Err(_) => return Ok(()),
        }

        let len = u16::from_be_bytes(len_buf) as usize;
        if len == 0 {
            continue;
        }

        // Read the message body into the reusable packet buffer (no per-request malloc).
        if packet_buf.len() < len {
            packet_buf.resize(len, 0);
        }
        let body_result = match read_timeout {
            None => read_half.read_exact(&mut packet_buf[..len]).await,
            Some(t) => {
                match tokio::time::timeout(t, read_half.read_exact(&mut packet_buf[..len])).await {
                    Ok(r) => r,
                    Err(_elapsed) => return Ok(()), // body read stalled — close
                }
            }
        };
        if body_result.is_err() {
            return Ok(());
        }

        let pkt = &packet_buf[..len];

        // Try the synchronous fast path (cache hit) before the full async resolver.
        // On a warm cache this avoids any heap allocation or task spawn.
        resp_buf.clear();
        match try_fast_path_into(pkt, peer, &state, &mut resp_buf) {
            FastPathOutcome::Response { resp } => {
                let mut w = write_half.lock().await;
                if write_tcp_response(&mut *w, &resp, &mut framing_buf)
                    .await
                    .is_err()
                {
                    return Ok(());
                }
            }
            FastPathOutcome::Drop => {}
            FastPathOutcome::Miss { info } => {
                // Spawn a concurrent task so the read loop continues immediately
                // rather than blocking until upstream resolution completes.
                let packet = Bytes::copy_from_slice(pkt);
                let write = Arc::clone(&write_half);
                let state2 = state.clone();
                tokio::spawn(async move {
                    if let Ok(Some(resp)) = handle_packet_slow_preparsed(
                        packet,
                        peer,
                        ClientProto::Tcp,
                        state2,
                        info,
                        None,
                    )
                    .await
                    {
                        let mut framing = Vec::with_capacity(resp.len() + 2);
                        let mut w = write.lock().await;
                        let _ = write_tcp_response(&mut *w, &resp, &mut framing).await;
                    }
                });
            }
        }
    }
}

async fn write_tcp_response<W: AsyncWriteExt + Unpin>(
    writer: &mut W,
    resp: &[u8],
    framing_buf: &mut Vec<u8>,
) -> Result<()> {
    let len = u16::try_from(resp.len()).map_err(|_| anyhow!("dns response too large for tcp"))?;
    // Combine the 2-byte length prefix and response body into one write_all so
    // the kernel sees a single writev — halves the syscall count per response.
    // No flush needed: TcpStream has no userspace write buffer, and TCP_NODELAY
    // ensures the kernel sends immediately without waiting to fill a segment.
    framing_buf.clear();
    framing_buf.extend_from_slice(&len.to_be_bytes());
    framing_buf.extend_from_slice(resp);
    writer.write_all(framing_buf).await?;
    Ok(())
}

fn bind_udp_socket_reuse_port(
    addr: SocketAddr,
    buf_size: usize,
    iface: Option<&str>,
) -> Result<UdpSocket> {
    let fd = create_reuse_port_socket(addr, libc::SOCK_DGRAM, iface)?;
    sys::bind_inet(fd.as_raw_fd(), addr).context("failed to bind reuse-port socket")?;
    set_raw_socket_buf_size(fd.as_raw_fd(), buf_size);
    // Best-effort socket-level cmsgs delivered with every datagram:
    //  - SO_RXQ_OVFL:    cumulative receive-buffer overflow drop count (kernel RX drops)
    //  - SO_TIMESTAMPNS: kernel receive timestamp, for kernel→userspace recv latency
    let yes: libc::c_int = 1;
    for opt in [libc::SO_RXQ_OVFL, libc::SO_TIMESTAMPNS] {
        let _ = sys::set_socket_i32(fd.as_raw_fd(), libc::SOL_SOCKET, opt, yes);
    }
    let socket = std::net::UdpSocket::from(fd);
    socket.set_nonblocking(true)?;
    UdpSocket::from_std(socket).map_err(Into::into)
}

/// Bind a TCP listener with deterministic IPv6 behaviour (IPV6_V6ONLY set).
/// Used by the dashboard HTTP API. `iface` is applied via SO_BINDTODEVICE when set.
pub fn bind_tcp_listener(addr: SocketAddr, iface: Option<&str>) -> Result<TcpListener> {
    bind_tcp_listener_reuse_port(addr, iface)
}

fn bind_tcp_listener_reuse_port(addr: SocketAddr, iface: Option<&str>) -> Result<TcpListener> {
    let fd = create_reuse_port_socket(addr, libc::SOCK_STREAM, iface)?;
    sys::bind_inet(fd.as_raw_fd(), addr).context("failed to bind reuse-port socket")?;
    let backlog = 1024;
    sys::listen(fd.as_raw_fd(), backlog).context("failed to listen on reuse-port tcp socket")?;
    let listener = std::net::TcpListener::from(fd);
    listener.set_nonblocking(true)?;
    TcpListener::from_std(listener).map_err(Into::into)
}

fn create_reuse_port_socket(
    addr: SocketAddr,
    ty: libc::c_int,
    iface: Option<&str>,
) -> Result<OwnedFd> {
    let domain = if addr.is_ipv6() {
        libc::AF_INET6
    } else {
        libc::AF_INET
    };
    let fd = sys::socket(domain, ty, 0).context("failed to create socket")?;
    let yes: libc::c_int = 1;
    for (name, opt) in [
        ("SO_REUSEADDR", libc::SO_REUSEADDR),
        ("SO_REUSEPORT", libc::SO_REUSEPORT),
    ] {
        sys::set_socket_i32(fd.as_raw_fd(), libc::SOL_SOCKET, opt, yes)
            .with_context(|| format!("failed to set {name}"))?;
    }
    // IP_FREEBIND: allow binding to an address not yet configured on any interface.
    // On a router, pathdns can start before the LAN/WAN address is up (DHCP, PPPoE,
    // boot ordering) and still bind its listen address. Best-effort — the kernel
    // option value is shared by v4 and v6 sockets.
    let _ = sys::set_socket_i32(fd.as_raw_fd(), libc::IPPROTO_IP, libc::IP_FREEBIND, yes);
    // Explicit IPV6_V6ONLY so behaviour does not depend on the system-wide
    // net.ipv6.bindv6only sysctl: a v6 bind serves v6 only, and dual-stack is
    // configured deliberately with `"bind": ["0.0.0.0:53", "[::]:53"]`.
    // This also avoids an unpredictable v4-traffic split between a 0.0.0.0
    // REUSEPORT group and a dual-stack [::] socket on the same port.
    if addr.is_ipv6() {
        sys::set_socket_i32(
            fd.as_raw_fd(),
            libc::IPPROTO_IPV6,
            libc::IPV6_V6ONLY,
            yes,
        )
        .context("failed to set IPV6_V6ONLY")?;
    }
    if let Some(name) = iface {
        set_bindtodevice(fd.as_raw_fd(), name).with_context(|| {
            format!(
                "failed to bind socket to interface {name:?} (requires root or CAP_NET_RAW)"
            )
        })?;
    }
    Ok(fd)
}

/// Apply `SO_BINDTODEVICE` to restrict the socket to a specific network interface.
/// Requires `CAP_NET_RAW` or root privileges.
fn set_bindtodevice(fd: libc::c_int, iface: &str) -> std::io::Result<()> {
    let name = sys::interface_cstring(iface)?;
    sys::set_socket_option_bytes(
        fd,
        libc::SOL_SOCKET,
        libc::SO_BINDTODEVICE,
        name.as_bytes_with_nul(),
    )
}

/// Enumerate all network interface names present on this host.
/// Used to resolve `InterfaceFilter::Except` at startup.
pub fn list_interface_names() -> std::io::Result<Vec<String>> {
    sys::interface_names()
}
