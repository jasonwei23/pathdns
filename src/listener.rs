#![cfg(unix)]
//! Linux SO_REUSEPORT sharded UDP/TCP listener sockets.
//!
//! On Linux, `serve_udp` and `serve_tcp` each bind `worker_threads` SO_REUSEPORT sockets
//! and run them in a `JoinSet`. The kernel distributes incoming packets/connections across
//! the socket group with no central bottleneck.
//!
//! UDP fast path: `serve_udp_socket` calls `pipeline::try_fast_path` inline (no `tokio::spawn`)
//! for every packet. Cache hits and filter hits are processed and sent back without ever
//! allocating a Tokio task. Only cache misses spawn a task for full async upstream resolution.
//! TCP connections are handled per-connection in a spawned task that calls `handle_packet`.

use crate::pipeline::{
    handle_packet_bytes, handle_packet_slow_preparsed, spawn_cache_refresh, try_fast_path_into,
    FastPathOutcome,
};
use crate::dns;
use crate::server::AppState;
use crate::upstream::{set_raw_socket_buf_size, ClientProto};
use anyhow::{anyhow, Context, Result};
use bytes::BytesMut;
use std::net::SocketAddr;
use std::os::fd::FromRawFd;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::OwnedSemaphorePermit;
use tokio::task::JoinSet;

const MAX_DNS_MESSAGE: usize = u16::MAX as usize;

/// Bind `worker_threads` SO_REUSEPORT UDP sockets and race them in a `JoinSet`.
pub async fn serve_udp(bind: SocketAddr, state: Arc<AppState>) -> Result<()> {
    let buf_size = state.cfg.udp_buf_size;
    let n = state.cfg.worker_threads.max(1);
    let mut sockets = Vec::with_capacity(n);
    for _ in 0..n {
        sockets.push(Arc::new(
            bind_udp_socket_reuse_port(bind, buf_size)
                .with_context(|| format!("failed to bind UDP on {bind}"))?,
        ));
    }
    let addr = sockets[0].local_addr()?;
    if n == 1 {
        crate::startup!("listen udp://{}", addr);
        return serve_udp_socket(sockets.remove(0), state).await;
    }
    crate::startup!("listen udp://{} shards={}", addr, n);
    let mut set = JoinSet::new();
    for socket in sockets {
        let s = state.clone();
        set.spawn(serve_udp_socket(socket, s));
    }
    match set.join_next().await {
        Some(Ok(r)) => r,
        Some(Err(e)) => Err(anyhow!("udp shard panicked: {e}")),
        None => Ok(()),
    }
}

/// Bind `worker_threads` SO_REUSEPORT TCP listeners and race them in a `JoinSet`.
pub async fn serve_tcp(bind: SocketAddr, state: Arc<AppState>) -> Result<()> {
    let n = state.cfg.worker_threads.max(1);
    let mut listeners = Vec::with_capacity(n);
    for _ in 0..n {
        listeners.push(Arc::new(
            bind_tcp_listener_reuse_port(bind)
                .with_context(|| format!("failed to bind TCP on {bind}"))?,
        ));
    }
    let addr = listeners[0].local_addr()?;
    if n == 1 {
        crate::startup!("listen tcp://{}", addr);
        return serve_tcp_listener(listeners.remove(0), state).await;
    }
    crate::startup!("listen tcp://{} shards={}", addr, n);
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

async fn serve_udp_socket(socket: Arc<UdpSocket>, state: Arc<AppState>) -> Result<()> {
    let mut recv_buf = BytesMut::with_capacity(MAX_DNS_MESSAGE);
    let mut send_buf = BytesMut::with_capacity(4096);
    loop {
        recv_buf.clear();
        let (_n, peer) = socket.recv_buf_from(&mut recv_buf).await?;

        match try_fast_path_into(&recv_buf, peer, &state, &mut send_buf) {
            FastPathOutcome::Response { resp, refresh } => {
                if let Some(r) = refresh {
                    spawn_cache_refresh(r, &state);
                }
                // Enforce the client's EDNS UDP payload limit (512 for non-EDNS).
                let resp = crate::dns::maybe_truncate_for_udp(resp, &recv_buf);
                // Try non-blocking send first; only spawn if the kernel buffer is momentarily full.
                if let Err(e) = socket.try_send_to(&resp, peer) {
                    if e.kind() == std::io::ErrorKind::WouldBlock {
                        let socket = socket.clone();
                        tokio::spawn(async move {
                            let _ = socket.send_to(&resp, peer).await;
                        });
                    }
                }
            }
            FastPathOutcome::Drop => {}
            FastPathOutcome::Miss { info } => {
                // Acquire the inflight semaphore permit BEFORE spawning to bound the number
                // of in-flight tasks. Without this, a UDP flood creates unlimited waiting
                // tasks that consume memory even while the semaphore is saturated.
                let permit = match state.limit.clone().try_acquire_owned() {
                    Ok(p) => p,
                    Err(_) => {
                        // Semaphore full: reply with SERVFAIL immediately, do not spawn.
                        state
                            .querylog
                            .counters
                            .inflight_drops
                            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        if let Ok(sf) = dns::servfail_reply(&recv_buf, info.question_end) {
                            let _ = socket.try_send_to(&sf, peer);
                        }
                        continue;
                    }
                };
                // Cache miss: upstream resolution is async I/O, spawn a task for it.
                // Materialize the packet only for the async slow path; cache/filter hits
                // are answered directly from the reusable BytesMut receive buffer.
                let packet =
                    std::mem::replace(&mut recv_buf, BytesMut::with_capacity(MAX_DNS_MESSAGE))
                        .freeze();
                let state = state.clone();
                let socket = socket.clone();
                tokio::spawn(async move {
                    // Clone is O(1) (Bytes refcount bump); needed to enforce UDP size after
                    // handle_packet_slow_preparsed takes ownership of `packet`.
                    let query = packet.clone();
                    match handle_packet_slow_preparsed(
                        packet,
                        peer,
                        ClientProto::Udp,
                        state,
                        info,
                        Some(permit),
                    )
                    .await
                    {
                        Ok(Some(resp)) => {
                            let resp = crate::dns::maybe_truncate_for_udp(resp, &query);
                            let _ = socket.send_to(&resp, peer).await;
                        }
                        Ok(None) => {}
                        Err(_) => {}
                    }
                });
            }
        }
    }
}

async fn serve_tcp_listener(listener: Arc<TcpListener>, state: Arc<AppState>) -> Result<()> {
    loop {
        let (stream, peer) = listener.accept().await?;
        // Acquire a connection slot before spawning. When the limit is reached, drop
        // the stream immediately (RST) rather than leaving clients waiting.
        let conn_permit: Option<OwnedSemaphorePermit> =
            if let Some(sem) = &state.tcp_conn_limit {
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
    mut stream: TcpStream,
    peer: std::net::SocketAddr,
    state: Arc<AppState>,
    // Held for the lifetime of this connection; drop releases the slot.
    _conn_permit: Option<OwnedSemaphorePermit>,
) -> Result<()> {
    let idle_timeout = (state.cfg.tcp_idle_timeout_ms > 0)
        .then(|| Duration::from_millis(state.cfg.tcp_idle_timeout_ms));
    let read_timeout = (state.cfg.tcp_read_timeout_ms > 0)
        .then(|| Duration::from_millis(state.cfg.tcp_read_timeout_ms));

    loop {
        // Wait for the 2-byte length prefix, applying the idle timeout.
        // This also catches the "1-byte stall" attack: a client that sends
        // only the first byte of the header is evicted when the timeout fires.
        let mut len_buf = [0u8; 2];
        let len_result = match idle_timeout {
            None => stream.read_exact(&mut len_buf).await,
            Some(t) => {
                match tokio::time::timeout(t, stream.read_exact(&mut len_buf)).await {
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

        // Read the message body, applying the frame-read timeout.
        let mut packet = BytesMut::zeroed(len);
        let body_result = match read_timeout {
            None => stream.read_exact(&mut packet).await,
            Some(t) => {
                match tokio::time::timeout(t, stream.read_exact(&mut packet)).await {
                    Ok(r) => r,
                    Err(_elapsed) => return Ok(()), // body read stalled — close
                }
            }
        };
        if body_result.is_err() {
            return Ok(());
        }

        match handle_packet_bytes(packet.freeze(), peer, ClientProto::Tcp, state.clone()).await {
            Ok(Some(resp)) => write_tcp_response(&mut stream, &resp).await?,
            Ok(None) => {}
            Err(_) => return Ok(()),
        }
    }
}

async fn write_tcp_response(stream: &mut TcpStream, resp: &[u8]) -> Result<()> {
    let len = u16::try_from(resp.len()).map_err(|_| anyhow!("dns response too large for tcp"))?;
    stream.write_all(&len.to_be_bytes()).await?;
    stream.write_all(resp).await?;
    stream.flush().await?;
    Ok(())
}

fn bind_udp_socket_reuse_port(addr: SocketAddr, buf_size: usize) -> Result<UdpSocket> {
    let fd = create_reuse_port_socket(addr, libc::SOCK_DGRAM)?;
    bind_raw_socket(fd, addr)?;
    set_raw_socket_buf_size(fd, buf_size);
    let socket = unsafe { std::net::UdpSocket::from_raw_fd(fd) };
    socket.set_nonblocking(true)?;
    UdpSocket::from_std(socket).map_err(Into::into)
}

/// Bind a TCP listener with deterministic IPv6 behaviour (IPV6_V6ONLY set).
/// Also used by the dashboard HTTP API so that a dual-stack bind array like
/// `["0.0.0.0:8080", "[::]:8080"]` never conflicts on systems where
/// net.ipv6.bindv6only is 0.
pub fn bind_tcp_listener(addr: SocketAddr) -> Result<TcpListener> {
    bind_tcp_listener_reuse_port(addr)
}

fn bind_tcp_listener_reuse_port(addr: SocketAddr) -> Result<TcpListener> {
    let fd = create_reuse_port_socket(addr, libc::SOCK_STREAM)?;
    bind_raw_socket(fd, addr)?;
    let backlog = 1024;
    if unsafe { libc::listen(fd, backlog) } < 0 {
        let err = std::io::Error::last_os_error();
        unsafe { libc::close(fd) };
        return Err(err).context("failed to listen on reuse-port tcp socket");
    }
    let listener = unsafe { std::net::TcpListener::from_raw_fd(fd) };
    listener.set_nonblocking(true)?;
    TcpListener::from_std(listener).map_err(Into::into)
}

fn create_reuse_port_socket(addr: SocketAddr, ty: libc::c_int) -> Result<libc::c_int> {
    let domain = if addr.is_ipv6() {
        libc::AF_INET6
    } else {
        libc::AF_INET
    };
    let fd = unsafe { libc::socket(domain, ty, 0) };
    if fd < 0 {
        return Err(std::io::Error::last_os_error()).context("failed to create socket");
    }
    let yes: libc::c_int = 1;
    for (name, opt) in [
        ("SO_REUSEADDR", libc::SO_REUSEADDR),
        ("SO_REUSEPORT", libc::SO_REUSEPORT),
    ] {
        if unsafe {
            libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                opt,
                &yes as *const _ as *const libc::c_void,
                std::mem::size_of_val(&yes) as libc::socklen_t,
            )
        } < 0
        {
            let err = std::io::Error::last_os_error();
            unsafe { libc::close(fd) };
            return Err(err).with_context(|| format!("failed to set {name}"));
        }
    }
    // Explicit IPV6_V6ONLY so behaviour does not depend on the system-wide
    // net.ipv6.bindv6only sysctl: a v6 bind serves v6 only, and dual-stack is
    // configured deliberately with `"bind": ["0.0.0.0:53", "[::]:53"]`.
    // This also avoids an unpredictable v4-traffic split between a 0.0.0.0
    // REUSEPORT group and a dual-stack [::] socket on the same port.
    if addr.is_ipv6()
        && unsafe {
            libc::setsockopt(
                fd,
                libc::IPPROTO_IPV6,
                libc::IPV6_V6ONLY,
                &yes as *const _ as *const libc::c_void,
                std::mem::size_of_val(&yes) as libc::socklen_t,
            )
        } < 0
    {
        let err = std::io::Error::last_os_error();
        unsafe { libc::close(fd) };
        return Err(err).context("failed to set IPV6_V6ONLY");
    }
    Ok(fd)
}

fn bind_raw_socket(fd: libc::c_int, addr: SocketAddr) -> Result<()> {
    let result = match addr {
        SocketAddr::V4(addr) => {
            let octets = addr.ip().octets();
            let raw = libc::sockaddr_in {
                sin_family: libc::AF_INET as libc::sa_family_t,
                sin_port: addr.port().to_be(),
                sin_addr: libc::in_addr {
                    s_addr: u32::from_ne_bytes(octets),
                },
                sin_zero: [0; 8],
            };
            unsafe {
                libc::bind(
                    fd,
                    &raw as *const _ as *const libc::sockaddr,
                    std::mem::size_of_val(&raw) as libc::socklen_t,
                )
            }
        }
        SocketAddr::V6(addr) => {
            let raw = libc::sockaddr_in6 {
                sin6_family: libc::AF_INET6 as libc::sa_family_t,
                sin6_port: addr.port().to_be(),
                sin6_flowinfo: addr.flowinfo(),
                sin6_addr: libc::in6_addr {
                    s6_addr: addr.ip().octets(),
                },
                sin6_scope_id: addr.scope_id(),
            };
            unsafe {
                libc::bind(
                    fd,
                    &raw as *const _ as *const libc::sockaddr,
                    std::mem::size_of_val(&raw) as libc::socklen_t,
                )
            }
        }
    };
    if result < 0 {
        let err = std::io::Error::last_os_error();
        unsafe { libc::close(fd) };
        Err(err).context("failed to bind reuse-port socket")
    } else {
        Ok(())
    }
}
