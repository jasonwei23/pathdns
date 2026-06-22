use super::inflight::{Completion, InflightRegistry};
use super::{apply_ecs_mode, tcp_exchange_packet, UpstreamRequest};
use crate::config::EcsMode;
use crate::dns;
use crate::sys;
use anyhow::{anyhow, Context, Result};
use bytes::{Bytes, BytesMut};
use std::net::SocketAddr;
use std::os::unix::io::AsRawFd;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::UdpSocket;

const MAX_DNS_MESSAGE: usize = u16::MAX as usize;

pub(super) struct UdpUpstream {
    pub(super) name: String,
    remote: SocketAddr,
    sockets: Vec<Arc<UdpSocket>>,
    send_idx: AtomicUsize,
    timeout: Duration,
    inflight: InflightRegistry,
    ecs_mode: EcsMode,
    /// fwmark reused for the TC-bit TCP fallback so it routes like the UDP socket.
    mark: Option<u32>,
}

impl UdpUpstream {
    /// Create a pool of `pool_size` sockets, spawn one recv loop per socket.
    #[allow(clippy::too_many_arguments)]
    pub(super) async fn create(
        name: String,
        remote: SocketAddr,
        timeout: Duration,
        pool_size: usize,
        buf_size: usize,
        max_inflight: usize,
        ecs_mode: EcsMode,
        mark: Option<u32>,
    ) -> Result<Arc<Self>> {
        let bind = if remote.is_ipv6() {
            "[::]:0"
        } else {
            "0.0.0.0:0"
        };
        let mut sockets = Vec::with_capacity(pool_size);
        for _ in 0..pool_size {
            let socket = UdpSocket::bind(bind)
                .await
                .with_context(|| format!("upstream {name} udp bind failed: {bind}"))?;
            // SO_MARK before connect so every datagram on this socket carries the fwmark.
            if let Some(m) = mark {
                super::set_so_mark(socket.as_raw_fd(), m)
                    .with_context(|| format!("upstream {name}"))?;
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
            sockets.push(Arc::new(socket));
        }
        let upstream = Arc::new(Self {
            name,
            remote,
            sockets,
            send_idx: AtomicUsize::new(0),
            timeout,
            inflight: InflightRegistry::new(max_inflight),
            ecs_mode,
            mark,
        });
        for i in 0..upstream.sockets.len() {
            let u = upstream.clone();
            tokio::spawn(async move {
                let mut delay_ms = 50u64;
                while let Err(err) = u.clone().recv_loop(i).await {
                    crate::log_error!(
                        "upstream name={} event=recv_loop_exit error={err:#} restarting_in={delay_ms}ms",
                        u.name
                    );
                    tokio::time::sleep(Duration::from_millis(delay_ms)).await;
                    delay_ms = (delay_ms * 2).min(5_000);
                }
            });
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

        // Apply 0x20 QNAME case mixing.
        let q_end = 12 + question.len();
        let seed_0x20 = upstream_id as u64
            ^ (std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.subsec_micros() as u64)
                .unwrap_or(0));
        dns::mix_qname_case(&mut packet, q_end, seed_0x20);

        let socket_idx = self.send_idx.fetch_add(1, Ordering::Relaxed) % self.sockets.len();
        let socket = &self.sockets[socket_idx];

        if let Err(err) = socket.send(&packet).await {
            return Err(err.into());
        }

        match tokio::time::timeout(self.timeout, rx).await {
            Ok(Ok(resp)) => {
                // Verify 0x20 case echo before checking TC.
                if let Some(resp_qend) = dns::question_end(&resp) {
                    if !dns::verify_qname_case_echo(packet.as_ref(), q_end, &resp, resp_qend) {
                        return Err(anyhow!(
                            "upstream {}: 0x20 QNAME case mismatch (possible spoof)",
                            self.name
                        ));
                    }
                }
                if dns::is_truncated(&resp) {
                    match tcp_exchange_packet(self.remote, &packet, self.timeout, &self.name, self.mark).await
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

    async fn recv_loop(self: Arc<Self>, socket_idx: usize) -> Result<()> {
        let socket = &self.sockets[socket_idx];
        let fd = socket.as_raw_fd();
        let mut buf = BytesMut::with_capacity(MAX_DNS_MESSAGE);
        let mut recv_count = 0u32;
        loop {
            buf.clear();
            if buf.capacity() < MAX_DNS_MESSAGE {
                buf.reserve(MAX_DNS_MESSAGE - buf.capacity());
            }
            let n = match socket.recv_buf(&mut buf).await {
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
            match self.inflight.complete(&mut buf, n) {
                Completion::Delivered => {
                    recv_count += 1;
                    // Yield every 100 dispatched responses to prevent monopolizing the Tokio
                    // worker during burst periods where many responses arrive back-to-back.
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn icmp_unreachable_classification() {
        use std::io::Error;
        assert!(is_icmp_unreachable(&Error::from_raw_os_error(libc::ECONNREFUSED)));
        assert!(is_icmp_unreachable(&Error::from_raw_os_error(libc::EHOSTUNREACH)));
        assert!(is_icmp_unreachable(&Error::from_raw_os_error(libc::ENETUNREACH)));
        assert!(!is_icmp_unreachable(&Error::from_raw_os_error(libc::EAGAIN)));
        assert!(!is_icmp_unreachable(&Error::from_raw_os_error(libc::ECONNRESET)));
    }

    #[test]
    fn ip_recverr_delivers_icmp_to_error_queue() {
        // Connect to a closed loopback port: the kernel returns ICMP port-unreachable,
        // which IP_RECVERR must route to the error queue for drain_error_queue to clear.
        let sock = std::net::UdpSocket::bind(("127.0.0.1", 0)).unwrap();
        let fd = sock.as_raw_fd();
        set_recverr(fd, false);
        sock.connect(("127.0.0.1", 1)).unwrap();
        sock.set_nonblocking(true).unwrap();
        let _ = sock.send(b"x");
        std::thread::sleep(std::time::Duration::from_millis(40));
        // A normal recv reports the ICMP error and our classifier recognises it.
        let mut buf = [0u8; 64];
        if let Err(e) = sock.recv(&mut buf) {
            assert!(
                is_icmp_unreachable(&e),
                "expected ICMP unreachable from closed port, got {e:?}"
            );
        }
        // The error also sits in the error queue; draining must consume it.
        assert!(
            drain_error_queue(fd) >= 1,
            "IP_RECVERR error queue should contain the ICMP error"
        );
    }

    /// The UDP egress socket must carry the configured SO_MARK (read back to verify).
    #[tokio::test]
    async fn udp_upstream_applies_so_mark() {
        if !super::super::so_mark_supported() {
            eprintln!("skipping udp_upstream_applies_so_mark: SO_MARK requires CAP_NET_ADMIN");
            return;
        }
        use std::os::unix::io::AsRawFd;
        // Remote need not exist: UDP connect() just sets the default peer.
        let remote: SocketAddr = "127.0.0.1:9".parse().unwrap();
        let up = UdpUpstream::create(
            "test".to_string(),
            remote,
            Duration::from_secs(1),
            1,
            0,
            0,
            EcsMode::Forward,
            Some(0xabc),
        )
        .await
        .expect("create with mark (needs CAP_NET_ADMIN)");

        let fd = up.sockets[0].as_raw_fd();
        let val = sys::get_socket_u32(fd, libc::SOL_SOCKET, libc::SO_MARK)
            .expect("getsockopt(SO_MARK) failed");
        assert_eq!(val, 0xabc, "UDP upstream socket did not carry the fwmark");
    }
}
