use super::inflight::{Completion, InflightRegistry};
use super::{apply_ecs_mode, tcp_exchange_packet, UpstreamRequest};
use crate::config::EcsMode;
use crate::dns;
use anyhow::{anyhow, Context, Result};
use bytes::{Bytes, BytesMut};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;

pub(super) struct UdpUpstream {
    pub(super) name: String,
    remote: SocketAddr,
    sockets: Vec<Arc<UdpSocket>>,
    send_idx: AtomicUsize,
    timeout: Duration,
    inflight: InflightRegistry,
    ecs_mode: EcsMode,
}

impl UdpUpstream {
    /// Create a pool of `pool_size` sockets, spawn one recv loop per socket.
    pub(super) async fn create(
        name: String,
        remote: SocketAddr,
        timeout: Duration,
        pool_size: usize,
        buf_size: usize,
        max_inflight: usize,
        ecs_mode: EcsMode,
    ) -> Result<Arc<Self>> {
        // buf_size is only consumed by the #[cfg(unix)] set_socket_buf_size call below.
        #[cfg(not(unix))]
        let _ = buf_size;
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
            socket
                .connect(remote)
                .await
                .with_context(|| format!("upstream {name} udp connect failed: {remote}"))?;
            #[cfg(unix)]
            super::set_socket_buf_size(&socket, buf_size);
            sockets.push(Arc::new(socket));
        }
        crate::verbose!("upstream name={name} proto=udp remote={remote} pool={pool_size}");
        let upstream = Arc::new(Self {
            name,
            remote,
            sockets,
            send_idx: AtomicUsize::new(0),
            timeout,
            inflight: InflightRegistry::new(max_inflight),
            ecs_mode,
        });
        for i in 0..upstream.sockets.len() {
            let u = upstream.clone();
            tokio::spawn(async move {
                let mut delay_ms = 50u64;
                while let Err(err) = u.clone().recv_loop(i).await {
                    crate::stats::inc_udp_recv_restart();
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
        let started = Instant::now();
        let raw_packet = apply_ecs_mode(&req.packet, &self.ecs_mode);
        let mut packet = BytesMut::from(raw_packet.as_ref());
        let question = req.question.clone(); // keep a copy for TC-fallback validation
        let (upstream_id, rx, _guard) =
            self.inflight
                .register(&self.name, req.client_id, req.question)?;
        dns::set_id(&mut packet, upstream_id)?;

        let socket_idx = self.send_idx.fetch_add(1, Ordering::Relaxed) % self.sockets.len();
        let socket = &self.sockets[socket_idx];

        if let Err(err) = socket.send(&packet).await {
            crate::verbose!(
                "upstream name={} proto=udp remote={} event=send_failed elapsed_us={} error={err}",
                self.name,
                self.remote,
                started.elapsed().as_micros()
            );
            return Err(err.into());
        }
        crate::verbose!(
            "upstream name={} proto=udp remote={} event=send",
            self.name,
            self.remote
        );

        match tokio::time::timeout(self.timeout, rx).await {
            Ok(Ok(resp)) => {
                if dns::is_truncated(&resp) {
                    crate::stats::inc_tc_fallback();
                    match tcp_exchange_packet(self.remote, &packet, self.timeout, &self.name).await
                    {
                        Ok(mut tcp_resp) => {
                            super::validate_upstream_response(
                                &tcp_resp,
                                upstream_id,
                                &question,
                            )
                            .map_err(|e| {
                                anyhow!("upstream {}: TCP fallback {e}", self.name)
                            })?;
                            dns::set_id(&mut tcp_resp, req.client_id)?;
                            return Ok(Bytes::from(tcp_resp));
                        }
                        Err(err) => {
                            crate::verbose!(
                                "upstream name={} event=tcp_fallback_failed error={err:#}",
                                self.name
                            );
                            return Err(err);
                        }
                    }
                }
                Ok(resp)
            }
            Ok(Err(_closed)) => Err(anyhow!("upstream {} response channel closed", self.name)),
            Err(_elapsed) => {
                crate::verbose!(
                    "upstream name={} proto=udp remote={} event=timeout elapsed_us={}",
                    self.name,
                    self.remote,
                    started.elapsed().as_micros()
                );
                Err(anyhow!("upstream {} timeout: {}", self.name, self.remote))
            }
        }
    }

    async fn recv_loop(self: Arc<Self>, socket_idx: usize) -> Result<()> {
        let socket = &self.sockets[socket_idx];
        let mut buf = BytesMut::with_capacity(4096);
        let mut recv_count = 0u32;
        loop {
            buf.clear();
            if buf.capacity() < 4096 {
                buf.reserve(4096 - buf.capacity());
            }
            let n = socket.recv_buf(&mut buf).await?;
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
                Completion::Mismatch(id) => {
                    crate::verbose!(
                        "upstream name={} proto=udp remote={} event=question_mismatch id={id} — keeping inflight, dropping stale/spoofed response",
                        self.name,
                        self.remote
                    );
                }
                Completion::NoWaiter => {}
            }
        }
    }
}
