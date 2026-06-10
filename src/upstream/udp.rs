use super::{apply_ecs_mode, mix16, random_id_seed, tcp_exchange_packet, UpstreamRequest};
use crate::config::EcsMode;
use crate::dns;
use anyhow::{anyhow, Context, Result};
use bytes::{Bytes, BytesMut};
use dashmap::DashMap;
use rustc_hash::FxBuildHasher;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU32, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;
use tokio::sync::oneshot;

// Inflight entry: (response sender, original client_id, question bytes for mismatch detection)
type InflightEntry = (oneshot::Sender<Bytes>, u16, Bytes);

pub(super) struct UdpUpstream {
    pub(super) name: String,
    remote: SocketAddr,
    sockets: Vec<Arc<UdpSocket>>,
    send_idx: AtomicUsize,
    timeout: Duration,
    /// Counter seeded from system time at startup; mixed through `mix16` before use
    /// so that upstream query IDs are non-sequential and unpredictable.
    id: AtomicU32,
    inflight: DashMap<u16, InflightEntry, FxBuildHasher>,
    /// Maximum concurrent in-flight queries (0 = unlimited).
    max_inflight: usize,
    ecs_mode: EcsMode,
}

struct InflightGuard<'a> {
    upstream: &'a UdpUpstream,
    id: u16,
}

impl Drop for InflightGuard<'_> {
    fn drop(&mut self) {
        self.upstream.remove_inflight(self.id);
    }
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
            id: AtomicU32::new(random_id_seed()),
            inflight: DashMap::with_hasher(FxBuildHasher::default()),
            max_inflight,
            ecs_mode,
        });
        for i in 0..upstream.sockets.len() {
            let u = upstream.clone();
            tokio::spawn(async move {
                let mut delay_ms = 50u64;
                loop {
                    if let Err(err) = u.clone().recv_loop(i).await {
                        crate::log_error!(
                            "upstream name={} event=recv_loop_exit error={err:#} restarting_in={delay_ms}ms",
                            u.name
                        );
                        tokio::time::sleep(Duration::from_millis(delay_ms)).await;
                        delay_ms = (delay_ms * 2).min(5_000);
                    } else {
                        break;
                    }
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
        let (upstream_id, rx) = self.register_inflight(req.client_id, req.question)?;
        let _guard = InflightGuard {
            upstream: self,
            id: upstream_id,
        };
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

    fn register_inflight(
        &self,
        client_id: u16,
        question: Bytes,
    ) -> Result<(u16, oneshot::Receiver<Bytes>)> {
        if self.max_inflight > 0 && self.inflight.len() >= self.max_inflight {
            return Err(anyhow!(
                "upstream {} inflight cap ({}) reached",
                self.name,
                self.max_inflight
            ));
        }
        let (tx, rx) = oneshot::channel();
        let mut tx = Some(tx);
        for _ in 0..u16::MAX {
            let id = mix16(self.id.fetch_add(1, Ordering::Relaxed));
            match self.inflight.entry(id) {
                dashmap::mapref::entry::Entry::Vacant(e) => {
                    let Some(tx) = tx.take() else {
                        return Err(anyhow!("upstream {} sender already registered", self.name));
                    };
                    e.insert((tx, client_id, question));
                    return Ok((id, rx));
                }
                dashmap::mapref::entry::Entry::Occupied(_) => continue,
            }
        }
        Err(anyhow!("upstream {} inflight table is full", self.name))
    }

    fn remove_inflight(&self, id: u16) {
        self.inflight.remove(&id);
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
            if !dns::is_reply(&buf[..n]) {
                continue;
            }
            let id = match dns::get_id(&buf[..n]) {
                Ok(id) => id,
                Err(_) => continue,
            };
            // Peek first; only remove after question validation so a stale/spoofed
            // response with a recycled ID cannot destroy the live waiter's sender.
            if let Some(entry) = self.inflight.get(&id) {
                let resp_qend = dns::question_end(&buf[..n]);
                let resp_question = resp_qend
                    .and_then(|end| buf.get(12..end))
                    .unwrap_or(&[][..]);
                if !dns::questions_match(resp_question, &entry.2) {
                    crate::verbose!(
                        "upstream name={} proto=udp remote={} event=question_mismatch id={id} — keeping inflight, dropping stale/spoofed response",
                        self.name,
                        self.remote
                    );
                    continue; // entry stays; real response can still arrive
                }
                drop(entry); // release shared ref before taking ownership
                if let Some((_, (tx, client_id, _))) = self.inflight.remove(&id) {
                    let _ = dns::set_id(&mut buf[..n], client_id);
                    let _ = tx.send(buf.split_to(n).freeze());
                    recv_count += 1;
                    // Yield every 100 dispatched responses to prevent monopolizing the Tokio
                    // worker during burst periods where many responses arrive back-to-back.
                    if recv_count >= 100 {
                        recv_count = 0;
                        tokio::task::yield_now().await;
                    }
                }
            }
        }
    }
}
