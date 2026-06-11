use super::inflight::InflightRegistry;
use super::{apply_ecs_mode, connect_tcp_nodelay, now_ms, tcp_write_framed, UpstreamRequest};
use crate::config::EcsMode;
use crate::dns;
use anyhow::{anyhow, Context, Result};
use bytes::{Bytes, BytesMut};
use rustls::pki_types::ServerName;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite};

type BoxedWrite = Box<dyn AsyncWrite + Send + Unpin>;
type BoxedRead = Box<dyn AsyncRead + Send + Unpin>;

pub(super) enum MuxConnector {
    Tcp,
    Tls {
        config: Arc<rustls::ClientConfig>,
        server_name: ServerName<'static>,
    },
}

pub(super) struct TcpMux {
    pub(super) name: String,
    remote: SocketAddr,
    timeout: Duration,
    connector: MuxConnector,
    /// Write half of the active connection; `None` when not connected.
    write_half: Arc<tokio::sync::Mutex<Option<BoxedWrite>>>,
    pending: Arc<InflightRegistry>,
    /// Incremented on every reconnect; reader tasks exit when their birth-generation diverges.
    generation: Arc<AtomicU64>,
    ecs_mode: EcsMode,
    /// Epoch-ms before which reconnect attempts are rejected (exponential backoff).
    /// 0 = reconnect is allowed immediately.
    reconnect_not_before_ms: AtomicU64,
    /// Consecutive failed TCP/TLS connection attempts; reset to 0 on first success.
    reconnect_fail_count: AtomicU32,
    /// Drop the connection when a response frame exceeds this size. 0 = no limit.
    max_response_bytes: usize,
}

impl TcpMux {
    pub(super) fn new(
        name: String,
        remote: SocketAddr,
        timeout: Duration,
        connector: MuxConnector,
        max_inflight: usize,
        ecs_mode: EcsMode,
        max_response_bytes: usize,
    ) -> Self {
        Self {
            name,
            remote,
            timeout,
            connector,
            write_half: Arc::new(tokio::sync::Mutex::new(None)),
            reconnect_not_before_ms: AtomicU64::new(0),
            reconnect_fail_count: AtomicU32::new(0),
            pending: Arc::new(InflightRegistry::new(max_inflight)),
            generation: Arc::new(AtomicU64::new(0)),
            ecs_mode,
            max_response_bytes,
        }
    }

    /// Open a raw TCP or TLS connection and split it into read/write halves.
    async fn do_connect(&self) -> Result<(BoxedRead, BoxedWrite)> {
        match &self.connector {
            MuxConnector::Tcp => {
                let stream = connect_tcp_nodelay(self.remote, self.timeout, &self.name).await?;
                let (r, w) = stream.into_split();
                Ok((Box::new(r), Box::new(w)))
            }
            MuxConnector::Tls {
                config,
                server_name,
            } => {
                let tcp = connect_tcp_nodelay(self.remote, self.timeout, &self.name).await?;
                let connector = tokio_rustls::TlsConnector::from(config.clone());
                let tls =
                    tokio::time::timeout(self.timeout, connector.connect(server_name.clone(), tcp))
                        .await
                        .map_err(|_| {
                            anyhow!(
                                "upstream {} tls handshake timeout: {}",
                                self.name,
                                self.remote
                            )
                        })?
                        .with_context(|| {
                            format!(
                                "upstream {}: TLS handshake failed: {}",
                                self.name, self.remote
                            )
                        })?;
                let (r, w) = tokio::io::split(tls);
                Ok((Box::new(r), Box::new(w)))
            }
        }
    }

    /// Ensure a live connection exists. Spawns a background reader task on first
    /// connect or reconnect.  Returns an error immediately (without sleeping) when
    /// the upstream is within an exponential reconnect backoff window.
    async fn ensure_connection(&self) -> Result<()> {
        let mut guard = self.write_half.lock().await;
        if guard.is_some() {
            return Ok(());
        }

        // Reject attempts that arrive within the backoff window; no sleep, just
        // an immediate error so callers in the mutex queue drain quickly.
        let now = now_ms();
        let not_before = self.reconnect_not_before_ms.load(Ordering::Relaxed);
        if now < not_before {
            return Err(anyhow!(
                "upstream {} tcp reconnect backoff ({}ms remaining)",
                self.name,
                not_before - now
            ));
        }

        match self.do_connect().await {
            Ok((read_half, write_half)) => {
                // Reset backoff on successful connection.
                self.reconnect_fail_count.store(0, Ordering::Relaxed);
                self.reconnect_not_before_ms.store(0, Ordering::Relaxed);

                let my_gen = self.generation.fetch_add(1, Ordering::Relaxed) + 1;
                *guard = Some(write_half);

                let pending = self.pending.clone();
                let generation = self.generation.clone();
                let write_conn = self.write_half.clone();
                let max_resp = self.max_response_bytes;
                tokio::spawn(async move {
                    mux_reader_loop(read_half, pending, generation, my_gen, write_conn, max_resp).await;
                });

                Ok(())
            }
            Err(e) => {
                // Exponential backoff: 100ms, 200ms, 400ms, up to 5000ms.
                let failures = self.reconnect_fail_count.fetch_add(1, Ordering::Relaxed) + 1;
                let backoff_ms = (50u64 << failures.min(7)).min(5000);
                self.reconnect_not_before_ms
                    .store(now_ms() + backoff_ms, Ordering::Relaxed);
                Err(e)
            }
        }
    }

    pub(super) async fn exchange(&self, req: UpstreamRequest) -> Result<Bytes> {
        // Apply ECS mode before sending.
        let raw_packet = apply_ecs_mode(&req.packet, &self.ecs_mode);

        // Register in the shared inflight table: allocates an upstream query ID
        // (different from client_id to avoid cross-query aliasing) and enforces
        // the per-upstream inflight cap.
        let q_end = 12 + req.question.len();
        let (upstream_id, rx, _guard) =
            self.pending
                .register(&self.name, req.client_id, req.question)?;

        // Patch ID into a mutable copy, then write framed under a timed write lock.
        let mut pkt = raw_packet.to_vec();
        dns::set_id(&mut pkt, upstream_id)?;

        // Apply 0x20 QNAME case mixing.
        let seed_0x20 = upstream_id as u64 ^ (self.generation.load(Ordering::Relaxed) << 16);
        dns::mix_qname_case(&mut pkt, q_end, seed_0x20);

        let name = &self.name;
        let write_result = tokio::time::timeout(self.timeout, async {
            self.ensure_connection().await?;
            let mut conn = self.write_half.lock().await;
            match conn.as_mut() {
                Some(w) => tcp_write_framed(w, &pkt, name).await,
                None => Err(anyhow!("upstream {name} tcp connection lost before write")),
            }
        })
        .await;

        match write_result {
            Err(_elapsed) => {
                // Write timed out; drop the connection.
                *self.write_half.lock().await = None;
                return Err(anyhow!("upstream {} tcp write timeout", self.name));
            }
            Ok(Err(e)) => {
                *self.write_half.lock().await = None;
                return Err(e);
            }
            Ok(Ok(())) => {}
        }

        // Await response from reader task.
        match tokio::time::timeout(self.timeout, rx).await {
            Ok(Ok(resp)) => {
                // Verify 0x20 case echo.
                if let Some(resp_qend) = dns::question_end(&resp) {
                    if !dns::verify_qname_case_echo(&pkt, q_end, &resp, resp_qend) {
                        return Err(anyhow!(
                            "upstream {}: 0x20 QNAME case mismatch (possible spoof)",
                            self.name
                        ));
                    }
                }
                Ok(resp)
            }
            Ok(Err(_closed)) => Err(anyhow!(
                "upstream {} tcp response channel closed",
                self.name
            )),
            Err(_elapsed) => Err(anyhow!("upstream {} tcp timeout", self.name)),
        }
    }
}

/// Background reader loop for a mux connection.
/// Exits when the generation changes (superseded by a new connection) or on read error.
async fn mux_reader_loop(
    mut reader: BoxedRead,
    pending: Arc<InflightRegistry>,
    global_gen: Arc<AtomicU64>,
    my_gen: u64,
    write_conn: Arc<tokio::sync::Mutex<Option<BoxedWrite>>>,
    max_response_bytes: usize,
) {
    let mut buf = BytesMut::with_capacity(4096);
    loop {
        // Exit if a newer connection has been established.
        if global_gen.load(Ordering::Relaxed) != my_gen {
            return;
        }

        let mut len_buf = [0u8; 2];
        if reader.read_exact(&mut len_buf).await.is_err() {
            if global_gen.load(Ordering::Relaxed) == my_gen {
                // Clear write half and drain all pending (callers see channel-closed error).
                *write_conn.lock().await = None;
                pending.clear();
            }
            return;
        }

        let resp_len = u16::from_be_bytes(len_buf) as usize;
        if resp_len < 12 || (max_response_bytes > 0 && resp_len > max_response_bytes) {
            // Malformed or oversized response; disconnect.
            if global_gen.load(Ordering::Relaxed) == my_gen {
                *write_conn.lock().await = None;
                pending.clear();
            }
            return;
        }

        buf.clear();
        buf.resize(resp_len, 0);
        if reader.read_exact(&mut buf).await.is_err() {
            if global_gen.load(Ordering::Relaxed) == my_gen {
                *write_conn.lock().await = None;
                pending.clear();
            }
            return;
        }

        let _ = pending.complete(&mut buf, resp_len);
    }
}
