use super::{
    apply_ecs_mode, connect_tcp_nodelay, mix16, now_ms, random_id_seed, tcp_write_framed,
    UpstreamRequest,
};
use crate::config::EcsMode;
use crate::dns;
use anyhow::{anyhow, Context, Result};
use bytes::{Bytes, BytesMut};
use dashmap::DashMap;
use rustc_hash::FxBuildHasher;
use rustls::pki_types::ServerName;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite};
use tokio::sync::oneshot;
use tokio_rustls;

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
    /// Pending response channels: upstream_id → (client_id, sender, question_bytes).
    pending: Arc<DashMap<u16, (u16, oneshot::Sender<Bytes>, Bytes), FxBuildHasher>>,
    /// Incremented on every reconnect; reader tasks exit when their birth-generation diverges.
    generation: Arc<AtomicU64>,
    /// Counter for assigning upstream query IDs; mixed through `mix16` before use.
    next_id: AtomicU32,
    /// Max concurrent in-flight queries (0 = unlimited).
    max_inflight: usize,
    ecs_mode: EcsMode,
    /// Epoch-ms before which reconnect attempts are rejected (exponential backoff).
    /// 0 = reconnect is allowed immediately.
    reconnect_not_before_ms: AtomicU64,
    /// Consecutive failed TCP/TLS connection attempts; reset to 0 on first success.
    reconnect_fail_count: AtomicU32,
}

impl TcpMux {
    pub(super) fn new(
        name: String,
        remote: SocketAddr,
        timeout: Duration,
        connector: MuxConnector,
        max_inflight: usize,
        ecs_mode: EcsMode,
    ) -> Self {
        crate::verbose!(
            "upstream name={name} proto={} remote={remote}",
            match connector {
                MuxConnector::Tcp => "tcp",
                MuxConnector::Tls { .. } => "tls",
            }
        );
        Self {
            name,
            remote,
            timeout,
            connector,
            write_half: Arc::new(tokio::sync::Mutex::new(None)),
            reconnect_not_before_ms: AtomicU64::new(0),
            reconnect_fail_count: AtomicU32::new(0),
            pending: Arc::new(DashMap::with_hasher(FxBuildHasher::default())),
            generation: Arc::new(AtomicU64::new(0)),
            next_id: AtomicU32::new(random_id_seed()),
            max_inflight,
            ecs_mode,
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
                let name = self.name.clone();
                tokio::spawn(async move {
                    mux_reader_loop(read_half, pending, generation, my_gen, write_conn, name).await;
                });

                crate::verbose!("upstream name={} event=connected gen={my_gen}", self.name);
                Ok(())
            }
            Err(e) => {
                // Exponential backoff: 100ms, 200ms, 400ms, up to 5000ms.
                let failures = self.reconnect_fail_count.fetch_add(1, Ordering::Relaxed) + 1;
                let backoff_ms = (50u64 << failures.min(7)).min(5000);
                self.reconnect_not_before_ms
                    .store(now_ms() + backoff_ms, Ordering::Relaxed);
                crate::verbose!(
                    "upstream name={} event=connect_failed failures={failures} backoff_ms={backoff_ms}",
                    self.name
                );
                Err(e)
            }
        }
    }

    pub(super) async fn exchange(&self, req: UpstreamRequest) -> Result<Bytes> {
        // Per-upstream inflight cap.
        if self.max_inflight > 0 && self.pending.len() >= self.max_inflight {
            return Err(anyhow!(
                "upstream {} tcp inflight cap ({}) reached",
                self.name,
                self.max_inflight
            ));
        }

        // Apply ECS mode before sending.
        let raw_packet = apply_ecs_mode(&req.packet, &self.ecs_mode);

        // Assign an upstream query ID (different from client_id to avoid cross-query aliasing).
        let upstream_id = {
            let mut id;
            loop {
                id = mix16(self.next_id.fetch_add(1, Ordering::Relaxed));
                if !self.pending.contains_key(&id) {
                    break;
                }
            }
            id
        };

        let (tx, rx) = oneshot::channel::<Bytes>();
        self.pending
            .insert(upstream_id, (req.client_id, tx, req.question));
        let _guard = TcpPendingGuard {
            pending: &self.pending,
            id: upstream_id,
        };

        // Patch ID into a mutable copy, then write framed under a timed write lock.
        let mut pkt = raw_packet.to_vec();
        dns::set_id(&mut pkt, upstream_id)?;

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

        crate::verbose!(
            "upstream name={} proto=tcp remote={} event=send id={upstream_id}",
            self.name,
            self.remote
        );

        // Await response from reader task.
        match tokio::time::timeout(self.timeout, rx).await {
            Ok(Ok(resp)) => Ok(resp),
            Ok(Err(_closed)) => Err(anyhow!(
                "upstream {} tcp response channel closed",
                self.name
            )),
            Err(_elapsed) => {
                crate::verbose!(
                    "upstream name={} proto=tcp remote={} event=timeout",
                    self.name,
                    self.remote
                );
                Err(anyhow!("upstream {} tcp timeout", self.name))
            }
        }
    }
}

/// RAII guard: removes the pending entry from the map when dropped (on timeout or error).
struct TcpPendingGuard<'a> {
    pending: &'a DashMap<u16, (u16, oneshot::Sender<Bytes>, Bytes), FxBuildHasher>,
    id: u16,
}

impl Drop for TcpPendingGuard<'_> {
    fn drop(&mut self) {
        self.pending.remove(&self.id);
    }
}

/// Background reader loop for a mux connection.
/// Exits when the generation changes (superseded by a new connection) or on read error.
async fn mux_reader_loop(
    mut reader: BoxedRead,
    pending: Arc<DashMap<u16, (u16, oneshot::Sender<Bytes>, Bytes), FxBuildHasher>>,
    global_gen: Arc<AtomicU64>,
    my_gen: u64,
    write_conn: Arc<tokio::sync::Mutex<Option<BoxedWrite>>>,
    name: String,
) {
    let mut buf = BytesMut::with_capacity(4096);
    loop {
        // Exit if a newer connection has been established.
        if global_gen.load(Ordering::Relaxed) != my_gen {
            return;
        }

        let mut len_buf = [0u8; 2];
        if let Err(e) = reader.read_exact(&mut len_buf).await {
            if global_gen.load(Ordering::Relaxed) == my_gen {
                crate::verbose!(
                    "upstream name={name} proto=tcp event=read_error gen={my_gen} error={e:#}"
                );
                // Clear write half and drain all pending (callers see channel-closed error).
                *write_conn.lock().await = None;
                pending.clear();
            }
            return;
        }

        let resp_len = u16::from_be_bytes(len_buf) as usize;
        if resp_len < 12 {
            // Malformed response; disconnect.
            if global_gen.load(Ordering::Relaxed) == my_gen {
                *write_conn.lock().await = None;
                pending.clear();
            }
            return;
        }

        buf.clear();
        if buf.capacity() < resp_len {
            buf.reserve(resp_len - buf.capacity());
        }
        unsafe { buf.set_len(resp_len) };
        if let Err(e) = reader.read_exact(&mut buf).await {
            if global_gen.load(Ordering::Relaxed) == my_gen {
                crate::verbose!(
                    "upstream name={name} proto=tcp event=read_body_error gen={my_gen} error={e:#}"
                );
                *write_conn.lock().await = None;
                pending.clear();
            }
            return;
        }

        let upstream_id = match dns::get_id(&buf) {
            Ok(id) => id,
            Err(_) => continue,
        };

        // Peek first; only remove after question validation so a stale response
        // with a recycled ID cannot destroy the live waiter's sender.
        if let Some(entry) = pending.get(&upstream_id) {
            let resp_qend = crate::dns::question_end(&buf[..resp_len]);
            let resp_question = resp_qend
                .and_then(|end| buf.get(12..end))
                .unwrap_or(&[][..]);
            if !crate::dns::questions_match(resp_question, &entry.2) {
                crate::verbose!(
                    "upstream name={name} proto=tcp event=question_mismatch id={upstream_id} — keeping pending, dropping stale/mismatched response"
                );
                continue; // entry stays; real response can still arrive
            }
            drop(entry); // release shared ref before taking ownership
            if let Some((_, (client_id, tx, _))) = pending.remove(&upstream_id) {
                let mut resp = buf.split_to(resp_len).to_vec();
                let _ = crate::dns::set_id(&mut resp, client_id);
                let _ = tx.send(Bytes::from(resp));
            }
        }
    }
}
