use super::inflight::InflightRegistry;
use super::{connect_tcp_nodelay, now_ms, UpstreamRequest};
use crate::config::EcsMode;
use anyhow::{anyhow, Context, Result};
use bytes::{Bytes, BytesMut};
use rustls::pki_types::ServerName;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::mpsc;

type BoxedWrite = Box<dyn AsyncWrite + Send + Unpin>;
type BoxedRead = Box<dyn AsyncRead + Send + Unpin>;

/// Channel back to a connection's writer task. `None` when not connected.
type WriterTx = Arc<tokio::sync::Mutex<Option<mpsc::Sender<Bytes>>>>;

/// Bound on queued-but-unwritten frames per connection. Backpressure beyond this
/// surfaces as a per-query timeout; a configured inflight cap usually bites first.
const WRITE_QUEUE_CAP: usize = 1024;

/// Cap on bytes coalesced into a single write, so a burst cannot grow the staging
/// buffer without bound. DNS-over-TCP queries are tiny, so this fits thousands.
const MAX_WRITE_BATCH_BYTES: usize = 64 * 1024;

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
    /// Sender to the active connection's writer task; `None` when not connected.
    /// Callers clone this under a brief lock and never hold it across a socket write,
    /// so concurrent queries do not serialize on a write mutex.
    writer_tx: WriterTx,
    pending: Arc<InflightRegistry>,
    /// Incremented on every reconnect; reader/writer tasks exit when their birth-generation diverges.
    generation: Arc<AtomicU64>,
    ecs_mode: EcsMode,
    /// Epoch-ms before which reconnect attempts are rejected (exponential backoff).
    /// 0 = reconnect is allowed immediately.
    reconnect_not_before_ms: AtomicU64,
    /// Consecutive failed TCP/TLS connection attempts; reset to 0 on first success.
    reconnect_fail_count: AtomicU32,
    /// Drop the connection when a response frame exceeds this size. 0 = no limit.
    max_response_bytes: usize,
    /// `SO_MARK` (fwmark) applied to each TCP socket before connect, for policy routing.
    mark: Option<u32>,
}

impl TcpMux {
    #[allow(clippy::too_many_arguments)]
    pub(super) fn new(
        name: String,
        remote: SocketAddr,
        timeout: Duration,
        connector: MuxConnector,
        max_inflight: usize,
        ecs_mode: EcsMode,
        max_response_bytes: usize,
        mark: Option<u32>,
    ) -> Self {
        Self {
            name,
            remote,
            timeout,
            connector,
            writer_tx: Arc::new(tokio::sync::Mutex::new(None)),
            reconnect_not_before_ms: AtomicU64::new(0),
            reconnect_fail_count: AtomicU32::new(0),
            pending: Arc::new(InflightRegistry::new(max_inflight)),
            generation: Arc::new(AtomicU64::new(0)),
            ecs_mode,
            max_response_bytes,
            mark,
        }
    }

    /// Open a raw TCP or TLS connection and split it into read/write halves.
    async fn do_connect(&self) -> Result<(BoxedRead, BoxedWrite)> {
        match &self.connector {
            MuxConnector::Tcp => {
                let stream = connect_tcp_nodelay(self.remote, self.timeout, &self.name, self.mark).await?;
                let (r, w) = stream.into_split();
                Ok((Box::new(r), Box::new(w)))
            }
            MuxConnector::Tls {
                config,
                server_name,
            } => {
                let tcp = connect_tcp_nodelay(self.remote, self.timeout, &self.name, self.mark).await?;
                let connector = tokio_rustls::TlsConnector::from(config.clone());
                let tls =
                    tokio::time::timeout(self.timeout, connector.connect(server_name.clone(), tcp))
                        .await
                        .map_err(|e| {
                            anyhow::Error::from(e).context(format!(
                                "upstream {} tls handshake timeout: {}",
                                self.name, self.remote
                            ))
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

    /// Ensure a live connection exists and return a sender to its writer task.
    /// Spawns a reader and a writer task on first connect or reconnect.  Returns an
    /// error immediately (without sleeping) when the upstream is within an
    /// exponential reconnect backoff window.
    async fn ensure_connection(&self) -> Result<mpsc::Sender<Bytes>> {
        let mut guard = self.writer_tx.lock().await;
        if let Some(tx) = guard.as_ref() {
            return Ok(tx.clone());
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
                let (tx, rx) = mpsc::channel::<Bytes>(WRITE_QUEUE_CAP);
                *guard = Some(tx.clone());

                // Reader task: correlates responses back to waiters.
                tokio::spawn(mux_reader_loop(
                    read_half,
                    self.pending.clone(),
                    self.generation.clone(),
                    my_gen,
                    self.writer_tx.clone(),
                    self.max_response_bytes,
                    self.timeout,
                ));

                // Writer task: owns the write half and drains the queue, coalescing
                // ready frames into one write.
                tokio::spawn(mux_writer_loop(
                    write_half,
                    rx,
                    self.writer_tx.clone(),
                    self.pending.clone(),
                    self.generation.clone(),
                    my_gen,
                    self.timeout,
                ));

                Ok(tx)
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
        // Register in the shared inflight table: allocates an upstream query ID
        // (different from client_id to avoid cross-query aliasing) and enforces
        // the per-upstream inflight cap.  The registry validates the response
        // question and restores the client ID on delivery, so this path only uses
        // the shared `prepare_query` (not `finalize_response`).
        let (upstream_id, rx, _guard) =
            self.pending
                .register(&self.name, req.client_id, req.question)?;

        // Apply ECS and patch the upstream ID. 0x20 case mixing is not applied: a
        // plain `tcp://` stream is not off-path-spoofable like UDP, and `tls://`
        // (DoT) is already authenticated by TLS.
        let pkt = super::prepare_query(&req.packet, &self.ecs_mode, upstream_id)?;

        // Reject packets too large for a u16 DNS-over-TCP length prefix before we
        // hand them off (the writer task frames without re-checking).
        if u16::try_from(pkt.len()).is_err() {
            return Err(anyhow!("upstream {}: dns packet too large for tcp", self.name));
        }

        // Hand the query to the connection's writer task. The lock inside
        // `ensure_connection` is held only long enough to clone the channel sender,
        // never across the socket write.
        let frame = Bytes::from(pkt);
        let name = &self.name;
        let enqueue = tokio::time::timeout(self.timeout, async {
            let tx = self.ensure_connection().await?;
            tx.send(frame)
                .await
                .map_err(|_| anyhow!("upstream {name} tcp connection lost before write"))
        })
        .await;
        match enqueue {
            Err(elapsed) => {
                return Err(anyhow::Error::from(elapsed)
                    .context(format!("upstream {} tcp write enqueue timeout", self.name)));
            }
            Ok(Err(e)) => return Err(e),
            Ok(Ok(())) => {}
        }

        // Await response from reader task. The inflight registry already validated
        // the response question and restored the client ID on delivery.
        match tokio::time::timeout(self.timeout, rx).await {
            Ok(Ok(resp)) => Ok(resp),
            Ok(Err(_closed)) => Err(anyhow!(
                "upstream {} tcp response channel closed",
                self.name
            )),
            Err(elapsed) => {
                Err(anyhow::Error::from(elapsed)
                    .context(format!("upstream {} tcp timeout", self.name)))
            }
        }
    }
}

/// Append a length-prefixed DNS frame to `buf`. The caller guarantees `pkt` fits a
/// u16 length prefix (checked in `exchange` before enqueue).
fn push_framed(buf: &mut BytesMut, pkt: &[u8]) {
    buf.extend_from_slice(&(pkt.len() as u16).to_be_bytes());
    buf.extend_from_slice(pkt);
}

/// Tear down the current connection: drop the writer sender (so the writer task
/// winds down) and wake all pending waiters.  Only acts while still the current
/// generation, so a stale task cannot stomp a freshly reconnected one.
async fn disconnect(
    writer_tx: &WriterTx,
    pending: &Arc<InflightRegistry>,
    global_gen: &Arc<AtomicU64>,
    my_gen: u64,
) {
    if global_gen.load(Ordering::Relaxed) == my_gen {
        *writer_tx.lock().await = None;
        pending.clear();
    }
}

/// Background writer loop for a mux connection.  Drains the queue and coalesces all
/// frames already waiting into a single write — so a burst of concurrent queries
/// costs one syscall (and, for TLS, one record) instead of one per query.  Exits
/// when the channel closes (connection torn down) or the generation changes.
async fn mux_writer_loop(
    mut writer: BoxedWrite,
    mut rx: mpsc::Receiver<Bytes>,
    writer_tx: WriterTx,
    pending: Arc<InflightRegistry>,
    global_gen: Arc<AtomicU64>,
    my_gen: u64,
    write_timeout: Duration,
) {
    let mut batch = BytesMut::with_capacity(4096);
    while let Some(first) = rx.recv().await {
        // Exit quietly if a newer connection has superseded us.
        if global_gen.load(Ordering::Relaxed) != my_gen {
            return;
        }

        batch.clear();
        push_framed(&mut batch, &first);
        while batch.len() < MAX_WRITE_BATCH_BYTES {
            match rx.try_recv() {
                Ok(next) => push_framed(&mut batch, &next),
                Err(_) => break,
            }
        }

        let write_ok = matches!(
            tokio::time::timeout(write_timeout, async {
                writer.write_all(&batch).await?;
                writer.flush().await
            })
            .await,
            Ok(Ok(()))
        );
        if !write_ok {
            disconnect(&writer_tx, &pending, &global_gen, my_gen).await;
            return;
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
    writer_tx: WriterTx,
    max_response_bytes: usize,
    read_timeout: Duration,
) {
    let mut buf = BytesMut::with_capacity(4096);
    loop {
        // Exit if a newer connection has been established.
        if global_gen.load(Ordering::Relaxed) != my_gen {
            return;
        }

        // Length-prefix read: idle vs active connections are treated differently.
        //
        // When no queries are in flight the connection is idle.  Applying a
        // read timeout here would tear down the connection after `read_timeout`
        // seconds of silence, defeating the purpose of a persistent mux.  We
        // therefore wait for the first byte without any timeout.
        //
        // Once the first byte of the 2-byte length header has arrived, a frame
        // is in progress.  We then apply the read timeout to the rest so that an
        // upstream that sends the header and then stalls (half-frame deadlock)
        // cannot hold the connection open indefinitely.
        let mut len_buf = [0u8; 2];
        let len_ok = if pending.is_empty() {
            // Idle path: no timeout on the first byte.
            match reader.read_exact(&mut len_buf[..1]).await {
                Ok(_) => matches!(
                    tokio::time::timeout(read_timeout, reader.read_exact(&mut len_buf[1..])).await,
                    Ok(Ok(_))
                ),
                Err(_) => false,
            }
        } else {
            // Active path: full 2-byte read under timeout.
            matches!(
                tokio::time::timeout(read_timeout, reader.read_exact(&mut len_buf)).await,
                Ok(Ok(_))
            )
        };
        if !len_ok {
            disconnect(&writer_tx, &pending, &global_gen, my_gen).await;
            return;
        }

        let resp_len = u16::from_be_bytes(len_buf) as usize;
        if resp_len < 12 || (max_response_bytes > 0 && resp_len > max_response_bytes) {
            // Malformed or oversized response; disconnect.
            disconnect(&writer_tx, &pending, &global_gen, my_gen).await;
            return;
        }

        buf.clear();
        buf.resize(resp_len, 0);
        // Body read also guarded by the same timeout.
        let body_ok = matches!(
            tokio::time::timeout(read_timeout, reader.read_exact(&mut buf)).await,
            Ok(Ok(_))
        );
        if !body_ok {
            disconnect(&writer_tx, &pending, &global_gen, my_gen).await;
            return;
        }

        let _ = pending.complete(&mut buf[..resp_len]);
    }
}

#[cfg(test)]
#[path = "tests/tcp_mux.rs"]
mod tests;
