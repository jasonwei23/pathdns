use super::{mix16, random_id_seed, ConnSlot, UpstreamRequest};
use crate::config::EcsMode;
use anyhow::{anyhow, Result};
use bytes::Bytes;
use h2::client::SendRequest;
use http::Request;
use rustls::pki_types::ServerName;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::time::Duration;

// DNS-over-HTTPS upstream: hand-rolled h2 client over tokio-rustls.
//
// A single TLS+HTTP/2 connection is kept alive across requests (multiplexed
// via h2 streams).  On server-side GOAWAY or any connection error the next
// exchange reconnects transparently.  HTTP/1.1 fallback is not supported;
// the TLS ALPN negotiation requires the server to accept "h2".

pub(super) struct DoHUpstream {
    pub(super) name: String,
    remote: SocketAddr,
    server_name: ServerName<'static>,
    url: String,
    timeout: Duration,
    ecs_mode: EcsMode,
    mark: Option<u32>,
    next_id: AtomicU32,
    tls: Arc<tokio_rustls::TlsConnector>,
    /// Shared h2 connection handle; empty when no connection is open.
    conn: ConnSlot<SendRequest<Bytes>>,
    /// Enforces `upstream-max-inflight`, same as every other transport.
    inflight: Arc<tokio::sync::Semaphore>,
}

impl DoHUpstream {
    pub(super) fn new(
        common: super::UpstreamCommonConfig,
        server_name: String,
        path: String,
    ) -> Result<Self> {
        let super::UpstreamCommonConfig {
            name,
            remote,
            timeout,
            ecs_mode,
            max_inflight,
            mark,
        } = common;
        let sn = ServerName::try_from(server_name.as_str())
            .map_err(|_| anyhow!("upstream {name}: invalid DoH server name: {server_name}"))?
            .to_owned();
        let url = format!("https://{server_name}{path}");

        let roots: rustls::RootCertStore = webpki_roots::TLS_SERVER_ROOTS.iter().cloned().collect();
        let mut tls_cfg = rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        tls_cfg.alpn_protocols = vec![b"h2".to_vec()];
        let tls = Arc::new(tokio_rustls::TlsConnector::from(Arc::new(tls_cfg)));

        let permits = if max_inflight > 0 {
            max_inflight
        } else {
            tokio::sync::Semaphore::MAX_PERMITS
        };
        Ok(Self {
            name,
            remote,
            server_name: sn,
            url,
            timeout,
            ecs_mode,
            mark,
            next_id: AtomicU32::new(random_id_seed()),
            tls,
            conn: ConnSlot::new(),
            inflight: Arc::new(tokio::sync::Semaphore::new(permits)),
        })
    }

    /// Open a fresh TCP+TLS+h2 connection and spawn the connection driver.
    async fn connect(&self) -> Result<SendRequest<Bytes>> {
        // Shared TCP connect path: applies SO_MARK (policy routing), TCP_NODELAY, TFO.
        let tcp = super::connect_tcp_nodelay(self.remote, self.timeout, &self.name, self.mark)
            .await
            .map_err(|e| anyhow!("upstream {}: DoH TCP connect: {e}", self.name))?;
        let tls = self
            .tls
            .connect(self.server_name.clone(), tcp)
            .await
            .map_err(|e| anyhow!("upstream {}: DoH TLS handshake: {e}", self.name))?;
        let (sr, conn) = h2::client::handshake(tls)
            .await
            .map_err(|e| anyhow!("upstream {}: DoH h2 handshake: {e}", self.name))?;
        tokio::spawn(async move {
            let _ = conn.await;
        });
        Ok(sr)
    }

    /// Return a clone of the live connection handle, creating one if absent.
    /// Does not itself check liveness — `send_request` below does that with a
    /// `ready()` probe, since a cached-but-momentarily-busy (not dead) h2
    /// connection is normal and shouldn't force a reconnect here.
    async fn get_or_connect(&self) -> Result<SendRequest<Bytes>> {
        self.conn
            .get_or_connect(|_sr: &SendRequest<Bytes>| async { true }, self.connect())
            .await
    }

    /// Send the request headers + body and return the response-header future.
    /// If the existing connection is dead, reconnects once before giving up.
    async fn send_request(
        &self,
        req: Request<()>,
        body: Bytes,
    ) -> Result<h2::client::ResponseFuture> {
        let mut sr = self.get_or_connect().await?;

        // Fast, lock-free speculative check: cheap in the (overwhelmingly
        // common) case where the connection is already ready, since `ready()`
        // consumes its receiver and resolves immediately once genuinely
        // healthy — clone before checking, keep the original for send_request.
        if sr.clone().ready().await.is_err() {
            // The speculative check above suggests this connection is dead,
            // but it ran outside any lock, so a concurrent request could have
            // already reconnected. Re-verify (and only then clear) under one
            // continuous lock hold: unconditionally clearing here — as this
            // used to — could wipe out a fresh, healthy connection a
            // concurrent `get_or_connect` installed in the meantime.
            self.conn
                .evict_if_unhealthy(|c: &SendRequest<Bytes>| {
                    let c = c.clone();
                    async move { c.ready().await.is_ok() }
                })
                .await;
            sr = self.get_or_connect().await?;
            sr.clone()
                .ready()
                .await
                .map_err(|e| anyhow!("upstream {}: DoH h2 not ready: {e}", self.name))?;
        }

        let (response_fut, mut send_stream) = sr
            .send_request(req, false)
            .map_err(|e| anyhow!("upstream {}: DoH send request: {e}", self.name))?;
        send_stream
            .send_data(body, true)
            .map_err(|e| anyhow!("upstream {}: DoH send body: {e}", self.name))?;
        Ok(response_fut)
    }

    pub(super) async fn exchange(&self, req: UpstreamRequest) -> Result<Bytes> {
        let _permit =
            super::acquire_inflight_permit(&self.inflight, self.timeout, &self.name).await?;

        let upstream_id = mix16(self.next_id.fetch_add(1, Ordering::Relaxed));
        let body = super::prepare_query(&req.packet, &self.ecs_mode, upstream_id)?;

        let http_req = Request::builder()
            .method("POST")
            .uri(&self.url)
            .header("content-type", "application/dns-message")
            .header("accept", "application/dns-message")
            .body(())
            .map_err(|e| anyhow!("upstream {}: DoH build request: {e}", self.name))?;

        // One deadline for the whole exchange (connect/send + headers + body), not a
        // fresh budget re-granted per phase (and, worse, per body chunk) — otherwise
        // a slow/adversarial server dribbling the body in many small DATA frames could
        // keep a single query (and the TLS connection, and this permit) alive for an
        // unbounded multiple of `self.timeout` instead of being bounded by it.
        let resp_bytes = tokio::time::timeout(self.timeout, async {
            let response_fut = self.send_request(http_req, body).await?;
            let response = response_fut
                .await
                .map_err(|e| anyhow!("upstream {}: DoH response: {e}", self.name))?;

            if response.status().as_u16() != 200 {
                return Err(anyhow!(
                    "upstream {}: DoH HTTP {}",
                    self.name,
                    response.status().as_u16()
                ));
            }

            let mut body_stream = response.into_body();
            let mut resp_bytes: Vec<u8> = Vec::with_capacity(512);
            loop {
                match body_stream.data().await {
                    None => break,
                    Some(Ok(chunk)) => {
                        resp_bytes.extend_from_slice(&chunk);
                        let _ = body_stream.flow_control().release_capacity(chunk.len());
                        if resp_bytes.len() > 65_535 {
                            return Err(anyhow!(
                                "upstream {}: DoH response too large ({} bytes)",
                                self.name,
                                resp_bytes.len()
                            ));
                        }
                    }
                    Some(Err(e)) => {
                        return Err(anyhow!("upstream {}: DoH body read: {e}", self.name))
                    }
                }
            }
            Ok(resp_bytes)
        })
        .await
        .map_err(|e| {
            anyhow::Error::from(e).context(format!("upstream {}: DoH timeout", self.name))
        })??;

        super::finalize_response(resp_bytes, upstream_id, &req.question, req.client_id)
            .map_err(|e| anyhow!("upstream {}: DoH {e}", self.name))
    }
}
