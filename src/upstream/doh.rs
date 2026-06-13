use super::{apply_ecs_mode, mix16, random_id_seed, UpstreamRequest};
use crate::config::EcsMode;
use crate::dns;
use anyhow::{anyhow, Result};
use bytes::Bytes;
use h2::client::SendRequest;
use http::Request;
use rustls::pki_types::ServerName;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;

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
    next_id: AtomicU32,
    tls: Arc<tokio_rustls::TlsConnector>,
    /// Shared h2 connection handle; None when no connection is open.
    conn: Mutex<Option<SendRequest<Bytes>>>,
}

impl DoHUpstream {
    pub(super) fn new(
        name: String,
        remote: SocketAddr,
        server_name: String,
        path: String,
        timeout: Duration,
        ecs_mode: EcsMode,
    ) -> Result<Self> {
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

        Ok(Self {
            name,
            remote,
            server_name: sn,
            url,
            timeout,
            ecs_mode,
            next_id: AtomicU32::new(random_id_seed()),
            tls,
            conn: Mutex::new(None),
        })
    }

    /// Open a fresh TCP+TLS+h2 connection and spawn the connection driver.
    async fn connect(&self) -> Result<SendRequest<Bytes>> {
        let tcp = tokio::net::TcpStream::connect(self.remote)
            .await
            .map_err(|e| anyhow!("upstream {}: DoH TCP connect: {e}", self.name))?;
        tcp.set_nodelay(true).ok();
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
    async fn get_or_connect(&self) -> Result<SendRequest<Bytes>> {
        let mut guard = self.conn.lock().await;
        if let Some(ref sr) = *guard {
            return Ok(sr.clone());
        }
        let sr = self.connect().await?;
        *guard = Some(sr.clone());
        Ok(sr)
    }

    /// Send the request headers + body and return the response-header future.
    /// If the existing connection is dead, reconnects once before giving up.
    async fn send_request(
        &self,
        req: Request<()>,
        body: Bytes,
    ) -> Result<h2::client::ResponseFuture> {
        let mut sr = self.get_or_connect().await?;

        // If the connection closed (GOAWAY / idle), drop it and reconnect once.
        // ready() consumes self, so clone before checking; keep original for send_request.
        if sr.clone().ready().await.is_err() {
            *self.conn.lock().await = None;
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
        let raw = apply_ecs_mode(&req.packet, &self.ecs_mode);
        let mut pkt = raw.to_vec();
        let upstream_id = mix16(self.next_id.fetch_add(1, Ordering::Relaxed));
        dns::set_id(&mut pkt, upstream_id)?;

        let q_end = 12 + req.question.len();
        let seed = upstream_id as u64
            ^ (std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.subsec_micros() as u64)
                .unwrap_or(0));
        dns::mix_qname_case(&mut pkt, q_end, seed);

        let body = Bytes::from(pkt.clone());

        let http_req = Request::builder()
            .method("POST")
            .uri(&self.url)
            .header("content-type", "application/dns-message")
            .header("accept", "application/dns-message")
            .body(())
            .map_err(|e| anyhow!("upstream {}: DoH build request: {e}", self.name))?;

        // Connect + send headers/body within the configured timeout.
        let response_fut = tokio::time::timeout(self.timeout, self.send_request(http_req, body))
            .await
            .map_err(|e| {
                anyhow::Error::from(e).context(format!("upstream {}: DoH timeout", self.name))
            })??;

        // Wait for response headers.
        let response = tokio::time::timeout(self.timeout, response_fut)
            .await
            .map_err(|e| {
                anyhow::Error::from(e).context(format!("upstream {}: DoH timeout", self.name))
            })?
            .map_err(|e| anyhow!("upstream {}: DoH response: {e}", self.name))?;

        if response.status().as_u16() != 200 {
            return Err(anyhow!(
                "upstream {}: DoH HTTP {}",
                self.name,
                response.status().as_u16()
            ));
        }

        // Read response body.
        let mut body_stream = response.into_body();
        let mut resp_bytes: Vec<u8> = Vec::with_capacity(512);
        loop {
            match tokio::time::timeout(self.timeout, body_stream.data()).await {
                Err(e) => {
                    return Err(anyhow::Error::from(e)
                        .context(format!("upstream {}: DoH body read timeout", self.name)));
                }
                Ok(None) => break,
                Ok(Some(Ok(chunk))) => {
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
                Ok(Some(Err(e))) => {
                    return Err(anyhow!("upstream {}: DoH body read: {e}", self.name));
                }
            }
        }

        super::validate_upstream_response(&resp_bytes, upstream_id, &req.question)
            .map_err(|e| anyhow!("upstream {}: DoH {e}", self.name))?;
        if let Some(resp_qend) = dns::question_end(&resp_bytes) {
            if !dns::verify_qname_case_echo(&pkt, q_end, &resp_bytes, resp_qend) {
                return Err(anyhow!(
                    "upstream {}: DoH 0x20 QNAME case mismatch",
                    self.name
                ));
            }
        }
        dns::set_id(&mut resp_bytes, req.client_id)?;
        Ok(Bytes::from(resp_bytes))
    }
}
