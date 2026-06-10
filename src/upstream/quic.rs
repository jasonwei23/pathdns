use super::{apply_ecs_mode, mix16, random_id_seed, UpstreamRequest};
use crate::config::EcsMode;
use crate::dns;
use anyhow::{anyhow, Context, Result};
use bytes::Bytes;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::time::Duration;

// DNS-over-QUIC (DoQ, RFC 9250) upstream.
//
// Requires `--features doq` which adds the `quinn` crate.
// A single persistent QUIC connection is maintained per upstream; each DNS
// query opens a new bidirectional stream.  2-byte length prefix per RFC 9250.

/// Create a QUIC client endpoint bound to an ephemeral local port.
///
/// `alpn` must be the ALPN token for the protocol in use:
///   - `b"doq"` for DNS-over-QUIC (RFC 9250)
///   - `b"h3"`  for HTTP/3 DoH (RFC 9114)
///
/// RFC 9250 §4.1: implementations MUST use the "doq" ALPN token.
/// Without the correct ALPN, servers that enforce protocol negotiation
/// will reject the TLS handshake.
///
/// Chooses IPv6 or IPv4 bind address to match `remote`.
#[cfg(feature = "doq")]
fn make_quic_endpoint(remote: SocketAddr, name: &str, alpn: &[u8]) -> Result<quinn::Endpoint> {
    let roots: rustls::RootCertStore = webpki_roots::TLS_SERVER_ROOTS.iter().cloned().collect();
    let mut rustls_cfg = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    rustls_cfg.alpn_protocols = vec![alpn.to_vec()];
    let quic_cfg = quinn::crypto::rustls::QuicClientConfig::try_from(rustls_cfg)
        .map_err(|e| anyhow!("upstream {name}: QUIC TLS config: {e}"))?;
    let bind: SocketAddr = if remote.is_ipv6() {
        SocketAddr::from((Ipv6Addr::UNSPECIFIED, 0))
    } else {
        SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0))
    };
    let mut endpoint = quinn::Endpoint::client(bind)
        .with_context(|| format!("upstream {name}: QUIC bind failed ({bind})"))?;
    endpoint.set_default_client_config(quinn::ClientConfig::new(Arc::new(quic_cfg)));
    Ok(endpoint)
}

#[cfg(feature = "doq")]
pub(super) struct DoQUpstream {
    pub(super) name: String,
    endpoint: quinn::Endpoint,
    remote: SocketAddr,
    server_name: String,
    timeout: Duration,
    ecs_mode: EcsMode,
    next_id: AtomicU32,
    /// Active QUIC connection; `None` when not connected or after error.
    connection: tokio::sync::Mutex<Option<quinn::Connection>>,
}

#[cfg(feature = "doq")]
impl DoQUpstream {
    pub(super) fn new(
        name: String,
        remote: SocketAddr,
        server_name: String,
        timeout: Duration,
        ecs_mode: EcsMode,
    ) -> Result<Self> {
        let endpoint = make_quic_endpoint(remote, &name, b"doq")?;
        crate::verbose!("upstream name={name} proto=doq remote={remote} sni={server_name}");
        Ok(Self {
            name,
            endpoint,
            remote,
            server_name,
            timeout,
            ecs_mode,
            next_id: AtomicU32::new(random_id_seed()),
            connection: tokio::sync::Mutex::new(None),
        })
    }

    async fn get_or_connect(&self) -> Result<quinn::Connection> {
        let mut guard = self.connection.lock().await;
        if let Some(conn) = guard.as_ref() {
            if conn.close_reason().is_none() {
                return Ok(conn.clone());
            }
        }
        let connecting = self
            .endpoint
            .connect(self.remote, &self.server_name)
            .map_err(|e| anyhow!("upstream {}: DoQ connect error: {e}", self.name))?;
        let conn = tokio::time::timeout(self.timeout, connecting)
            .await
            .map_err(|_| anyhow!("upstream {}: DoQ connect timeout", self.name))?
            .with_context(|| format!("upstream {}: DoQ QUIC handshake failed", self.name))?;
        crate::verbose!(
            "upstream name={} proto=doq remote={} event=connected",
            self.name,
            self.remote
        );
        *guard = Some(conn.clone());
        Ok(conn)
    }

    pub(super) async fn exchange(&self, req: UpstreamRequest) -> Result<Bytes> {
        let raw = apply_ecs_mode(&req.packet, &self.ecs_mode);
        let mut pkt = raw.to_vec();
        let upstream_id = mix16(self.next_id.fetch_add(1, Ordering::Relaxed));
        dns::set_id(&mut pkt, upstream_id)?;

        let result = self.do_exchange(&pkt).await;
        if result.is_err() {
            *self.connection.lock().await = None;
        }
        let mut body = result?;
        super::validate_upstream_response(&body, upstream_id, &req.question)
            .map_err(|e| anyhow!("upstream {}: DoQ {e}", self.name))?;
        dns::set_id(&mut body, req.client_id)?;
        Ok(Bytes::from(body))
    }

    async fn do_exchange(&self, pkt: &[u8]) -> Result<Vec<u8>> {
        let conn = self.get_or_connect().await?;
        let fut = async {
            let (mut send, mut recv) = conn
                .open_bi()
                .await
                .with_context(|| format!("upstream {}: DoQ open stream failed", self.name))?;

            let frame_len = u16::try_from(pkt.len())
                .map_err(|_| anyhow!("upstream {}: DNS packet too large for DoQ", self.name))?;
            send.write_all(&frame_len.to_be_bytes()).await?;
            send.write_all(pkt).await?;
            let _ = send.finish();

            let mut len_buf = [0u8; 2];
            recv.read_exact(&mut len_buf).await.with_context(|| {
                format!("upstream {}: DoQ response length read failed", self.name)
            })?;
            let resp_len = u16::from_be_bytes(len_buf) as usize;
            if resp_len < 12 {
                return Err(anyhow!(
                    "upstream {}: DoQ response too short ({resp_len} bytes)",
                    self.name
                ));
            }
            let mut resp = vec![0u8; resp_len];
            recv.read_exact(&mut resp).await.with_context(|| {
                format!("upstream {}: DoQ response body read failed", self.name)
            })?;
            Ok(resp)
        };
        tokio::time::timeout(self.timeout, fut)
            .await
            .map_err(|_| anyhow!("upstream {}: DoQ timeout", self.name))?
    }
}

// HTTP/3 DoH upstream.
//
// Requires `--features h3` (which implies `doq`).  Uses per-query QUIC
// connections for simplicity; the h3 driver is run in a background task.

#[cfg(feature = "h3")]
pub(super) struct H3Upstream {
    pub(super) name: String,
    endpoint: quinn::Endpoint,
    remote: SocketAddr,
    server_name: String,
    path: String,
    timeout: Duration,
    ecs_mode: EcsMode,
    next_id: AtomicU32,
}

#[cfg(feature = "h3")]
impl H3Upstream {
    pub(super) fn new(
        name: String,
        remote: SocketAddr,
        server_name: String,
        path: String,
        timeout: Duration,
        ecs_mode: EcsMode,
    ) -> Result<Self> {
        let endpoint = make_quic_endpoint(remote, &name, b"h3")?;
        crate::verbose!(
            "upstream name={name} proto=h3 remote={remote} sni={server_name} path={path}"
        );
        Ok(Self {
            name,
            endpoint,
            remote,
            server_name,
            path,
            timeout,
            ecs_mode,
            next_id: AtomicU32::new(random_id_seed()),
        })
    }

    pub(super) async fn exchange(&self, req: UpstreamRequest) -> Result<Bytes> {
        let raw = apply_ecs_mode(&req.packet, &self.ecs_mode);
        let mut pkt = raw.to_vec();
        let upstream_id = mix16(self.next_id.fetch_add(1, Ordering::Relaxed));
        dns::set_id(&mut pkt, upstream_id)?;

        let mut body = self.do_exchange(pkt).await?;
        super::validate_upstream_response(&body, upstream_id, &req.question)
            .map_err(|e| anyhow!("upstream {}: H3 {e}", self.name))?;
        dns::set_id(&mut body, req.client_id)?;
        Ok(Bytes::from(body))
    }

    async fn do_exchange(&self, pkt: Vec<u8>) -> Result<Vec<u8>> {
        let fut = async {
            let connecting = self
                .endpoint
                .connect(self.remote, &self.server_name)
                .map_err(|e| anyhow!("upstream {}: H3 connect error: {e}", self.name))?;
            let quic_conn = connecting
                .await
                .with_context(|| format!("upstream {}: H3 QUIC handshake failed", self.name))?;

            let h3_conn = h3_quinn::Connection::new(quic_conn);
            let (mut driver, mut send_req) = h3::client::new(h3_conn)
                .await
                .map_err(|e| anyhow!("upstream {}: H3 connection init failed: {e}", self.name))?;

            tokio::spawn(async move {
                let _ = std::future::poll_fn(|cx| driver.poll_close(cx)).await;
            });

            let uri: http::Uri = format!(
                "https://{}:{}{}",
                self.server_name,
                self.remote.port(),
                self.path
            )
            .parse()
            .map_err(|e| anyhow!("upstream {}: H3 URI parse failed: {e}", self.name))?;

            let request = http::Request::builder()
                .method(http::Method::POST)
                .uri(uri)
                .header("content-type", "application/dns-message")
                .header("accept", "application/dns-message")
                .header("content-length", pkt.len().to_string())
                .body(())
                .map_err(|e| anyhow!("upstream {}: H3 request build failed: {e}", self.name))?;

            let mut stream = send_req
                .send_request(request)
                .await
                .map_err(|e| anyhow!("upstream {}: H3 send_request failed: {e}", self.name))?;

            stream
                .send_data(bytes::Bytes::from(pkt))
                .await
                .map_err(|e| anyhow!("upstream {}: H3 send_data failed: {e}", self.name))?;
            stream
                .finish()
                .await
                .map_err(|e| anyhow!("upstream {}: H3 stream finish failed: {e}", self.name))?;

            let response = stream
                .recv_response()
                .await
                .map_err(|e| anyhow!("upstream {}: H3 recv_response failed: {e}", self.name))?;

            if response.status() != http::StatusCode::OK {
                return Err(anyhow!(
                    "upstream {}: H3 HTTP/3 {}",
                    self.name,
                    response.status()
                ));
            }

            let mut body: Vec<u8> = Vec::new();
            loop {
                match stream.recv_data().await {
                    Ok(Some(mut chunk)) => {
                        use bytes::Buf;
                        while chunk.has_remaining() {
                            let slice = chunk.chunk();
                            let n = slice.len();
                            body.extend_from_slice(slice);
                            chunk.advance(n);
                        }
                    }
                    Ok(None) => break,
                    Err(e) => {
                        return Err(anyhow!("upstream {}: H3 recv_data failed: {e}", self.name))
                    }
                }
            }
            Ok(body)
        };
        tokio::time::timeout(self.timeout, fut)
            .await
            .map_err(|_| anyhow!("upstream {}: H3 timeout", self.name))?
    }
}
