use super::UpstreamRequest;
// `mix16`/`random_id_seed` and the atomic ID counter are only used by the H3
// upstream; DoQ pins the DNS ID to 0 (RFC 9250) and needs neither.
#[cfg(feature = "h3")]
use super::{mix16, random_id_seed};
use crate::config::EcsMode;
use anyhow::{anyhow, Context, Result};
use bytes::Bytes;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
#[cfg(feature = "h3")]
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
fn make_quic_endpoint(
    remote: SocketAddr,
    name: &str,
    alpn: &[u8],
    mark: Option<u32>,
) -> Result<quinn::Endpoint> {
    use std::os::unix::io::AsRawFd;
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
    // Bind the UDP socket ourselves (as quinn's Endpoint::client does internally) so
    // we can apply SO_MARK for policy routing before quinn takes ownership.
    let socket = std::net::UdpSocket::bind(bind)
        .with_context(|| format!("upstream {name}: QUIC bind failed ({bind})"))?;
    if let Some(m) = mark {
        super::set_so_mark(socket.as_raw_fd(), m).with_context(|| format!("upstream {name}"))?;
    }
    let runtime =
        quinn::default_runtime().ok_or_else(|| anyhow!("upstream {name}: no async runtime"))?;
    let mut endpoint =
        quinn::Endpoint::new(quinn::EndpointConfig::default(), None, socket, runtime)
            .with_context(|| format!("upstream {name}: QUIC endpoint init"))?;
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
    inflight: Arc<tokio::sync::Semaphore>,
    /// Active QUIC connection; `None` when not connected or after error.
    connection: tokio::sync::Mutex<Option<quinn::Connection>>,
}

#[cfg(feature = "doq")]
impl DoQUpstream {
    pub(super) fn new(common: super::UpstreamCommonConfig, server_name: String) -> Result<Self> {
        let super::UpstreamCommonConfig {
            name,
            remote,
            timeout,
            ecs_mode,
            max_inflight,
            mark,
        } = common;
        let endpoint = make_quic_endpoint(remote, &name, b"doq", mark)?;
        let permits = if max_inflight > 0 {
            max_inflight
        } else {
            tokio::sync::Semaphore::MAX_PERMITS
        };
        Ok(Self {
            name,
            endpoint,
            remote,
            server_name,
            timeout,
            ecs_mode,
            inflight: Arc::new(tokio::sync::Semaphore::new(permits)),
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
            .map_err(|e| {
                anyhow::Error::from(e)
                    .context(format!("upstream {}: DoQ connect timeout", self.name))
            })?
            .with_context(|| format!("upstream {}: DoQ QUIC handshake failed", self.name))?;
        *guard = Some(conn.clone());
        Ok(conn)
    }

    pub(super) async fn exchange(&self, req: UpstreamRequest) -> Result<Bytes> {
        let _permit =
            super::acquire_inflight_permit(&self.inflight, self.timeout, &self.name).await?;

        // RFC 9250 §4.2.1: the DNS Message ID on a DoQ stream MUST be 0.
        // Servers (AdGuard Home, dnsdist, …) may send DOQ_PROTOCOL_ERROR for non-zero IDs.
        let pkt = super::prepare_query(&req.packet, &self.ecs_mode, 0)?;

        let result = self.do_exchange(&pkt).await;
        // On connection-level failure, evict the stored connection so the next query
        // reconnects. Stream-level errors (a single query's timeout, a malformed
        // response, ...) do not evict the connection — an ordinary lost packet on
        // one query's stream is common on real UDP-based QUIC paths and does not
        // mean the shared connection (and every other query using it) is dead;
        // mirrors the same check in `H3Upstream::do_exchange`.
        if result.is_err() {
            let guard = self.connection.lock().await;
            if let Some(conn) = guard.as_ref() {
                if conn.close_reason().is_some() {
                    drop(guard);
                    *self.connection.lock().await = None;
                }
            }
        }
        let body = result?;
        super::finalize_response(body, 0, &req.question, req.client_id)
            .map_err(|e| anyhow!("upstream {}: DoQ {e}", self.name))
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
        tokio::time::timeout(self.timeout, fut).await.map_err(|e| {
            anyhow::Error::from(e).context(format!("upstream {}: DoQ timeout", self.name))
        })?
    }
}

// HTTP/3 DoH upstream.
//
// Requires `--features h3` (which implies `doq`).  Uses a persistent QUIC+h3
// connection per upstream node; each DNS query opens a new h3 request stream.
// The h3 driver is run in a background task.

#[cfg(feature = "h3")]
type H3SendReq = h3::client::SendRequest<h3_quinn::OpenStreams, bytes::Bytes>;

#[cfg(feature = "h3")]
struct H3Conn {
    quic: quinn::Connection,
    send_req: H3SendReq,
}

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
    inflight: Arc<tokio::sync::Semaphore>,
    connection: tokio::sync::Mutex<Option<H3Conn>>,
}

#[cfg(feature = "h3")]
impl H3Upstream {
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
        let endpoint = make_quic_endpoint(remote, &name, b"h3", mark)?;
        let permits = if max_inflight > 0 {
            max_inflight
        } else {
            tokio::sync::Semaphore::MAX_PERMITS
        };
        Ok(Self {
            name,
            endpoint,
            remote,
            server_name,
            path,
            timeout,
            ecs_mode,
            next_id: AtomicU32::new(random_id_seed()),
            inflight: Arc::new(tokio::sync::Semaphore::new(permits)),
            connection: tokio::sync::Mutex::new(None),
        })
    }

    async fn get_or_connect(&self) -> Result<H3SendReq> {
        let mut guard = self.connection.lock().await;
        if let Some(conn) = guard.as_ref() {
            if conn.quic.close_reason().is_none() {
                return Ok(conn.send_req.clone());
            }
        }
        // Establish a new QUIC+h3 connection.
        let setup_fut = async {
            let connecting = self
                .endpoint
                .connect(self.remote, &self.server_name)
                .map_err(|e| anyhow!("upstream {}: H3 connect error: {e}", self.name))?;
            let quic_conn = connecting
                .await
                .with_context(|| format!("upstream {}: H3 QUIC handshake failed", self.name))?;

            let h3_conn = h3_quinn::Connection::new(quic_conn.clone());
            let (mut driver, send_req) = h3::client::new(h3_conn)
                .await
                .map_err(|e| anyhow!("upstream {}: H3 connection init failed: {e}", self.name))?;

            tokio::spawn(async move {
                let _ = std::future::poll_fn(|cx| driver.poll_close(cx)).await;
            });

            Ok::<(quinn::Connection, H3SendReq), anyhow::Error>((quic_conn, send_req))
        };

        let (quic_conn, send_req) = tokio::time::timeout(self.timeout, setup_fut)
            .await
            .map_err(|e| {
                anyhow::Error::from(e)
                    .context(format!("upstream {}: H3 connect timeout", self.name))
            })??;

        let cloned = send_req.clone();
        *guard = Some(H3Conn {
            quic: quic_conn,
            send_req,
        });
        Ok(cloned)
    }

    pub(super) async fn exchange(&self, req: UpstreamRequest) -> Result<Bytes> {
        let _permit =
            super::acquire_inflight_permit(&self.inflight, self.timeout, &self.name).await?;

        let upstream_id = mix16(self.next_id.fetch_add(1, Ordering::Relaxed));
        let pkt = super::prepare_query(&req.packet, &self.ecs_mode, upstream_id)?;

        let body = self.do_exchange(pkt).await?;
        super::finalize_response(body, upstream_id, &req.question, req.client_id)
            .map_err(|e| anyhow!("upstream {}: H3 {e}", self.name))
    }

    async fn do_exchange(&self, pkt: Vec<u8>) -> Result<Vec<u8>> {
        let mut send_req = self.get_or_connect().await?;

        let name: &str = &self.name;
        let uri: http::Uri = format!(
            "https://{}:{}{}",
            self.server_name,
            self.remote.port(),
            self.path
        )
        .parse()
        .map_err(|e| anyhow!("upstream {name}: H3 URI parse failed: {e}"))?;

        let fut = async move {
            let request = http::Request::builder()
                .method(http::Method::POST)
                .uri(uri)
                .header("content-type", "application/dns-message")
                .header("accept", "application/dns-message")
                .header("content-length", pkt.len().to_string())
                .body(())
                .map_err(|e| anyhow!("upstream {name}: H3 request build failed: {e}"))?;

            let mut stream = send_req
                .send_request(request)
                .await
                .map_err(|e| anyhow!("upstream {name}: H3 send_request failed: {e}"))?;

            stream
                .send_data(bytes::Bytes::from(pkt))
                .await
                .map_err(|e| anyhow!("upstream {name}: H3 send_data failed: {e}"))?;
            stream
                .finish()
                .await
                .map_err(|e| anyhow!("upstream {name}: H3 stream finish failed: {e}"))?;

            let response = stream
                .recv_response()
                .await
                .map_err(|e| anyhow!("upstream {name}: H3 recv_response failed: {e}"))?;

            if response.status() != http::StatusCode::OK {
                return Err(anyhow!("upstream {name}: H3 HTTP/3 {}", response.status()));
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
                    Err(e) => return Err(anyhow!("upstream {name}: H3 recv_data failed: {e}")),
                }
            }
            Ok(body)
        };

        let result = tokio::time::timeout(self.timeout, fut).await.map_err(|e| {
            anyhow::Error::from(e).context(format!("upstream {}: H3 timeout", self.name))
        })?;

        // On connection-level failure, evict the stored connection so the next query
        // reconnects.  Stream/HTTP errors do not evict the connection.
        if result.is_err() {
            let guard = self.connection.lock().await;
            if let Some(conn) = guard.as_ref() {
                if conn.quic.close_reason().is_some() {
                    drop(guard);
                    *self.connection.lock().await = None;
                }
            }
        }

        result
    }
}
