use super::{
    apply_ecs_mode, connect_tcp_nodelay, make_tls_config, mix16, random_id_seed, UpstreamRequest,
};
use crate::config::EcsMode;
use crate::dns;
use anyhow::{anyhow, Context, Result};
use bytes::Bytes;
use rustls::pki_types::ServerName;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

// DNS-over-HTTPS (DoH) HTTP/1.1 upstream.
//
// Maintains a single persistent TLS connection per upstream, serialising
// HTTP/1.1 request/response cycles on it.  Serialisation is enforced by a
// `Mutex<Option<DoHStream>>` that is held for the full round-trip.
//
// When the idle connection has been closed by the server (detected as an I/O
// error on the first write), a new TLS handshake is performed and the request
// is retried once on the fresh connection.  Under sustained failure a new
// handshake attempt is made on every query (there is no per-upstream backoff
// here; the node-level `HealthStats` penalty window already throttles the
// calling pool).

/// Concrete type of a DoH TLS stream.
type DoHStream = tokio_rustls::client::TlsStream<TcpStream>;

pub(super) struct DoHUpstream {
    pub(super) name: String,
    remote: SocketAddr,
    /// TLS SNI / ALPN hostname.
    server_name: String,
    /// HTTP/1.1 Host header (server_name + port when non-443).
    host: String,
    path: String,
    timeout: Duration,
    tls_config: Arc<rustls::ClientConfig>,
    ecs_mode: EcsMode,
    next_id: AtomicU32,
    /// Persistent HTTP/1.1 connection.  Locked for the full request/response cycle
    /// (HTTP/1.1 is not multiplexed; serialise requests on a single connection).
    conn: tokio::sync::Mutex<Option<DoHStream>>,
}

impl DoHUpstream {
    pub(super) fn new(
        name: String,
        remote: SocketAddr,
        server_name: String,
        path: String,
        timeout: Duration,
        ecs_mode: EcsMode,
    ) -> Self {
        let host = if remote.port() == 443 {
            server_name.clone()
        } else {
            format!("{}:{}", server_name, remote.port())
        };
        Self {
            name,
            remote,
            server_name,
            host,
            path,
            timeout,
            tls_config: make_tls_config(),
            ecs_mode,
            next_id: AtomicU32::new(random_id_seed()),
            conn: tokio::sync::Mutex::new(None),
        }
    }

    pub(super) async fn exchange(&self, req: UpstreamRequest) -> Result<Bytes> {
        let raw = apply_ecs_mode(&req.packet, &self.ecs_mode);
        let mut pkt = raw.to_vec();
        let upstream_id = mix16(self.next_id.fetch_add(1, Ordering::Relaxed));
        dns::set_id(&mut pkt, upstream_id)?;

        let mut body = tokio::time::timeout(self.timeout, self.exchange_pooled(&pkt))
            .await
            .map_err(|_| anyhow!("upstream {}: DoH timeout", self.name))??;
        super::validate_upstream_response(&body, upstream_id, &req.question)
            .map_err(|e| anyhow!("upstream {}: DoH {e}", self.name))?;
        dns::set_id(&mut body, req.client_id)?;
        Ok(Bytes::from(body))
    }

    /// Send one DNS query over the persistent connection, reconnecting when needed.
    ///
    /// The `conn` mutex is held for the full request/response cycle so HTTP/1.1
    /// requests are serialised.  The timeout wrapping this call is applied by
    /// `exchange()`.
    async fn exchange_pooled(&self, pkt: &[u8]) -> Result<Vec<u8>> {
        let mut guard = self.conn.lock().await;

        // Try reusing the existing connection first.
        if let Some(mut stream) = guard.take() {
            match doh_send_request(&mut stream, &self.host, &self.path, pkt, &self.name).await {
                Ok((body, want_close)) => {
                    if !want_close {
                        *guard = Some(stream);
                    }
                    return Ok(body);
                }
                Err(_) => {
                    // Stale/broken connection; fall through and establish a new one.
                }
            }
        }

        // Establish a fresh TLS connection.
        let mut stream = doh_new_conn(
            self.remote,
            &self.server_name,
            &self.tls_config,
            self.timeout,
            &self.name,
        )
        .await?;
        let (body, want_close) =
            doh_send_request(&mut stream, &self.host, &self.path, pkt, &self.name).await?;
        if !want_close {
            *guard = Some(stream);
        }
        Ok(body)
    }
}

/// Open a fresh TLS connection to a DoH upstream.
async fn doh_new_conn(
    remote: SocketAddr,
    server_name: &str,
    tls_config: &Arc<rustls::ClientConfig>,
    timeout: Duration,
    name: &str,
) -> Result<DoHStream> {
    let tls_name = ServerName::try_from(server_name.to_string())
        .map_err(|e| anyhow!("upstream {name}: invalid DoH server name '{server_name}': {e}"))?;
    let tcp = connect_tcp_nodelay(remote, timeout, name).await?;
    let connector = tokio_rustls::TlsConnector::from(tls_config.clone());
    connector
        .connect(tls_name, tcp)
        .await
        .with_context(|| format!("upstream {name}: DoH TLS handshake failed"))
}

/// Send one HTTP/1.1 POST on an existing DoH stream.
///
/// Returns `(body, want_close)` where `want_close` is true when the server
/// responded with `Connection: close` and the stream should not be reused.
async fn doh_send_request(
    stream: &mut DoHStream,
    http_host: &str,
    path: &str,
    pkt: &[u8],
    name: &str,
) -> Result<(Vec<u8>, bool)> {
    let req_header = format!(
        "POST {path} HTTP/1.1\r\nHost: {http_host}\r\nContent-Type: application/dns-message\r\nAccept: application/dns-message\r\nContent-Length: {}\r\nConnection: keep-alive\r\n\r\n",
        pkt.len()
    );
    stream.write_all(req_header.as_bytes()).await?;
    stream.write_all(pkt).await?;
    stream.flush().await?;

    let (status, body_len, body_prefix, want_close) =
        doh_read_response_headers(stream, name).await?;
    if status != 200 {
        return Err(anyhow!("upstream {name}: DoH HTTP {status}"));
    }
    if body_len > 65_535 {
        return Err(anyhow!(
            "upstream {name}: DoH body too large ({body_len} bytes)"
        ));
    }

    let pre = body_prefix.len();
    if pre > body_len {
        return Err(anyhow!("upstream {name}: DoH body overflow"));
    }
    let mut body = body_prefix;
    body.resize(body_len, 0);
    if pre < body_len {
        stream
            .read_exact(&mut body[pre..])
            .await
            .with_context(|| format!("upstream {name}: DoH body read failed"))?;
    }
    Ok((body, want_close))
}

/// Read HTTP/1.1 response headers; return (status, content-length, body-prefix, want-close).
/// `want_close` is true when the server sent `Connection: close`.
async fn doh_read_response_headers(
    stream: &mut (impl AsyncRead + Unpin),
    name: &str,
) -> Result<(u16, usize, Vec<u8>, bool)> {
    let mut buf: Vec<u8> = Vec::with_capacity(1024);
    let mut tmp = [0u8; 512];
    let header_end;
    loop {
        let n = stream.read(&mut tmp).await?;
        if n == 0 {
            return Err(anyhow!(
                "upstream {name}: DoH connection closed during header read"
            ));
        }
        buf.extend_from_slice(&tmp[..n]);
        if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            header_end = pos;
            break;
        }
        if buf.len() > 16_384 {
            return Err(anyhow!(
                "upstream {name}: DoH response headers exceed 16 KiB"
            ));
        }
    }
    let hdr = std::str::from_utf8(&buf[..header_end])
        .map_err(|_| anyhow!("upstream {name}: DoH response headers are not UTF-8"))?;

    let status = doh_parse_status(hdr, name)?;
    let body_len = doh_parse_content_length(hdr, name)?;
    let want_close = doh_parse_want_close(hdr);
    let body_prefix = buf[header_end + 4..].to_vec();
    Ok((status, body_len, body_prefix, want_close))
}

/// Returns `true` when the response headers contain `Connection: close`.
fn doh_parse_want_close(headers: &str) -> bool {
    for line in headers.lines().skip(1) {
        if let Some((key, val)) = line.split_once(':') {
            if key.trim().eq_ignore_ascii_case("connection") {
                return val
                    .split(',')
                    .any(|t| t.trim().eq_ignore_ascii_case("close"));
            }
        }
    }
    false
}

fn doh_parse_status(headers: &str, name: &str) -> Result<u16> {
    let line = headers
        .lines()
        .next()
        .ok_or_else(|| anyhow!("upstream {name}: empty DoH response"))?;
    let code = line
        .split(' ')
        .nth(1)
        .ok_or_else(|| anyhow!("upstream {name}: malformed DoH status line"))?;
    code.parse::<u16>()
        .map_err(|_| anyhow!("upstream {name}: invalid DoH status code: {code}"))
}

fn doh_parse_content_length(headers: &str, name: &str) -> Result<usize> {
    for line in headers.lines().skip(1) {
        let Some((key, val)) = line.split_once(':') else {
            continue;
        };
        if key.trim().eq_ignore_ascii_case("content-length") {
            let v = val.trim();
            return v
                .parse::<usize>()
                .map_err(|_| anyhow!("upstream {name}: invalid DoH Content-Length: {v}"));
        }
    }
    Err(anyhow!(
        "upstream {name}: DoH response missing Content-Length"
    ))
}
