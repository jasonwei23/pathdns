use super::{apply_ecs_mode, mix16, random_id_seed, UpstreamRequest};
use crate::config::EcsMode;
use crate::dns;
use anyhow::{anyhow, Result};
use bytes::Bytes;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

// DNS-over-HTTPS upstream using reqwest (HTTP/2 via ALPN).
//
// One `reqwest::Client` per upstream; reqwest maintains a connection pool
// and negotiates HTTP/2 via ALPN when the server supports it, enabling
// concurrent pipelined requests on a single TLS connection.
//
// The server IP is supplied directly via `.resolve()` so DNS is bypassed
// while the server_name is still used for SNI and the Host header.

pub(super) struct DoHUpstream {
    pub(super) name: String,
    client: reqwest::Client,
    url: String,
    timeout: Duration,
    ecs_mode: EcsMode,
    next_id: AtomicU32,
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
        let url = format!("https://{server_name}{path}");
        let client = reqwest::Client::builder()
            .resolve(&server_name, remote)
            .https_only(true)
            .timeout(timeout)
            .build()
            .map_err(|e| anyhow!("upstream {name}: failed to build DoH client: {e}"))?;
        Ok(Self {
            name,
            client,
            url,
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

        let response = tokio::time::timeout(
            self.timeout,
            self.client
                .post(&self.url)
                .header("Content-Type", "application/dns-message")
                .header("Accept", "application/dns-message")
                .body(pkt)
                .send(),
        )
        .await
        .map_err(|_| anyhow!("upstream {}: DoH timeout", self.name))?
        .map_err(|e| anyhow!("upstream {}: DoH request failed: {e}", self.name))?;

        if !response.status().is_success() {
            return Err(anyhow!(
                "upstream {}: DoH HTTP {}",
                self.name,
                response.status().as_u16()
            ));
        }

        let body = tokio::time::timeout(self.timeout, response.bytes())
            .await
            .map_err(|_| anyhow!("upstream {}: DoH body read timeout", self.name))?
            .map_err(|e| anyhow!("upstream {}: DoH body read: {e}", self.name))?;

        if body.len() > 65_535 {
            return Err(anyhow!(
                "upstream {}: DoH response too large ({} bytes)",
                self.name,
                body.len()
            ));
        }

        let mut body = body.to_vec();
        super::validate_upstream_response(&body, upstream_id, &req.question)
            .map_err(|e| anyhow!("upstream {}: DoH {e}", self.name))?;
        dns::set_id(&mut body, req.client_id)?;
        Ok(Bytes::from(body))
    }
}
