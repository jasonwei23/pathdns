use super::*;
use crate::dns;
use tokio::net::TcpListener;

/// Build a minimal A-record query for `label.` (single label, no EDNS).
/// Layout: 12-byte header + qname + qtype(A) + qclass(IN).
fn make_query(label: &[u8]) -> (Vec<u8>, Bytes) {
    let mut pkt = Vec::new();
    pkt.extend_from_slice(&[0x00, 0x00]); // id (overwritten by exchange)
    pkt.extend_from_slice(&[0x01, 0x00]); // flags: RD=1
    pkt.extend_from_slice(&[0x00, 0x01]); // qdcount=1
    pkt.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x00, 0x00]); // an/ns/ar=0
    pkt.push(label.len() as u8);
    pkt.extend_from_slice(label);
    pkt.push(0x00); // root
    pkt.extend_from_slice(&[0x00, 0x01]); // qtype A
    pkt.extend_from_slice(&[0x00, 0x01]); // qclass IN
    let question = Bytes::copy_from_slice(&pkt[12..]);
    (pkt, question)
}

/// A mock DNS-over-TCP server that echoes each framed query back as a response
/// (QR=1) on the same connection, exercising the mux read/write/coalesce path.
async fn spawn_echo_server() -> SocketAddr {
    let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
        .await
        .unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        loop {
            let mut len_buf = [0u8; 2];
            if stream.read_exact(&mut len_buf).await.is_err() {
                return;
            }
            let len = u16::from_be_bytes(len_buf) as usize;
            let mut body = vec![0u8; len];
            if stream.read_exact(&mut body).await.is_err() {
                return;
            }
            body[2] |= 0x80; // set QR=1 -> it is now a reply
            let mut framed = Vec::with_capacity(2 + len);
            framed.extend_from_slice(&(len as u16).to_be_bytes());
            framed.extend_from_slice(&body);
            if stream.write_all(&framed).await.is_err() {
                return;
            }
        }
    });
    addr
}

fn test_mux(addr: SocketAddr) -> TcpMux {
    TcpMux::new(
        "test".to_string(),
        addr,
        Duration::from_secs(5),
        MuxConnector::Tcp,
        0,
        EcsMode::Forward,
        0,
        None,
    )
}

#[tokio::test]
async fn single_query_round_trips() {
    let addr = spawn_echo_server().await;
    let mux = test_mux(addr);
    let (pkt, question) = make_query(b"example");
    let resp = mux
        .exchange(UpstreamRequest {
            packet: Bytes::from(pkt),
            client_id: 0x1234,
            question,
        })
        .await
        .expect("exchange should succeed");
    // ID is rewritten back to the client's.
    assert_eq!(dns::get_id(&resp).unwrap(), 0x1234);
    assert_eq!(resp[2] & 0x80, 0x80); // QR set
}

#[tokio::test]
async fn concurrent_queries_are_not_cross_wired() {
    let addr = spawn_echo_server().await;
    let mux = Arc::new(test_mux(addr));

    // Fire many concurrent queries with distinct client IDs and qnames so the
    // coalescing writer and the shared inflight table must keep them apart.
    let mut handles = Vec::new();
    for i in 0u16..64 {
        let mux = mux.clone();
        handles.push(tokio::spawn(async move {
            let label = format!("h{i}");
            let (pkt, question) = make_query(label.as_bytes());
            let resp = mux
                .exchange(UpstreamRequest {
                    packet: Bytes::from(pkt),
                    client_id: 0x4000 + i,
                    question: question.clone(),
                })
                .await
                .expect("exchange should succeed");
            // Response carries this query's client ID and its own question bytes.
            // Compare case-insensitively (the registry matches questions that way).
            assert_eq!(dns::get_id(&resp).unwrap(), 0x4000 + i);
            let qend = dns::question_end(&resp).unwrap();
            assert!(resp[12..qend].eq_ignore_ascii_case(&question[..]));
        }));
    }
    for h in handles {
        h.await.expect("task should not panic");
    }
}
