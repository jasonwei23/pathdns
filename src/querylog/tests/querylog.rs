use super::*;

fn event(seq: u64) -> QueryLogEvent {
    QueryLogEvent {
        seq,
        unix_micros: 0,
        client: "127.0.0.1".parse().unwrap(),
        client_port: 53,
        qname: Arc::from("example.com"),
        qtype: 1,
        rcode: 0,
        elapsed_us: 1,
        response_bytes: 32,
        source: "cache",
        rule: None,
        answer_ips: smallvec::SmallVec::new(),
    }
}

#[test]
fn disabled_config_has_no_event_channel() {
    let (handle, worker, _, _, _) = build(QueryLogConfig {
        enabled: false,
        memory: 1000,
        channel: 4096,
        answer_ips: false,
        file: None,
    });
    assert!(!handle.collecting());
    assert!(worker.is_none());
}

#[test]
fn full_channel_is_counted_without_blocking() {
    let (handle, worker, _, _, _) = build(QueryLogConfig {
        enabled: true,
        memory: 1,
        channel: 1,
        answer_ips: false,
        file: None,
    });
    let _worker = worker.unwrap();
    for _ in 0..65 {
        handle.try_emit_with(event);
    }
    assert_eq!(handle.counters.events_enqueued.load(Ordering::Relaxed), 64);
    assert_eq!(
        handle.counters.events_dropped_full.load(Ordering::Relaxed),
        1
    );
}

#[tokio::test]
async fn worker_drains_events_during_shutdown() {
    let (handle, worker, _, _, shutdown) = build(QueryLogConfig {
        enabled: true,
        memory: 4,
        channel: 64,
        answer_ips: false,
        file: None,
    });
    let worker = worker.unwrap();
    let ring = worker.ring.clone();
    let counters = handle.counters.clone();
    let task = tokio::spawn(crate::querylog::worker::run(
        worker.rx,
        worker.ring,
        worker.counters,
        worker.file_cfg,
        worker.shutdown,
    ));
    handle.try_emit_with(event);
    handle.try_emit_with(event);
    handle.try_emit_with(event);
    shutdown.send(true).unwrap();
    task.await.unwrap();
    assert_eq!(ring.len(), 3);
    assert_eq!(counters.events_processed.load(Ordering::Relaxed), 3);
}
