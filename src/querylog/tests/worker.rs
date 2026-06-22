use super::*;
use std::io::Write as _;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::atomic::{AtomicU64, Ordering};

static TEMP_ID: AtomicU64 = AtomicU64::new(0);

fn event(seq: u64, unix_micros: u64) -> Arc<QueryLogEvent> {
    Arc::new(QueryLogEvent {
        seq,
        unix_micros,
        client: IpAddr::V4(Ipv4Addr::LOCALHOST),
        client_port: 53,
        qname: Arc::from(format!("host-{seq}.example")),
        qtype: 1,
        rcode: if seq.is_multiple_of(2) { 0 } else { 3 },
        elapsed_us: seq,
        response_bytes: 32,
        source: if seq.is_multiple_of(2) {
            "cache"
        } else {
            "upstream"
        },
        rule: None,
        answer_ips: smallvec::SmallVec::new(),
    })
}

fn temp_config() -> QueryLogFileConfig {
    let unique = super::super::unix_micros_now();
    let id = TEMP_ID.fetch_add(1, Ordering::Relaxed);
    QueryLogFileConfig {
        dir: std::env::temp_dir().join(format!(
            "pathdns-history-index-{}-{unique}-{id}",
            std::process::id(),
        )),
        max_mb: 64,
        max_segments: 3,
        batch_size: 300,
        flush_interval_ms: 100,
        retention_days: None,
        compress: true,
    }
}

#[tokio::test]
async fn indexed_history_supports_metadata_time_filter_and_gzip_paging() {
    let cfg = temp_config();
    tokio::fs::create_dir_all(&cfg.dir).await.unwrap();
    let mut state = MsgpackFileState::open(&cfg).await.unwrap();
    let first: Vec<_> = (0..300).map(|n| event(n, 1_000 + n)).collect();
    let second: Vec<_> = (300..600).map(|n| event(n, 1_000 + n)).collect();
    state.append_batch(&first, &cfg).await.unwrap();
    state.append_batch(&second, &cfg).await.unwrap();
    state.flush().await.unwrap();
    let plain_path = state.path.clone();
    drop(state);

    let files = list_history_files(&cfg.dir);
    assert_eq!(files.len(), 1);
    assert_eq!(files[0].total_entries, Some(600));
    assert_eq!(files[0].start_micros, Some(1_000));
    assert_eq!(files[0].end_micros, Some(1_599));

    let query = HistoryQuery {
        limit: 25,
        cursor: None,
        from_micros: Some(1_250),
        to_micros: Some(1_350),
        qname: None,
        rcode: Some(0),
        source: Some("cache".to_string()),
    };
    let first_page = read_history_page(&plain_path, &query).unwrap();
    assert_eq!(first_page.events.len(), 25);
    assert_eq!(first_page.events[0].seq, 250);
    assert!(first_page.has_more);

    compress_to_gz(&plain_path).unwrap();
    let gz_path = PathBuf::from(format!("{}.gz", plain_path.display()));
    let second_page = read_history_page(
        &gz_path,
        &HistoryQuery {
            cursor: first_page.next_cursor,
            ..query
        },
    )
    .unwrap();
    assert_eq!(second_page.events[0].seq, 300);
    assert_eq!(second_page.total_entries, Some(600));
    assert!(second_page.indexed);

    let _ = std::fs::remove_dir_all(&cfg.dir);
}

#[tokio::test]
async fn stale_sidecar_falls_back_without_hiding_persisted_events() {
    let cfg = temp_config();
    tokio::fs::create_dir_all(&cfg.dir).await.unwrap();
    let mut state = MsgpackFileState::open(&cfg).await.unwrap();
    state.append_batch(&[event(1, 1_000)], &cfg).await.unwrap();
    state.flush().await.unwrap();
    let path = state.path.clone();
    drop(state);

    // Append a second event directly to the file, bypassing the index.
    let mut encoded = Vec::new();
    rmp_serde::encode::write_named(&mut encoded, event(2, 2_000).as_ref()).unwrap();
    std::fs::OpenOptions::new()
        .append(true)
        .open(&path)
        .unwrap()
        .write_all(&encoded)
        .unwrap();

    // The index now covers fewer bytes than the file → load_index fails.
    let files = list_history_files(&cfg.dir);
    assert!(!files[0].indexed);
    assert_eq!(files[0].total_entries, None);

    let page = read_history_page(
        &path,
        &HistoryQuery {
            limit: 100,
            cursor: None,
            from_micros: None,
            to_micros: None,
            qname: None,
            rcode: None,
            source: None,
        },
    )
    .unwrap();
    assert_eq!(page.events.len(), 2);
    assert!(!page.indexed);

    let _ = std::fs::remove_dir_all(&cfg.dir);
}
