use super::*;

const DEFAULT_SELECT_BAND_FACTOR: u64 = 2;

/// Read back SO_MARK from a socket fd to verify it was applied.
fn get_so_mark(fd: libc::c_int) -> u32 {
    sys::get_socket_u32(fd, libc::SOL_SOCKET, libc::SO_MARK).expect("getsockopt(SO_MARK) failed")
}

#[test]
fn set_so_mark_roundtrip() {
    if !so_mark_supported() {
        eprintln!("skipping set_so_mark_roundtrip: SO_MARK requires CAP_NET_ADMIN");
        return;
    }
    // setsockopt then getsockopt must agree — confirms the value reaches the kernel.
    let sock = std::net::UdpSocket::bind(("127.0.0.1", 0)).unwrap();
    let fd = std::os::unix::io::AsRawFd::as_raw_fd(&sock);
    set_so_mark(fd, 0x1234).expect("set_so_mark");
    assert_eq!(get_so_mark(fd), 0x1234);
}

#[tokio::test]
async fn connect_tcp_nodelay_applies_mark() {
    if !so_mark_supported() {
        eprintln!("skipping connect_tcp_nodelay_applies_mark: SO_MARK requires CAP_NET_ADMIN");
        return;
    }
    // The shared TCP connect path (used by tcp://, tls://, https:// and the TC
    // fallback) must stamp SO_MARK on the socket. Verified by reading it back.
    use std::os::unix::io::AsRawFd;
    let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
    let addr = listener.local_addr().unwrap();
    std::thread::spawn(move || {
        let _ = listener.accept();
        std::thread::sleep(std::time::Duration::from_millis(50));
    });

    let stream = connect_tcp_nodelay(addr, Duration::from_secs(2), "test", Some(0x4d2))
        .await
        .expect("connect with mark");
    assert_eq!(get_so_mark(stream.as_raw_fd()), 0x4d2);

    // And without a mark the socket stays unmarked (0).
    let listener2 = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
    let addr2 = listener2.local_addr().unwrap();
    std::thread::spawn(move || {
        let _ = listener2.accept();
        std::thread::sleep(std::time::Duration::from_millis(50));
    });
    let plain = connect_tcp_nodelay(addr2, Duration::from_secs(2), "test", None)
        .await
        .expect("connect without mark");
    assert_eq!(get_so_mark(plain.as_raw_fd()), 0);
}

fn default_health() -> HealthStats {
    HealthStats::new(0)
}

#[test]
fn failure_inflates_rtt_estimate() {
    let h = default_health();
    h.record_success(20_000);
    assert_eq!(h.ewma_rtt_us.load(Ordering::Relaxed), 20_000);

    // First failure: 20_000 * 2 = 40_000 < floor, so the floor applies.
    h.record_failure(false);
    assert_eq!(h.ewma_rtt_us.load(Ordering::Relaxed), FAILURE_RTT_FLOOR_US);

    // Subsequent failures double the estimate.
    h.record_failure(false);
    assert_eq!(
        h.ewma_rtt_us.load(Ordering::Relaxed),
        FAILURE_RTT_FLOOR_US * 2
    );
}

#[test]
fn failure_inflation_is_capped() {
    let h = default_health();
    h.record_success(8_000_000);
    h.record_failure(false);
    assert_eq!(h.ewma_rtt_us.load(Ordering::Relaxed), FAILURE_RTT_CAP_US);
    h.record_failure(false);
    assert_eq!(h.ewma_rtt_us.load(Ordering::Relaxed), FAILURE_RTT_CAP_US);
}

#[test]
fn failure_with_no_data_uses_floor() {
    let h = default_health();
    h.record_failure(false);
    assert_eq!(h.ewma_rtt_us.load(Ordering::Relaxed), FAILURE_RTT_FLOOR_US);
}

#[test]
fn success_after_failure_adopts_fresh_sample() {
    let h = default_health();
    h.record_success(20_000);
    h.record_failure(false);
    h.record_failure(false);
    // Recovery: fresh sample replaces the inflated estimate outright.
    h.record_success(22_000);
    assert_eq!(h.ewma_rtt_us.load(Ordering::Relaxed), 22_000);
    assert_eq!(h.consecutive_failures.load(Ordering::Relaxed), 0);
}

#[test]
fn steady_state_success_blends_ewma() {
    let h = default_health();
    h.record_success(20_000);
    h.record_success(40_000);
    // 0.75 * 20_000 + 0.25 * 40_000 = 25_000
    assert_eq!(h.ewma_rtt_us.load(Ordering::Relaxed), 25_000);
}

#[test]
fn band_limit_floor_and_factor() {
    // No data / zero best: floor only.
    assert_eq!(
        band_limit(0, DEFAULT_SELECT_BAND_FACTOR, SELECT_BAND_FLOOR_US),
        SELECT_BAND_FLOOR_US
    );
    // Sub-millisecond best: additive floor dominates (500*2 < 500+2000).
    assert_eq!(
        band_limit(500, DEFAULT_SELECT_BAND_FACTOR, SELECT_BAND_FLOOR_US),
        500 + SELECT_BAND_FLOOR_US
    );
    // Above the floor crossover: multiplicative factor dominates.
    assert_eq!(
        band_limit(10_000, DEFAULT_SELECT_BAND_FACTOR, SELECT_BAND_FLOOR_US),
        20_000
    );
}
