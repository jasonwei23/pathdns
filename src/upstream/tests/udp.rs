use super::*;

#[test]
fn icmp_unreachable_classification() {
    use std::io::Error;
    assert!(is_icmp_unreachable(&Error::from_raw_os_error(
        libc::ECONNREFUSED
    )));
    assert!(is_icmp_unreachable(&Error::from_raw_os_error(
        libc::EHOSTUNREACH
    )));
    assert!(is_icmp_unreachable(&Error::from_raw_os_error(
        libc::ENETUNREACH
    )));
    assert!(!is_icmp_unreachable(&Error::from_raw_os_error(
        libc::EAGAIN
    )));
    assert!(!is_icmp_unreachable(&Error::from_raw_os_error(
        libc::ECONNRESET
    )));
}

#[test]
fn ip_recverr_delivers_icmp_to_error_queue() {
    // Connect to a closed loopback port: the kernel returns ICMP port-unreachable,
    // which IP_RECVERR must route to the error queue for drain_error_queue to clear.
    let sock = std::net::UdpSocket::bind(("127.0.0.1", 0)).unwrap();
    let fd = sock.as_raw_fd();
    set_recverr(fd, false);
    sock.connect(("127.0.0.1", 1)).unwrap();
    sock.set_nonblocking(true).unwrap();
    let _ = sock.send(b"x");
    std::thread::sleep(std::time::Duration::from_millis(40));
    // A normal recv reports the ICMP error and our classifier recognises it.
    let mut buf = [0u8; 64];
    if let Err(e) = sock.recv(&mut buf) {
        assert!(
            is_icmp_unreachable(&e),
            "expected ICMP unreachable from closed port, got {e:?}"
        );
    }
    // The error also sits in the error queue; draining must consume it.
    assert!(
        drain_error_queue(fd) >= 1,
        "IP_RECVERR error queue should contain the ICMP error"
    );
}

/// The UDP egress socket must carry the configured SO_MARK (read back to verify).
#[tokio::test]
async fn udp_upstream_applies_so_mark() {
    if !super::super::so_mark_supported() {
        eprintln!("skipping udp_upstream_applies_so_mark: SO_MARK requires CAP_NET_ADMIN");
        return;
    }
    use std::os::unix::io::AsRawFd;
    // Remote need not exist: UDP connect() just sets the default peer.
    let remote: SocketAddr = "127.0.0.1:9".parse().unwrap();
    let up = UdpUpstream::create(
        "test".to_string(),
        remote,
        Duration::from_secs(1),
        1,
        0,
        0,
        EcsMode::Forward,
        Some(0xabc),
    )
    .await
    .expect("create with mark (needs CAP_NET_ADMIN)");

    let fd = up.sockets[0].as_raw_fd();
    let val = sys::get_socket_u32(fd, libc::SOL_SOCKET, libc::SO_MARK)
        .expect("getsockopt(SO_MARK) failed");
    assert_eq!(val, 0xabc, "UDP upstream socket did not carry the fwmark");
}
