use super::*;
use std::net::{Ipv4Addr, UdpSocket as StdUdp};

#[test]
fn multishot_recvmsg_delivers_datagrams() {
    // End-to-end: arm a multishot recvmsg, fire several datagrams of distinct
    // sizes, and confirm each is delivered with the right payload and peer.
    let server = StdUdp::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let addr = server.local_addr().unwrap();
    let mut recv = UringRecv::new(server.as_raw_fd(), 64, 2048).unwrap();
    recv.arm().unwrap();

    let sender = StdUdp::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let sender_addr = sender.local_addr().unwrap();
    let payloads: [&[u8]; 4] = [b"a", b"bb", b"ccc", &[0x7f; 500]];
    for p in payloads {
        sender.send_to(p, addr).unwrap();
    }

    // Collect until we've seen all four (multishot posts one CQE per packet).
    let mut got: Vec<Vec<u8>> = Vec::new();
    for _ in 0..8 {
        recv.ring.submit_and_wait(1).unwrap();
        recv.drain(|payload, peer| {
            assert_eq!(peer, sender_addr, "source address mismatch");
            got.push(payload.to_vec());
        });
        if got.len() >= payloads.len() {
            break;
        }
    }

    assert_eq!(got.len(), payloads.len(), "not all datagrams delivered");
    for p in payloads {
        assert!(
            got.iter().any(|g| g.as_slice() == p),
            "missing a datagram of len {}",
            p.len()
        );
    }
}

#[test]
fn buffer_recycling_outlasts_the_ring_size() {
    // Send far more datagrams than there are provided buffers, draining between
    // bursts. Correct recycling means every packet is eventually delivered.
    let server = StdUdp::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let addr = server.local_addr().unwrap();
    let entries = 8u16;
    let mut recv = UringRecv::new(server.as_raw_fd(), entries, 256).unwrap();
    recv.arm().unwrap();

    let sender = StdUdp::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let total = 100u32;
    let mut received = 0u32;
    for i in 0..total {
        sender.send_to(&[i as u8; 20], addr).unwrap();
        // Drain frequently so buffers recycle and never run dry.
        recv.ring.submit_and_wait(1).unwrap();
        loop {
            let stats = recv.drain(|_, _| {});
            received += stats.packets as u32;
            if recv.needs_arm() {
                recv.arm().unwrap();
            }
            if stats.packets == 0 {
                break;
            }
        }
    }
    assert_eq!(received, total, "buffer recycling lost datagrams");
}

#[test]
fn multishot_recvmsg_surfaces_recv_timestamp() {
    // With SO_TIMESTAMPNS enabled, the kernel receive timestamp must come through
    // the multishot recvmsg control data so we can measure ingress latency.
    let server = StdUdp::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let addr = server.local_addr().unwrap();
    let fd = server.as_raw_fd();
    let on: libc::c_int = 1;
    sys::set_socket_i32(fd, libc::SOL_SOCKET, libc::SO_TIMESTAMPNS, on).unwrap();
    let mut recv = UringRecv::new(fd, 8, 2048).unwrap();
    recv.arm().unwrap();
    let sender = StdUdp::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    sender.send_to(b"hi", addr).unwrap();
    // Sleep so the measured kernel→drain latency is unambiguously non-zero.
    std::thread::sleep(Duration::from_millis(15));
    recv.ring.submit_and_wait(1).unwrap();
    let stats = recv.drain(|_, _| {});
    assert!(
        stats.recv_lat_us > 0,
        "SO_TIMESTAMPNS not surfaced via multishot recvmsg control data"
    );
}

#[test]
fn recv_latency_clamps_negative_skew_to_zero() {
    let a = libc::timespec {
        tv_sec: 100,
        tv_nsec: 0,
    };
    let b = libc::timespec {
        tv_sec: 100,
        tv_nsec: 500_000,
    }; // 500µs later than `a`
    assert_eq!(recv_latency_us(&b, &a), 500);
    assert_eq!(recv_latency_us(&a, &b), 0); // now < ts → clamped
    let earliest = libc::timespec {
        tv_sec: i64::MIN,
        tv_nsec: 0,
    };
    let latest = libc::timespec {
        tv_sec: i64::MAX,
        tv_nsec: 999_999_999,
    };
    assert_eq!(recv_latency_us(&latest, &earliest), u32::MAX);
}

#[test]
fn multishot_recvmsg_surfaces_rxq_overflow() {
    // With SO_RXQ_OVFL enabled and a tiny receive buffer, flooding the socket
    // makes the kernel stamp later packets with the cumulative drop count, which
    // must surface through the multishot recvmsg control data.
    let server = StdUdp::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let addr = server.local_addr().unwrap();
    let fd = server.as_raw_fd();
    let rcvbuf: libc::c_int = 1024;
    let one: libc::c_int = 1;
    sys::set_socket_i32(fd, libc::SOL_SOCKET, libc::SO_RCVBUF, rcvbuf).unwrap();
    sys::set_socket_i32(fd, libc::SOL_SOCKET, libc::SO_RXQ_OVFL, one).unwrap();

    let mut recv = UringRecv::new(fd, 8, 2048).unwrap();
    recv.arm().unwrap();
    let sender = StdUdp::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();

    let mut max_overflow = 0u32;
    // Two phases: the first flood overflows the buffer (drained packets predate
    // the drops); fresh packets sent afterwards carry the accumulated count.
    for round in 0..2 {
        let count = if round == 0 { 5000 } else { 50 };
        for i in 0..count {
            let _ = sender.send_to(&[i as u8; 20], addr);
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
        for _ in 0..512 {
            let stats = recv.drain(|_, _| {});
            if let Some(v) = stats.rx_overflow {
                max_overflow = max_overflow.max(v);
            }
            if recv.needs_arm() {
                recv.arm().unwrap();
            }
            if stats.packets == 0 && stats.rx_overflow.is_none() {
                break;
            }
        }
    }

    assert!(
        max_overflow > 0,
        "SO_RXQ_OVFL not surfaced via multishot recvmsg control data"
    );
}

#[test]
fn supported_returns_true_on_this_kernel() {
    // The CI/dev kernel here is recent enough; this guards the probe wiring.
    assert!(supported(), "io_uring multishot recvmsg probe failed");
}

#[test]
fn invalid_buffer_ring_config_returns_error_instead_of_panicking() {
    assert!(ProvidedBufRing::new(0, 256).is_err());
    assert!(ProvidedBufRing::new(7, 256).is_err());
    assert!(ProvidedBufRing::new(8, 0).is_err());
}

#[test]
fn malformed_control_messages_are_ignored() {
    let mut short = vec![0u8; mem::size_of::<libc::cmsghdr>()];
    assert!(parse_control(&short).rxq_overflow.is_none());

    short[..mem::size_of::<usize>()].copy_from_slice(&usize::MAX.to_ne_bytes());
    let parsed = parse_control(&short);
    assert!(parsed.rxq_overflow.is_none());
    assert!(parsed.timestamp.is_none());
}

#[test]
fn parses_rxq_overflow_control_message_without_raw_pointers() {
    let header_len = align_up(
        mem::size_of::<libc::cmsghdr>(),
        mem::align_of::<libc::cmsghdr>(),
    );
    let cmsg_len = header_len + mem::size_of::<u32>();
    let mut control = vec![0u8; align_up(cmsg_len, mem::align_of::<libc::cmsghdr>())];
    control[..mem::size_of::<usize>()].copy_from_slice(&cmsg_len.to_ne_bytes());
    let level_offset = mem::size_of::<usize>();
    control[level_offset..level_offset + mem::size_of::<libc::c_int>()]
        .copy_from_slice(&libc::SOL_SOCKET.to_ne_bytes());
    let type_offset = level_offset + mem::size_of::<libc::c_int>();
    control[type_offset..type_offset + mem::size_of::<libc::c_int>()]
        .copy_from_slice(&libc::SO_RXQ_OVFL.to_ne_bytes());
    control[header_len..cmsg_len].copy_from_slice(&42u32.to_ne_bytes());

    assert_eq!(parse_control(&control).rxq_overflow, Some(42));
}
