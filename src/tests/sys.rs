use super::*;

#[test]
fn sockaddr_bytes_roundtrip() {
    for address in ["127.0.0.1:5353", "[::1]:5353"] {
        let original: SocketAddr = address.parse().expect("valid fixture");
        // Exercise the same private encoder used by sendmmsg.
        // SAFETY: all-zero is a valid sockaddr_storage representation.
        let mut storage: libc::sockaddr_storage = unsafe { mem::zeroed() };
        let len = write_sockaddr(original, &mut storage) as usize;
        // SAFETY: storage is live and initialized for `len` bytes.
        let bytes = unsafe { std::slice::from_raw_parts(&storage as *const _ as *const u8, len) };
        assert_eq!(read_sockaddr_bytes(bytes), Some(original));
    }
}

#[test]
fn send_batch_rejects_capacity_overflow_before_syscall() {
    let mut batch = SendMmsgBatch::new(1);
    let payload = [0u8; 1];
    let peer: SocketAddr = "127.0.0.1:53".parse().expect("valid fixture");
    let error = batch
        .send(-1, [(&payload[..], peer), (&payload[..], peer)])
        .expect_err("oversized batch must be rejected");
    assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
}

#[test]
fn recvmmsg_batch_drains_multiple_datagrams_in_one_call() {
    use std::net::UdpSocket;
    use std::os::fd::AsRawFd;

    let recv = UdpSocket::bind("127.0.0.1:0").expect("bind recv");
    let send = UdpSocket::bind("127.0.0.1:0").expect("bind send");
    recv.connect(send.local_addr().unwrap()).unwrap();
    send.connect(recv.local_addr().unwrap()).unwrap();

    let payloads: [&[u8]; 3] = [b"one", b"two!!", b"three..."];
    for p in payloads {
        send.send(p).unwrap();
    }
    // Let the datagrams settle in the receive queue.
    std::thread::sleep(std::time::Duration::from_millis(50));

    let mut batch = RecvMmsgBatch::new(8, 4096);
    let n = batch.recv(recv.as_raw_fd()).expect("recvmmsg");
    assert_eq!(n, 3, "all three datagrams drained in one syscall");
    for (i, p) in payloads.iter().enumerate() {
        assert_eq!(batch.message(i).unwrap().to_vec(), p.to_vec());
    }
}

#[test]
fn recvmmsg_batch_reports_wouldblock_when_empty() {
    use std::net::UdpSocket;
    use std::os::fd::AsRawFd;

    let recv = UdpSocket::bind("127.0.0.1:0").expect("bind recv");
    let send = UdpSocket::bind("127.0.0.1:0").expect("bind send");
    recv.connect(send.local_addr().unwrap()).unwrap();

    let mut batch = RecvMmsgBatch::new(4, 4096);
    let err = batch
        .recv(recv.as_raw_fd())
        .expect_err("empty queue must surface WouldBlock for async_io");
    assert_eq!(err.kind(), io::ErrorKind::WouldBlock);
}
