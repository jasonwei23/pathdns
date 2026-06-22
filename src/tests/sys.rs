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
