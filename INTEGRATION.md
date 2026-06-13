# UDP Batch Processing: recvmmsg / sendmmsg

## What Changed

The UDP receive loop (`serve_udp_socket`) has been replaced with
`serve_udp_batch` (in `src/udp_batch.rs`), which uses Linux
`recvmmsg(2)` / `sendmmsg(2)` to process up to 32 DNS packets per
syscall pair instead of one packet at a time.

**Syscall overhead reduction:**

| Path | Before | After |
|------|--------|-------|
| Per packet (cache-hot) | `recvfrom` + `sendto` = 2 syscalls | ~2 syscalls / 32 packets |
| Per packet (cache miss) | `recvfrom` + `sendto` (in spawned task) | `recvmmsg` batch + `send_to` per miss |

**Bug #9 fix (incidental):**
The old miss path did `std::mem::replace(&mut recv_buf, BytesMut::with_capacity(65535))`
on every cache miss, allocating a 64 KB buffer each time.  The new path does
`Bytes::copy_from_slice(&recv_buf[..pkt_len])`, allocating only the actual
packet bytes (~50–200 bytes).

## Configuration

Add to your config file (TOML/JSON, depending on your format):

```json
"udp-batch-size": 32
```

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `udp-batch-size` | integer | `32` | Packets per `recvmmsg` call. Upper bound is 64. |

## Platform Notes

- Only compiled on Linux (`#[cfg(target_os = "linux")]`).
- musl cross-compile (`aarch64-unknown-linux-musl`) is supported with no
  extra configuration — `libc` 0.2 exposes `recvmmsg`/`sendmmsg`/`mmsghdr`
  for musl targets.

## Building

```sh
# Native:
cargo build --release

# musl/aarch64 cross-compile:
cargo build --release --target aarch64-unknown-linux-musl
```

## Running Tests

```sh
# Unit tests for the batch module (recvmmsg loopback + sockaddr roundtrip):
cargo test udp_batch

# Full test suite:
cargo test
```

## Benchmark Verification

### Confirm batching is active

```sh
# strace: should show recvmmsg/sendmmsg, NOT recvfrom/sendto
strace -c -e trace=recvmmsg,sendmmsg,recvfrom,sendto -p $(pidof pathdns)
```

### Measure syscall reduction

```sh
perf stat -e syscalls:sys_enter_recvmmsg,syscalls:sys_enter_sendmmsg \
    dnsperf -s 127.0.0.1 -p 53 -d queries.txt -c 10 -Q 50000 -l 10
```

With batching active and a cache-hot workload, `recvmmsg` call count
should be approximately `query_count / batch_size` (≈ 1/32 of before).

### Throughput comparison

```sh
# Run dnsperf twice and compare "Queries per second":
dnsperf -s 127.0.0.1 -d queries.txt -c 20 -Q 100000 -l 30
```

## Design Notes

### try_io drain loop

The inner `recvmmsg` loop uses Tokio's `socket.try_io(Interest::READABLE, ...)`
rather than calling `recvmmsg` directly on the raw fd.  This is required:
`try_io` clears Tokio's internal readiness bit when the closure returns
`WouldBlock`.  Without it the outer `socket.readable().await` returns
immediately every time, creating a busy-spin at 100% CPU.

### musl-safe struct initialization

`libc::msghdr` and `libc::sockaddr_storage` contain private padding fields on
musl (`__pad1`, `__pad2` typed as `Padding<c_int>`).  Struct literal syntax is
a compile error on musl for these types.  All code in `udp_batch.rs` uses
`mem::zeroed()` followed by individual field assignment.

`libc::sockaddr_in` and `libc::sockaddr_in6` have all-public fields and are
safe to initialize with struct literals.

### sendmmsg partial-send handling

`sendmmsg` returns `-1` only when `msgs[0]` fails; a return value `n < count`
means the first `n` messages were sent and the rest were not attempted.  Any
unsent messages fall back to individual `socket.send_to` async tasks.
