// Fast UDP DNS mock upstream for benchmarking. Std-only, no deps.
// N threads share one UdpSocket (kernel distributes datagrams); each answers
// every query NOERROR with a single A 9.9.9.9, echoing the question. Sustains
// far more than a Python mock so it never becomes the benchmark bottleneck.
//
// Build: rustc -O rustmock.rs -o rustmock
// Run:   ./rustmock 5300 [threads]
use std::net::UdpSocket;
use std::sync::Arc;
use std::thread;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let port: u16 = args.get(1).and_then(|s| s.parse().ok()).unwrap_or(5300);
    let threads: usize = args.get(2).and_then(|s| s.parse().ok()).unwrap_or(4);

    let sock = Arc::new(UdpSocket::bind(("127.0.0.1", port)).expect("bind"));
    // A RR: name pointer 0xC00C, type A, class IN, ttl 60, rdlen 4, 9.9.9.9
    const A_RR: [u8; 16] = [
        0xC0, 0x0C, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3C, 0x00, 0x04, 9, 9, 9, 9,
    ];

    let mut handles = Vec::new();
    for _ in 0..threads {
        let s = sock.clone();
        handles.push(thread::spawn(move || {
            let mut buf = [0u8; 2048];
            let mut out = [0u8; 2048];
            loop {
                let (n, peer) = match s.recv_from(&mut buf) {
                    Ok(v) => v,
                    Err(_) => continue,
                };
                if n < 12 {
                    continue;
                }
                // find end of QNAME
                let mut off = 12usize;
                while off < n {
                    let l = buf[off] as usize;
                    if l == 0 {
                        break;
                    }
                    off += 1 + l;
                }
                let qend = off + 1 + 4; // null label + qtype + qclass
                if qend > n {
                    continue;
                }
                // header (12) + question, then one answer
                out[..qend].copy_from_slice(&buf[..qend]);
                out[2] = 0x84; // QR=1, AA=1
                out[3] = 0x00; // rcode 0
                out[6] = 0;
                out[7] = 1; // ANCOUNT=1
                out[8] = 0;
                out[9] = 0; // NSCOUNT=0
                out[10] = 0;
                out[11] = 0; // ARCOUNT=0
                out[qend..qend + 16].copy_from_slice(&A_RR);
                let _ = s.send_to(&out[..qend + 16], peer);
            }
        }));
    }
    eprintln!("rustmock :{port} threads={threads}");
    for h in handles {
        let _ = h.join();
    }
}
