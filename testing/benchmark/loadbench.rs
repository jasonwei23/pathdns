//! Minimal std-only DNS load client for before/after benchmarking of pathdns
//! itself (complements `orchestrator.py`, which compares whole resolvers via
//! dnsperf — this needs no external tools).
//!
//! Build:  rustc -O -o /tmp/loadbench loadbench.rs
//! Test:   rustc --test -o /tmp/loadbench-test loadbench.rs && /tmp/loadbench-test
//! Usage:  loadbench <udp|tcp> <ip:port> <threads> <outstanding> <seconds> <warm|unique|hotset:N>
//!
//! - `warm`:     every query asks the same qname → after the first response the
//!               server answers from its DNS cache (warm-cache hit path).
//! - `hotset:N`: queries cycle through N distinct qnames **shared by all
//!               threads** → cache hits spread over a working set of N entries
//!               instead of one perpetually-hot cache line.
//! - `unique`:   every query asks a fresh qname → always a cache miss (routing +
//!               upstream forward path; point the server at a fast mock upstream).
//!
//! The client is deliberately built to not be the bottleneck it measures:
//! - queries are prebuilt once per thread and patched in place (ID bytes and a
//!   fixed-width digit label), so the request path allocates nothing;
//! - response counts and latency histograms are per-thread, on their own cache
//!   lines, summed by the coordinator — no cross-thread contention;
//! - `unique` sequence numbers come from per-thread ranges, not a shared counter;
//! - UDP keeps a fixed table of `outstanding` in-flight slots keyed by DNS ID
//!   (slot = id % outstanding). Each slot owns the **exact rendered request
//!   bytes** it last sent: a timeout resends those bytes unchanged (same ID,
//!   same qname), and a new sequence number is allocated only after the slot
//!   receives a valid response. This keeps the true in-flight count fixed —
//!   the earlier design re-rendered on resend, so one timeout could put two
//!   different qnames in flight under one ID and let the old response
//!   incorrectly complete the new query.

use std::io::{Read, Write};
use std::net::{TcpStream, UdpSocket};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

static STOP: AtomicBool = AtomicBool::new(false);

/// One per worker thread; the padding keeps each count on its own cache line
/// so the only writer never shares it with a sibling's.
#[repr(align(64))]
struct PaddedCount(AtomicU64);

/// Per-thread latency histogram: bucket i counts responses with
/// `2^(i-1) <= latency_us < 2^i` (bucket 0 = sub-microsecond). Written by one
/// thread, snapshotted by the coordinator at the warm-up boundary and at the
/// end so the report covers only the measurement window.
const LAT_BUCKETS: usize = 40;
#[repr(align(64))]
struct LatHist([AtomicU64; LAT_BUCKETS]);

impl LatHist {
    fn new() -> Self {
        Self(std::array::from_fn(|_| AtomicU64::new(0)))
    }
    fn record(&self, lat: Duration) {
        let us = lat.as_micros() as u64;
        let bucket = (64 - us.leading_zeros() as usize).min(LAT_BUCKETS - 1);
        self.0[bucket].fetch_add(1, Ordering::Relaxed);
    }
    fn snapshot(&self) -> [u64; LAT_BUCKETS] {
        std::array::from_fn(|i| self.0[i].load(Ordering::Relaxed))
    }
}

/// Per-thread latency accounting. Two histograms because a UDP query that is
/// resent has two meaningful latencies: the **end-to-end** wait from the first
/// send (what a real client experiences under loss) and the **attempt** wait
/// from the last resend (steady-state RTT when the reply does arrive). TCP has
/// no resends, so only `e2e` is populated there.
struct Metrics {
    e2e: LatHist,
    attempt: LatHist,
    /// Total resends issued (each expired-slot retransmit counts once).
    resends: AtomicU64,
    /// Responses that arrived for a query that had been resent at least once.
    responses_after_resend: AtomicU64,
}

impl Metrics {
    fn new() -> Self {
        Self {
            e2e: LatHist::new(),
            attempt: LatHist::new(),
            resends: AtomicU64::new(0),
            responses_after_resend: AtomicU64::new(0),
        }
    }
}

/// A point-in-time copy of a thread's metrics, so the coordinator can subtract
/// the warm-up-boundary snapshot and report only the measurement window.
#[derive(Clone)]
struct MetricsSnapshot {
    e2e: [u64; LAT_BUCKETS],
    attempt: [u64; LAT_BUCKETS],
    resends: u64,
    responses_after_resend: u64,
}

impl MetricsSnapshot {
    fn zero() -> Self {
        Self {
            e2e: [0; LAT_BUCKETS],
            attempt: [0; LAT_BUCKETS],
            resends: 0,
            responses_after_resend: 0,
        }
    }
}

/// Approximate a percentile from merged histogram deltas: find the bucket where
/// the cumulative count crosses, report its geometric midpoint in microseconds.
fn percentile_us(hist: &[u64; LAT_BUCKETS], pct: f64) -> f64 {
    let total: u64 = hist.iter().sum();
    if total == 0 {
        return 0.0;
    }
    let target = (total as f64 * pct).ceil() as u64;
    let mut cum = 0u64;
    for (i, &c) in hist.iter().enumerate() {
        cum += c;
        if cum >= target {
            // Bucket i covers [2^(i-1), 2^i) µs; use the geometric midpoint.
            let lo = if i == 0 { 1.0 } else { (1u64 << (i - 1)) as f64 };
            let hi = (1u64 << i) as f64;
            return (lo * hi).sqrt();
        }
    }
    (1u64 << (LAT_BUCKETS - 1)) as f64
}

#[derive(Clone, Copy)]
enum Mode {
    Warm,
    /// Cycle through this many distinct qnames, shared across all threads.
    Hotset(u64),
    Unique,
}

fn parse_mode(s: &str) -> Option<Mode> {
    match s {
        "warm" => Some(Mode::Warm),
        "unique" => Some(Mode::Unique),
        _ => s
            .strip_prefix("hotset:")
            .and_then(|n| n.parse::<u64>().ok())
            .filter(|&n| n > 0)
            .map(Mode::Hotset),
    }
}

/// Fixed-width digit run patched in place for digit-bearing qnames; wide enough
/// that a per-thread `unique` range (thread index in the top digits) never wraps.
const SEQ_DIGITS: usize = 18;

fn build_query(id: u16, qname: &str) -> Vec<u8> {
    let mut q = vec![
        (id >> 8) as u8,
        id as u8,
        0x01,
        0x00, // RD=1
        0x00,
        0x01, // QDCOUNT
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
    ];
    for label in qname.split('.') {
        q.push(label.len() as u8);
        q.extend_from_slice(label.as_bytes());
    }
    q.push(0);
    q.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]); // A IN
    q
}

/// In-place query renderer. `allocate_sequence` advances the per-thread
/// sequence counter; `render` patches the DNS ID and the fixed-width digit
/// label for a given (id, sequence) pair without allocating. Keeping the two
/// steps separate lets a UDP slot re-render (or just resend) the *same*
/// request after a timeout instead of silently switching to a new qname.
struct QueryTemplate {
    buf: Vec<u8>,
    /// Byte offset of the first digit of the sequence label; None for warm mode.
    digits_at: Option<usize>,
    next_seq: u64,
    mode: Mode,
}

impl QueryTemplate {
    fn new(mode: Mode, thread_idx: usize) -> Self {
        let qname = match mode {
            Mode::Warm => "warm-bench.example".to_string(),
            // "u" + 18 digits; hotset digits stay in 0..N so every thread
            // shares the same N names, unique digits encode the thread in the
            // top digits so ranges are disjoint without shared state.
            _ => format!("u{:0width$}.bench.example", 0, width = SEQ_DIGITS),
        };
        let buf = build_query(0, &qname);
        // Label layout: [len]['u'][18 digits] starting at offset 12.
        let digits_at = (!matches!(mode, Mode::Warm)).then_some(12 + 2);
        let next_seq = match mode {
            Mode::Warm => 0,
            // Decorrelate thread cycle positions without leaving 0..N.
            Mode::Hotset(n) => (thread_idx as u64).wrapping_mul(9973) % n,
            // Thread t owns [t * 10^12, (t+1) * 10^12) — far beyond any run.
            Mode::Unique => thread_idx as u64 * 1_000_000_000_000,
        };
        Self {
            buf,
            digits_at,
            next_seq,
            mode,
        }
    }

    /// Hand out the sequence number for the *next new* query. Only called when
    /// a slot retires its previous request (valid response received), never on
    /// resend.
    fn allocate_sequence(&mut self) -> u64 {
        match self.mode {
            Mode::Warm => 0,
            Mode::Hotset(n) => {
                let s = self.next_seq;
                self.next_seq = (self.next_seq + 1) % n;
                s
            }
            Mode::Unique => {
                let s = self.next_seq;
                self.next_seq += 1;
                s
            }
        }
    }

    /// Render the query for (id, seq) into the template buffer and return it.
    /// Pure with respect to the sequence counter: rendering the same pair
    /// twice yields identical bytes.
    fn render(&mut self, id: u16, seq: u64) -> &[u8] {
        self.buf[0] = (id >> 8) as u8;
        self.buf[1] = id as u8;
        if let Some(at) = self.digits_at {
            let mut n = seq;
            for i in (0..SEQ_DIGITS).rev() {
                self.buf[at + i] = b'0' + (n % 10) as u8;
                n /= 10;
            }
        }
        &self.buf
    }
}

/// One UDP in-flight slot: the exact ID it expects and the exact bytes it last
/// sent, so a resend repeats the original request verbatim.
struct Slot {
    expected_id: u16,
    request: Vec<u8>,
    /// When this query's *current* sequence was first put on the wire — the
    /// clock for end-to-end latency across any resends.
    first_sent_at: Instant,
    /// When it was last (re)sent — the clock for single-attempt RTT.
    last_sent_at: Instant,
    /// Whether the current query has been resent at least once.
    resent: bool,
}

/// Outcome of feeding one datagram to the UDP slot table.
enum UdpRecv {
    /// A valid reply to slot `slot`. `e2e` is measured from the query's first
    /// send, `attempt` from its last (re)send; `was_resent` marks replies that
    /// arrived only after a retransmit. The slot has already advanced to its
    /// next query, whose bytes are in `slots[slot].request`, ready to send.
    Accepted {
        slot: usize,
        e2e: Duration,
        attempt: Duration,
        was_resent: bool,
    },
    /// The datagram matched no in-flight query — wrong slot/ID, or a stale reply
    /// whose question doesn't echo the current one. No state changed.
    Rejected,
}

/// The UDP client's in-flight state machine, factored out of the socket loop so
/// its loss / resend / stale-reply behaviour can be unit-tested deterministically.
/// The worker owns the socket and drives this; every timing decision takes an
/// explicit `now` so tests exercise it without sleeping.
struct UdpState {
    // Fixed in-flight slot table: slot s always carries an ID ≡ s (mod
    // outstanding), so a response ID maps straight back to its slot, and the
    // slot's expected ID rejects late duplicates of a resent query.
    slots: Vec<Slot>,
    tmpl: QueryTemplate,
    outstanding: usize,
}

impl UdpState {
    /// Build the slot table with `outstanding` distinct queries rendered and
    /// stamped as sent at `now`; the caller transmits each `slots[i].request`.
    fn new(mode: Mode, idx: usize, outstanding: usize, now: Instant) -> Self {
        // The slot mapping (slot = id % outstanding with u16 wrap-around) only
        // preserves residue classes when outstanding divides 2^16.
        assert!(
            outstanding.is_power_of_two() && outstanding <= 1 << 15,
            "outstanding must be a power of two <= 32768"
        );
        let mut tmpl = QueryTemplate::new(mode, idx);
        let slots: Vec<Slot> = (0..outstanding as u16)
            .map(|id| {
                let seq = tmpl.allocate_sequence();
                Slot {
                    expected_id: id,
                    request: tmpl.render(id, seq).to_vec(),
                    first_sent_at: now,
                    last_sent_at: now,
                    resent: false,
                }
            })
            .collect();
        Self {
            slots,
            tmpl,
            outstanding,
        }
    }

    /// Feed one received datagram. On a valid reply the slot retires its request
    /// and renders the next one (same ID residue class); the caller then sends
    /// `slots[slot].request`.
    fn on_response(&mut self, resp: &[u8], now: Instant) -> UdpRecv {
        if resp.len() < 12 {
            return UdpRecv::Rejected;
        }
        let id = u16::from_be_bytes([resp[0], resp[1]]);
        let s = id as usize % self.outstanding;
        {
            let slot = &self.slots[s];
            if slot.expected_id != id {
                return UdpRecv::Rejected; // stale duplicate of a resent slot
            }
            // Identity check: the response must echo this slot's question. The
            // ID alone is not enough — IDs cycle (id += outstanding, wrapping
            // u16), so a very late reply to a retired query can land on the
            // current ID. The request's bytes past the header are exactly its
            // question (qname+qtype+qclass); a real reply echoes them verbatim
            // before its answer RRs.
            let qlen = slot.request.len() - 12;
            if resp.len() < 12 + qlen || resp[12..12 + qlen] != slot.request[12..] {
                return UdpRecv::Rejected; // foreign / stale response, not this query's
            }
        }
        let (e2e, attempt, was_resent, next_id) = {
            let slot = &self.slots[s];
            (
                now.duration_since(slot.first_sent_at),
                now.duration_since(slot.last_sent_at),
                slot.resent,
                id.wrapping_add(self.outstanding as u16),
            )
        };
        // Only now does the slot retire its request and take the next sequence
        // number (same ID residue class).
        let seq = self.tmpl.allocate_sequence();
        let rendered = self.tmpl.render(next_id, seq);
        let slot = &mut self.slots[s];
        slot.expected_id = next_id;
        slot.request.clear();
        slot.request.extend_from_slice(rendered);
        slot.first_sent_at = now;
        slot.last_sent_at = now;
        slot.resent = false;
        UdpRecv::Accepted {
            slot: s,
            e2e,
            attempt,
            was_resent,
        }
    }

    /// Resend every slot whose last send is older than `resend_after`, byte for
    /// byte — the outstanding count and the qname under each ID stay fixed
    /// instead of drifting. `first_sent_at` is left alone so end-to-end latency
    /// still counts from the original send. Returns the number of resends.
    fn resend_expired(
        &mut self,
        now: Instant,
        resend_after: Duration,
        mut send: impl FnMut(&[u8]),
    ) -> u64 {
        let mut resends = 0;
        for slot in &mut self.slots {
            if now.duration_since(slot.last_sent_at) >= resend_after {
                send(&slot.request);
                slot.last_sent_at = now;
                slot.resent = true;
                resends += 1;
            }
        }
        resends
    }
}

fn udp_worker(
    addr: String,
    outstanding: usize,
    mode: Mode,
    idx: usize,
    count: Arc<PaddedCount>,
    metrics: Arc<Metrics>,
) {
    let sock = UdpSocket::bind("127.0.0.1:0").expect("bind");
    sock.connect(&addr).expect("connect");
    sock.set_read_timeout(Some(Duration::from_millis(100)))
        .expect("timeout");

    const RESEND_AFTER: Duration = Duration::from_millis(150);
    let mut state = UdpState::new(mode, idx, outstanding, Instant::now());
    for slot in &state.slots {
        let _ = sock.send(&slot.request);
    }

    let mut buf = [0u8; 2048];
    while !STOP.load(Ordering::Relaxed) {
        match sock.recv(&mut buf) {
            Ok(n) => match state.on_response(&buf[..n], Instant::now()) {
                UdpRecv::Accepted {
                    slot,
                    e2e,
                    attempt,
                    was_resent,
                } => {
                    metrics.e2e.record(e2e);
                    metrics.attempt.record(attempt);
                    if was_resent {
                        metrics
                            .responses_after_resend
                            .fetch_add(1, Ordering::Relaxed);
                    }
                    count.0.fetch_add(1, Ordering::Relaxed);
                    let _ = sock.send(&state.slots[slot].request);
                }
                UdpRecv::Rejected => {}
            },
            Err(_) => {
                // Timeout: resend only the slots that actually expired.
                let resends = state.resend_expired(Instant::now(), RESEND_AFTER, |bytes| {
                    let _ = sock.send(bytes);
                });
                if resends > 0 {
                    metrics.resends.fetch_add(resends, Ordering::Relaxed);
                }
            }
        }
    }
}

/// The TCP client's pipeline state, factored out of the socket loop so its
/// out-of-order response accounting can be unit-tested. pathdns resolves
/// cache-miss TCP queries in independent per-query tasks, so responses on one
/// connection are NOT guaranteed to come back in send order — whichever
/// upstream exchange finishes first grabs the write lock. Pairing a response
/// with its send by FIFO would misattribute latency on the miss path; instead
/// each query's send time is stored by its DNS ID and looked up when the
/// response (which carries that ID) arrives.
struct TcpState {
    tmpl: QueryTemplate,
    next_id: u16,
    /// Send time indexed by DNS ID; `Some` means that ID is currently in flight.
    pending: Vec<Option<Instant>>,
    /// Scratch for the length-prefixed frame handed back to the caller.
    framed: Vec<u8>,
}

impl TcpState {
    fn new(mode: Mode, idx: usize, outstanding: usize) -> Self {
        assert!(
            outstanding < 1 << 16,
            "outstanding must be < 65536 so in-flight DNS IDs never alias"
        );
        let tmpl = QueryTemplate::new(mode, idx);
        let framed = vec![0u8; 2 + tmpl.buf.len()];
        Self {
            tmpl,
            next_id: 0,
            pending: vec![None; 1 << 16],
            framed,
        }
    }

    /// Render the next query into the framed scratch buffer, record its send
    /// time under its DNS ID, and return the length-prefixed bytes to write.
    fn next_frame(&mut self, now: Instant) -> &[u8] {
        // Skip IDs still in flight so a response can never be misattributed
        // (only reachable if outstanding approached 65536, which `new` forbids,
        // but it keeps the invariant local and obvious).
        while self.pending[self.next_id as usize].is_some() {
            self.next_id = self.next_id.wrapping_add(1);
        }
        let id = self.next_id;
        let seq = self.tmpl.allocate_sequence();
        let q = self.tmpl.render(id, seq);
        let qlen = q.len();
        self.framed[..2].copy_from_slice(&(qlen as u16).to_be_bytes());
        self.framed[2..2 + qlen].copy_from_slice(q);
        self.pending[id as usize] = Some(now);
        self.next_id = id.wrapping_add(1);
        &self.framed[..2 + qlen]
    }

    /// Match a received DNS message to its send by the echoed ID and return its
    /// end-to-end latency, or `None` if that ID isn't in flight (a duplicate or
    /// a late reply to an already-completed query).
    fn on_response(&mut self, resp: &[u8], now: Instant) -> Option<Duration> {
        if resp.len() < 2 {
            return None;
        }
        let rid = u16::from_be_bytes([resp[0], resp[1]]) as usize;
        self.pending[rid].take().map(|sent| now.duration_since(sent))
    }
}

fn tcp_worker(
    addr: String,
    outstanding: usize,
    mode: Mode,
    idx: usize,
    count: Arc<PaddedCount>,
    metrics: Arc<Metrics>,
) {
    let mut stream = TcpStream::connect(&addr).expect("connect");
    stream.set_nodelay(true).ok();
    stream
        .set_read_timeout(Some(Duration::from_millis(500)))
        .expect("timeout");
    let mut state = TcpState::new(mode, idx, outstanding);
    for _ in 0..outstanding {
        let frame = state.next_frame(Instant::now());
        let _ = stream.write_all(frame);
    }
    let mut len_buf = [0u8; 2];
    // A TCP DNS message can be up to 65535 bytes; size the buffer for the
    // worst case up front rather than slicing a short buffer by `len`.
    let mut buf = vec![0u8; 65535];
    while !STOP.load(Ordering::Relaxed) {
        match stream.read_exact(&mut len_buf) {
            Ok(()) => {
                let len = u16::from_be_bytes(len_buf) as usize;
                if len < 12 || stream.read_exact(&mut buf[..len]).is_err() {
                    return;
                }
                if let Some(e2e) = state.on_response(&buf[..len], Instant::now()) {
                    metrics.e2e.record(e2e);
                }
                count.0.fetch_add(1, Ordering::Relaxed);
                let frame = state.next_frame(Instant::now());
                let _ = stream.write_all(frame);
            }
            // TCP is reliable: a timeout means slow, not lost — keep waiting
            // rather than growing the pipeline beyond `outstanding`.
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::TimedOut
                        | std::io::ErrorKind::WouldBlock
                        | std::io::ErrorKind::Interrupted
                ) =>
            {
                continue;
            }
            // EOF / reset / anything else is permanent: a closed socket fails
            // read_exact immediately, so `continue` here would busy-spin a
            // core for the rest of the run.
            Err(_) => return,
        }
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 7 {
        eprintln!("usage: loadbench <udp|tcp> <ip:port> <threads> <outstanding> <seconds> <warm|unique|hotset:N>");
        std::process::exit(2);
    }
    let proto = args[1].clone();
    let addr = args[2].clone();
    let threads: usize = args[3].parse().expect("threads");
    let outstanding: usize = args[4].parse().expect("outstanding");
    let seconds: u64 = args[5].parse().expect("seconds");
    let mode = parse_mode(&args[6]).unwrap_or_else(|| {
        eprintln!("mode must be warm, unique, or hotset:N (N > 0)");
        std::process::exit(2);
    });

    let counts: Vec<Arc<PaddedCount>> = (0..threads)
        .map(|_| Arc::new(PaddedCount(AtomicU64::new(0))))
        .collect();
    let metrics: Vec<Arc<Metrics>> = (0..threads).map(|_| Arc::new(Metrics::new())).collect();
    let mut handles = Vec::new();
    for t in 0..threads {
        let (a, c, m) = (addr.clone(), counts[t].clone(), metrics[t].clone());
        handles.push(if proto == "udp" {
            std::thread::spawn(move || udp_worker(a, outstanding, mode, t, c, m))
        } else {
            std::thread::spawn(move || tcp_worker(a, outstanding, mode, t, c, m))
        });
    }

    let sum = |counts: &[Arc<PaddedCount>]| -> u64 {
        counts.iter().map(|c| c.0.load(Ordering::Relaxed)).sum()
    };
    let merged = |metrics: &[Arc<Metrics>]| -> MetricsSnapshot {
        let mut out = MetricsSnapshot::zero();
        for m in metrics {
            for (o, s) in out.e2e.iter_mut().zip(m.e2e.snapshot()) {
                *o += s;
            }
            for (o, s) in out.attempt.iter_mut().zip(m.attempt.snapshot()) {
                *o += s;
            }
            out.resends += m.resends.load(Ordering::Relaxed);
            out.responses_after_resend += m.responses_after_resend.load(Ordering::Relaxed);
        }
        out
    };

    // Warm-up second (populate the cache, settle sockets), then measure.
    std::thread::sleep(Duration::from_secs(1));
    let start_count = sum(&counts);
    let start = merged(&metrics);
    let t0 = Instant::now();
    std::thread::sleep(Duration::from_secs(seconds));
    let total = sum(&counts) - start_count;
    let end = merged(&metrics);
    let elapsed = t0.elapsed().as_secs_f64();
    STOP.store(true, Ordering::Relaxed);
    for h in handles {
        let _ = h.join();
    }

    // Subtract the warm-up-boundary snapshot so the report covers only the
    // measurement window.
    let window = |e: &[u64; LAT_BUCKETS], s: &[u64; LAT_BUCKETS]| -> [u64; LAT_BUCKETS] {
        std::array::from_fn(|i| e[i] - s[i])
    };
    let e2e = window(&end.e2e, &start.e2e);
    let attempt = window(&end.attempt, &start.attempt);
    let resends = end.resends - start.resends;
    let after_resend = end.responses_after_resend - start.responses_after_resend;

    // `e2e` is the client-visible latency (from the first send, across any
    // resends). For UDP it's the primary number; `attempt` (from the last
    // send) is only meaningfully different once resends happen, so the extra
    // line is printed only then.
    print!(
        "{} {}: {total} responses in {elapsed:.2}s = {:.0} qps  e2e p50~{:.0}us p99~{:.0}us",
        proto,
        args[6],
        total as f64 / elapsed,
        percentile_us(&e2e, 0.50),
        percentile_us(&e2e, 0.99),
    );
    if resends > 0 {
        print!(
            "  attempt p50~{:.0}us p99~{:.0}us  resends={resends} after_resend={after_resend}",
            percentile_us(&attempt, 0.50),
            percentile_us(&attempt, 0.99),
        );
    }
    println!();
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The full UDP slot state machine under loss: a query is sent, times out
    /// and is resent *verbatim* (no new qname), a stale reply carrying the same
    /// ID but a different question is rejected without retiring the slot, and
    /// only the genuine reply completes the query — with end-to-end latency
    /// counted from the first send and single-attempt latency from the resend.
    /// A new qname appears only afterwards. This is exactly the sequence the
    /// task calls out, driven with explicit timestamps (no sleeping).
    #[test]
    fn udp_state_rejects_stale_reply_and_times_e2e_across_a_resend() {
        let t0 = Instant::now();
        let mut state = UdpState::new(Mode::Unique, 3, 1, t0);
        assert_eq!(state.slots.len(), 1);
        assert_eq!(state.slots[0].expected_id, 0);
        let request_a = state.slots[0].request.clone();

        // A times out at t0+150ms → resent byte-for-byte, still the same qname.
        let mut resent_bytes = Vec::new();
        let n = state.resend_expired(
            t0 + Duration::from_millis(150),
            Duration::from_millis(150),
            |b| resent_bytes.extend_from_slice(b),
        );
        assert_eq!(n, 1, "the one expired slot must resend");
        assert_eq!(resent_bytes, request_a, "resend must repeat the bytes");
        assert!(state.slots[0].resent);
        assert_eq!(state.slots[0].request, request_a, "no new qname on resend");

        // A reply with A's ID but a corrupted question is rejected — and must
        // NOT retire the slot (that would leak A's latency onto a foreign reply
        // and prematurely advance the qname).
        let mut stale = request_a.clone();
        let digit = 14; // [len]['u'] at offset 12, first qname digit at 14
        stale[digit] ^= 1;
        assert!(matches!(
            state.on_response(&stale, t0 + Duration::from_millis(200)),
            UdpRecv::Rejected
        ));
        assert_eq!(state.slots[0].request, request_a, "reject must not advance");
        assert_eq!(state.slots[0].expected_id, 0);

        // A's genuine reply at t0+300ms completes it: e2e from the first send
        // (300ms), attempt from the resend (150ms), flagged after-resend.
        match state.on_response(&request_a, t0 + Duration::from_millis(300)) {
            UdpRecv::Accepted {
                slot,
                e2e,
                attempt,
                was_resent,
            } => {
                assert_eq!(slot, 0);
                assert_eq!(e2e, Duration::from_millis(300), "e2e counts from 1st send");
                assert_eq!(attempt, Duration::from_millis(150), "attempt from resend");
                assert!(was_resent);
            }
            UdpRecv::Rejected => panic!("the genuine reply must be accepted"),
        }

        // Only now does the slot carry a new query B: same ID residue, new qname.
        let request_b = &state.slots[0].request;
        assert_ne!(*request_b, request_a, "new qname only after a valid reply");
        assert_eq!(request_b.len(), request_a.len());
        assert_eq!(state.slots[0].expected_id, 0u16.wrapping_add(1));
        assert!(!state.slots[0].resent);
    }

    /// TCP responses can come back out of send order (per-query upstream tasks),
    /// so each reply's latency must be attributed to *its own* send time via the
    /// echoed DNS ID — never by arrival order. Send three queries at distinct,
    /// known times, then answer them 3rd-1st-2nd and confirm each latency maps to
    /// the right original send. A duplicate reply for a completed ID is ignored.
    #[test]
    fn tcp_state_attributes_reordered_replies_to_their_own_sends() {
        let base = Instant::now();
        let mut state = TcpState::new(Mode::Unique, 0, 3);

        // Three sends at t=0/10/25ms; capture the DNS ID each one got.
        let sent_at = [
            Duration::from_millis(0),
            Duration::from_millis(10),
            Duration::from_millis(25),
        ];
        let ids: Vec<u16> = sent_at
            .iter()
            .map(|&dt| {
                let frame = state.next_frame(base + dt);
                // frame = [len_hi, len_lo, dns_msg...]; DNS ID at bytes 2..4.
                u16::from_be_bytes([frame[2], frame[3]])
            })
            .collect();
        assert_eq!(
            ids.iter().collect::<std::collections::HashSet<_>>().len(),
            3,
            "three distinct IDs must be in flight"
        );

        // Replies arrive reordered (3rd, 1st, 2nd) at t=30/40/45ms.
        let plan = [
            (2usize, Duration::from_millis(30)),
            (0usize, Duration::from_millis(40)),
            (1usize, Duration::from_millis(45)),
        ];
        for &(which, recv_at) in &plan {
            let latency = state
                .on_response(&dns_message(ids[which]), base + recv_at)
                .expect("in-flight ID must resolve");
            assert_eq!(
                latency,
                recv_at - sent_at[which],
                "reordered reply misattributed to the wrong send"
            );
        }

        // A duplicate/late reply for an already-completed ID resolves to nothing.
        assert!(state
            .on_response(&dns_message(ids[0]), base + Duration::from_millis(60))
            .is_none());
    }

    /// A minimal DNS message carrying `id` in the header (enough for the TCP
    /// pipeline, which matches replies by ID alone).
    fn dns_message(id: u16) -> Vec<u8> {
        let mut m = vec![0u8; 12];
        m[0] = (id >> 8) as u8;
        m[1] = id as u8;
        m
    }

    /// The invariant the UDP slot table relies on: a resend must repeat the
    /// original request byte for byte (same ID, same qname), and a new qname
    /// appears only after the slot retires its request.
    #[test]
    fn resend_repeats_bytes_and_new_sequence_only_after_response() {
        let mut tmpl = QueryTemplate::new(Mode::Unique, 3);

        // Request A is rendered once and stored by its slot.
        let seq_a = tmpl.allocate_sequence();
        let request_a = tmpl.render(7, seq_a).to_vec();

        // The template gets reused by other slots in between...
        let other = tmpl.render(8, tmpl.next_seq).to_vec();
        assert_ne!(other, request_a);
        // ...yet re-rendering the same (id, seq) — a resend — reproduces the
        // original request exactly.
        assert_eq!(
            tmpl.render(7, seq_a),
            &request_a[..],
            "resend must be byte-identical"
        );

        // Only after the response does the slot allocate a new sequence: the
        // next request differs in the qname digits (and nothing but those,
        // since the slot ID here stays the same).
        let seq_b = tmpl.allocate_sequence();
        assert_eq!(seq_b, seq_a + 1);
        let request_b = tmpl.render(7, seq_b).to_vec();
        assert_ne!(request_b, request_a);
        assert_eq!(request_a.len(), request_b.len());
        assert_eq!(&request_a[..2], &request_b[..2]);
        let at = 14; // [len]['u'] at offset 12, digits start at 14
        assert_ne!(
            &request_a[at..at + SEQ_DIGITS],
            &request_b[at..at + SEQ_DIGITS]
        );
        assert_eq!(&request_a[at + SEQ_DIGITS..], &request_b[at + SEQ_DIGITS..]);
    }

    #[test]
    fn hotset_sequences_stay_in_range_and_are_shared_across_threads() {
        let n = 64u64;
        let mut a = QueryTemplate::new(Mode::Hotset(n), 0);
        let mut b = QueryTemplate::new(Mode::Hotset(n), 5);
        let mut seen = std::collections::HashSet::new();
        for _ in 0..(2 * n) {
            let (sa, sb) = (a.allocate_sequence(), b.allocate_sequence());
            assert!(sa < n && sb < n);
            seen.insert(a.render(1, sa).to_vec());
            seen.insert(b.render(1, sb).to_vec());
        }
        // Both threads draw from the same N rendered qnames.
        assert_eq!(seen.len(), n as usize);
    }

    #[test]
    fn warm_mode_renders_a_constant_qname() {
        let mut tmpl = QueryTemplate::new(Mode::Warm, 0);
        let s1 = tmpl.allocate_sequence();
        let q1 = tmpl.render(1, s1).to_vec();
        let s2 = tmpl.allocate_sequence();
        let q2 = tmpl.render(1, s2).to_vec();
        assert_eq!(q1, q2);
    }

    #[test]
    fn percentiles_come_from_the_right_buckets() {
        let mut hist = [0u64; LAT_BUCKETS];
        hist[7] = 99; // 64..128us
        hist[12] = 1; // 2048..4096us
        let p50 = percentile_us(&hist, 0.50);
        assert!((64.0..128.0).contains(&p50), "p50={}", p50);
        let p99 = percentile_us(&hist, 0.99);
        assert!((64.0..128.0).contains(&p99), "p99={}", p99);
        let p999 = percentile_us(&hist, 0.999);
        assert!((2048.0..4096.0).contains(&p999), "p999={}", p999);
    }
}
