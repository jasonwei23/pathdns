//! Mihomo `.mrs` rule-set binary format.
//!
//! ## Container
//! A single zstd frame wrapping: 4-byte magic `b"MRS\x01"`, a 1-byte behavior
//! tag ([`BEHAVIOR_DOMAIN`]=domain, [`BEHAVIOR_IPCIDR`]=ipcidr, `2`=classical),
//! an 8-byte big-endian entry count, an 8-byte big-endian "extra" length
//! (reserved by mihomo for future use; always skipped), then a behavior-specific
//! body. See `github.com/metacubex/mihomo/rules/provider` (`mrs_reader.go`,
//! `mrs_converter.go`).
//!
//! ## Domain-set body ([`decode_domain_patterns`])
//! A succinct (LOUDS-style) trie over reversed domain-name bytes, exactly as
//! written by mihomo's `component/trie.DomainSet.WriteBin`: a version byte
//! (`1`), then two length-prefixed `u64` arrays (`leaves`, `labelBitmap`) and
//! one length-prefixed byte array (`labels`).
//!
//! Decoding walks the trie the same way mihomo's own `DomainSet.keys()` does,
//! reconstructing each stored pattern in mihomo's inline text form:
//! - `example.com`   — exact match only
//! - `+.example.com` — the domain itself and all subdomains
//! - `.example.com`  — subdomains only, without the apex (rare hand-written
//!   form; mihomo's own text dump can't distinguish it from a bare
//!   `+.example.com` remnant either, so callers may reasonably treat it the
//!   same way)
//! - `*.example.com` — single-label wildcard
//!
//! ## IP-CIDR body ([`decode_ipcidr_ranges`])
//! A flat, count-prefixed list of `(from, to)` ranges: an inner version byte
//! (`1`), an 8-byte big-endian range count, then 32 bytes per range (16-byte
//! `from` + 16-byte `to`, IPv4 addresses in their IPv4-mapped-IPv6 form) — no
//! CIDR/prefix trie on disk, matching both mihomo's current Go implementation
//! (`component/cidr.IpCidrSet`, a sorted-range set) and Watfaq/clash-rs's
//! decoder. [`crate::iprange`] compiles the decoded ranges into a queryable set.
//!
//! This module only decodes; pathdns never writes `.mrs` files.

use anyhow::{anyhow, Context, Result};
use std::io::Read;

const MRS_MAGIC: [u8; 4] = *b"MRS\x01";
/// Domain-behavior mrs file (a [`decode_domain_patterns`] body follows the header).
pub const BEHAVIOR_DOMAIN: u8 = 0;
/// IP-CIDR-behavior mrs file (see [`decode_ipcidr_ranges`]).
pub const BEHAVIOR_IPCIDR: u8 = 1;

/// Generous upper bound, in BYTES, on any single length-prefixed array in the
/// file, to reject a corrupt or hostile header before attempting a large
/// allocation. Real geosite-derived domain sets (even the largest categories)
/// are at most a few tens of MB; this leaves an order of magnitude of
/// headroom. Applied to the `u64` arrays (`leaves`, `labelBitmap`) as a byte
/// count, not an element count — an 8x difference that otherwise lets a small
/// file demand up to 2 GiB for a single array.
const MAX_ARRAY_BYTES: u64 = 256 * 1024 * 1024;

/// Hard cap on the number of steps `DomainSet::for_each_domain`'s explicit-stack
/// walk may take. A well-formed trie visits each edge encoded in `labels` at
/// most twice (down then up), so this is generous headroom over the largest
/// legitimate `labels` array (bounded by `MAX_ARRAY_BYTES`). It exists purely
/// to bound a malformed/hostile `labelBitmap` that doesn't actually encode a
/// tree: nothing here re-derives that the bitmap is acyclic, so a crafted
/// bitmap could make unrelated bit positions collapse onto the same child
/// node, letting the walk revisit (and re-expand) the same subtree from many
/// parents — a decompression-bomb-style blowup with a tiny file on disk.
const MAX_DOMAIN_SET_STEPS: u64 = 512 * 1024 * 1024;

/// Hard cap on the explicit-stack depth (not just the total step count) that
/// `DomainSet::for_each_domain`'s walk may reach. `MAX_DOMAIN_SET_STEPS` bounds
/// how long the walk may run, but a crafted `labelBitmap` that never sets an
/// `is_end` bit keeps pushing a `Frame` (24 bytes) per step without ever
/// popping, so the stack itself can grow to the full step count — up to
/// ~12 GiB — before that cap trips. With `panic = "abort"` in the release
/// profile, the allocation failure that follows aborts the whole process
/// instead of returning the `Err` this function is supposed to produce. A
/// legitimate domain trie's depth is bounded by the longest stored pattern
/// (at most 253 bytes, RFC 1035), so this cap leaves an order of magnitude of
/// headroom while keeping worst-case memory for one walk in the hundreds of KB.
const MAX_DOMAIN_SET_DEPTH: usize = 4096;

/// Generous upper bound on the number of ipcidr ranges in one file (each is a
/// fixed 32 bytes on disk), for the same reason as `MAX_ARRAY_BYTES`.
const MAX_IPCIDR_RANGES: u64 = 64 * 1024 * 1024;

fn open_decoder(
    raw: &[u8],
) -> Result<ruzstd::decoding::StreamingDecoder<&[u8], ruzstd::decoding::FrameDecoder>> {
    ruzstd::decoding::StreamingDecoder::new(raw).context("invalid zstd stream in mrs file")
}

/// Read and validate the common header, returning `(behavior_byte, count)` and
/// leaving the reader positioned at the behavior-specific body.
fn read_header<R: Read>(r: &mut R) -> Result<(u8, u64)> {
    let mut magic = [0u8; 4];
    r.read_exact(&mut magic).context("truncated mrs header")?;
    if magic != MRS_MAGIC {
        return Err(anyhow!("not a mihomo mrs file (bad magic bytes)"));
    }

    let mut behavior = [0u8; 1];
    r.read_exact(&mut behavior)
        .context("truncated mrs behavior byte")?;

    let count = read_u64_be(r).context("truncated mrs count field")?;

    let extra_len = read_u64_be(r).context("truncated mrs extra-length field")?;
    skip_exact(r, extra_len).context("truncated mrs extra field")?;

    Ok((behavior[0], count))
}

/// Decode a domain-behavior `.mrs` file's bytes into its stored domain
/// patterns, in mihomo's inline text form (see module docs). Order is unspecified.
pub fn decode_domain_patterns(raw: &[u8]) -> Result<Vec<String>> {
    let mut decoder = open_decoder(raw)?;
    let (behavior, _count) = read_header(&mut decoder)?;
    if behavior != BEHAVIOR_DOMAIN {
        return Err(anyhow!(
            "mrs behavior byte {behavior} does not match the configured behavior 'domain'"
        ));
    }

    let domain_set = DomainSet::read_from(&mut decoder).context("invalid mrs domain-set body")?;

    let mut out = Vec::new();
    domain_set.for_each_domain(|s| out.push(s))?;
    Ok(out)
}

/// Decode an ipcidr-behavior `.mrs` file's bytes into its stored `(from, to)`
/// ranges, each endpoint normalized into the unified 128-bit address space
/// (see [`crate::iprange`]). Order is unspecified.
///
/// Body layout (confirmed against both mihomo's Go `component/cidr` and
/// Watfaq/clash-rs's Rust port): a version byte (`1`), an 8-byte big-endian
/// range count, then for each range a 32-byte record — 16-byte `from` + 16-byte
/// `to`, both big-endian, IPv4 addresses written in their IPv4-mapped-IPv6
/// form. This is exactly [`crate::iprange::to_u128`]'s normalization, so each
/// endpoint can be used directly with no further conversion.
pub fn decode_ipcidr_ranges(raw: &[u8]) -> Result<Vec<(u128, u128)>> {
    let mut decoder = open_decoder(raw)?;
    let (behavior, _count) = read_header(&mut decoder)?;
    if behavior != BEHAVIOR_IPCIDR {
        return Err(anyhow!(
            "mrs behavior byte {behavior} does not match the configured behavior 'ipcidr'"
        ));
    }

    let mut version = [0u8; 1];
    decoder
        .read_exact(&mut version)
        .context("truncated ipcidr-set version byte")?;
    if version[0] != 1 {
        return Err(anyhow!("unsupported ipcidr-set version {}", version[0]));
    }

    let ranges_len = read_u64_be(&mut decoder).context("truncated ipcidr ranges length")?;
    if ranges_len > MAX_IPCIDR_RANGES {
        return Err(anyhow!(
            "mrs ipcidr range count {ranges_len} implausibly large"
        ));
    }

    let mut ranges = Vec::new();
    let mut from_buf = [0u8; 16];
    let mut to_buf = [0u8; 16];
    for _ in 0..ranges_len {
        decoder
            .read_exact(&mut from_buf)
            .context("truncated ipcidr range record")?;
        decoder
            .read_exact(&mut to_buf)
            .context("truncated ipcidr range record")?;
        ranges.push((u128::from_be_bytes(from_buf), u128::from_be_bytes(to_buf)));
    }
    Ok(ranges)
}

fn read_u64_be<R: Read>(r: &mut R) -> Result<u64> {
    let mut buf = [0u8; 8];
    r.read_exact(&mut buf)?;
    Ok(u64::from_be_bytes(buf))
}

/// Discard exactly `len` bytes without allocating a buffer sized by `len`.
fn skip_exact<R: Read>(r: &mut R, len: u64) -> Result<()> {
    let copied = std::io::copy(&mut r.take(len), &mut std::io::sink())?;
    if copied != len {
        return Err(anyhow!(
            "expected to skip {len} bytes, stream ended after {copied}"
        ));
    }
    Ok(())
}

fn read_u64_be_vec<R: Read>(r: &mut R, len: u64) -> Result<Vec<u64>> {
    if len
        .checked_mul(8)
        .is_none_or(|bytes| bytes > MAX_ARRAY_BYTES)
    {
        return Err(anyhow!("mrs array length {len} implausibly large"));
    }
    let mut out = Vec::new();
    for _ in 0..len {
        out.push(read_u64_be(r)?);
    }
    Ok(out)
}

fn read_byte_vec<R: Read>(r: &mut R, len: u64) -> Result<Vec<u8>> {
    if len > MAX_ARRAY_BYTES {
        return Err(anyhow!("mrs array length {len} implausibly large"));
    }
    let mut out = Vec::new();
    let mut remaining = len;
    let mut chunk = [0u8; 8192];
    while remaining > 0 {
        let n = usize::try_from(remaining.min(chunk.len() as u64)).unwrap_or(chunk.len());
        r.read_exact(&mut chunk[..n])?;
        out.extend_from_slice(&chunk[..n]);
        remaining -= n as u64;
    }
    Ok(out)
}

// Succinct (LOUDS) domain trie decode.

/// A bitmap with O(1) rank and O(word) select, matching the semantics of
/// mihomo's `openacid/low/bitmap` helpers (`setBit`/`getBit`/`Rank64`/`Select32R64`):
/// bit `i` lives at `words[i>>6]`, bit `i&63`, LSB first.
struct RankBitmap {
    words: Vec<u64>,
    /// `prefix[w]` = number of set bits among `words[0..w]`. `u64` rather than
    /// `u32`: `words` can hold enough set bits (bounded by `MAX_ARRAY_BYTES`,
    /// currently up to ~2^31) to sit uncomfortably close to `u32::MAX`, and a
    /// silent wraparound here would corrupt every rank/select lookup instead
    /// of failing loudly.
    prefix: Vec<u64>,
}

impl RankBitmap {
    fn new(words: Vec<u64>) -> Self {
        let mut prefix = Vec::with_capacity(words.len() + 1);
        prefix.push(0u64);
        let mut acc = 0u64;
        for w in &words {
            acc += w.count_ones() as u64;
            prefix.push(acc);
        }
        Self { words, prefix }
    }

    fn total_bits(&self) -> usize {
        self.words.len() * 64
    }

    fn get(&self, i: usize) -> Option<bool> {
        if i >= self.total_bits() {
            return None;
        }
        Some((self.words[i >> 6] >> (i & 63)) & 1 != 0)
    }

    /// Number of set bits in `[0, i)`. Valid for `i` in `[0, total_bits()]`.
    fn rank1(&self, i: usize) -> Option<usize> {
        if i > self.total_bits() {
            return None;
        }
        let word_idx = i >> 6;
        let bit = i & 63;
        let mask = if bit == 0 { 0 } else { u64::MAX >> (64 - bit) };
        let word = self.words.get(word_idx).copied().unwrap_or(0);
        Some(self.prefix[word_idx] as usize + (word & mask).count_ones() as usize)
    }

    /// Number of clear bits in `[0, i)`.
    fn rank0(&self, i: usize) -> Option<usize> {
        Some(i - self.rank1(i)?)
    }

    /// Position of the `k`-th (0-indexed) set bit, or `None` if there is no such bit.
    fn select1(&self, k: usize) -> Option<usize> {
        let k = k as u64;
        let word_idx = self.prefix.partition_point(|&c| c <= k).checked_sub(1)?;
        let word = *self.words.get(word_idx)?;
        let within = (k - self.prefix[word_idx]) as usize;
        Some(word_idx * 64 + select1_in_word(word, within)?)
    }
}

/// Position of the `k`-th (0-indexed) set bit within a single word, if any.
fn select1_in_word(mut word: u64, k: usize) -> Option<usize> {
    let mut remaining = k;
    loop {
        if word == 0 {
            return None;
        }
        let tz = word.trailing_zeros();
        if remaining == 0 {
            return Some(tz as usize);
        }
        word &= word - 1;
        remaining -= 1;
    }
}

struct DomainSet {
    leaves: RankBitmap,
    label_bitmap: RankBitmap,
    labels: Vec<u8>,
}

impl DomainSet {
    fn read_from<R: Read>(r: &mut R) -> Result<Self> {
        let mut version = [0u8; 1];
        r.read_exact(&mut version)
            .context("truncated domain-set version byte")?;
        if version[0] != 1 {
            return Err(anyhow!("unsupported domain-set version {}", version[0]));
        }

        let leaves_len = read_u64_be(r).context("truncated leaves length")?;
        let leaves = read_u64_be_vec(r, leaves_len).context("truncated leaves array")?;

        let label_bitmap_len = read_u64_be(r).context("truncated labelBitmap length")?;
        let label_bitmap =
            read_u64_be_vec(r, label_bitmap_len).context("truncated labelBitmap array")?;

        let labels_len = read_u64_be(r).context("truncated labels length")?;
        let labels = read_byte_vec(r, labels_len).context("truncated labels array")?;

        if leaves.is_empty() || label_bitmap.is_empty() || labels.is_empty() {
            return Err(anyhow!("empty domain-set arrays"));
        }

        Ok(Self {
            leaves: RankBitmap::new(leaves),
            label_bitmap: RankBitmap::new(label_bitmap),
            labels,
        })
    }

    fn is_leaf(&self, node_id: usize) -> Result<bool> {
        self.leaves
            .get(node_id)
            .ok_or_else(|| anyhow!("mrs domain-set: leaf index {node_id} out of range"))
    }

    /// Walk the whole trie depth-first (explicit stack; domain sets can be
    /// large and a malformed file must not risk unbounded call-stack
    /// recursion), calling `f` with each stored pattern in mihomo's inline
    /// text form (reversed back to forward reading order).
    fn for_each_domain(&self, mut f: impl FnMut(String)) -> Result<()> {
        struct Frame {
            node_id: usize,
            bm_idx: usize,
            restore_len: usize,
        }

        let mut current: Vec<u8> = Vec::new();
        let mut stack = vec![Frame {
            node_id: 0,
            bm_idx: 0,
            restore_len: 0,
        }];

        // A leaf at the root would mean an empty string was inserted as a
        // pattern; not a meaningful domain, so it's intentionally skipped.

        let mut steps: u64 = 0;
        while let Some(top) = stack.last_mut() {
            steps += 1;
            if steps > MAX_DOMAIN_SET_STEPS {
                return Err(anyhow!(
                    "mrs domain-set: trie walk exceeded {MAX_DOMAIN_SET_STEPS} steps \
                     (labelBitmap does not encode a well-formed tree)"
                ));
            }
            let bm_idx = top.bm_idx;
            let is_end = self.label_bitmap.get(bm_idx).ok_or_else(|| {
                anyhow!("mrs domain-set: labelBitmap index {bm_idx} out of range")
            })?;
            if is_end {
                current.truncate(top.restore_len);
                stack.pop();
                continue;
            }
            let node_id = top.node_id;
            top.bm_idx += 1;

            let label_idx = bm_idx
                .checked_sub(node_id)
                .ok_or_else(|| anyhow!("mrs domain-set: label index underflow"))?;
            let label = *self
                .labels
                .get(label_idx)
                .ok_or_else(|| anyhow!("mrs domain-set: label index {label_idx} out of range"))?;

            let restore_len = current.len();
            current.push(label);

            let next_node_id = self
                .label_bitmap
                .rank0(bm_idx + 1)
                .ok_or_else(|| anyhow!("mrs domain-set: rank0({}) out of range", bm_idx + 1))?;
            let next_bm_idx = next_node_id
                .checked_sub(1)
                .and_then(|k| self.label_bitmap.select1(k))
                .ok_or_else(|| anyhow!("mrs domain-set: select1 for node {next_node_id} failed"))?
                + 1;

            if self.is_leaf(next_node_id)? {
                emit(&mut f, &current)?;
            }

            if stack.len() >= MAX_DOMAIN_SET_DEPTH {
                return Err(anyhow!(
                    "mrs domain-set: trie walk exceeded {MAX_DOMAIN_SET_DEPTH}-deep stack \
                     (labelBitmap does not encode a well-formed tree)"
                ));
            }
            stack.push(Frame {
                node_id: next_node_id,
                bm_idx: next_bm_idx,
                restore_len,
            });
        }
        Ok(())
    }
}

/// Reverse the accumulated (reversed-domain) bytes back to forward reading
/// order and hand the resulting text to `f`.
fn emit(f: &mut impl FnMut(String), reversed: &[u8]) -> Result<()> {
    let mut bytes = reversed.to_vec();
    bytes.reverse();
    let text =
        String::from_utf8(bytes).map_err(|_| anyhow!("mrs domain-set: non-UTF-8 domain bytes"))?;
    f(text);
    Ok(())
}
