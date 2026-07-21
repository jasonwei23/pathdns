//! FNV-1a 64-bit hashing shared by cache keys and the config fingerprint.
//!
//! These hash values are persisted to disk (cache/verdict files are rejected on
//! fingerprint mismatch), so the algorithm must stay stable across versions —
//! do NOT replace it with a non-deterministic or platform-dependent hasher.

#[derive(Debug, Clone, Copy)]
pub(crate) struct Fnv1a(u64);

impl Fnv1a {
    const OFFSET: u64 = 14695981039346656037;
    const PRIME: u64 = 1099511628211;

    pub(crate) fn new() -> Self {
        Self(Self::OFFSET)
    }

    #[inline]
    pub(crate) fn write_byte(&mut self, b: u8) {
        self.0 ^= b as u64;
        self.0 = self.0.wrapping_mul(Self::PRIME);
    }

    #[inline]
    pub(crate) fn write(&mut self, bytes: &[u8]) {
        for &b in bytes {
            self.write_byte(b);
        }
    }

    /// Domain separator between adjacent variable-length fields, so that
    /// e.g. ("ab", "c") and ("a", "bc") hash differently.
    #[inline]
    pub(crate) fn write_sep(&mut self) {
        self.0 ^= 0x00FF_FF00;
        self.0 = self.0.wrapping_mul(Self::PRIME);
    }

    /// Hash a DNS wire-format QNAME (length-prefixed labels terminated by a
    /// zero-length label), lowercasing each label byte — the case-insensitive
    /// comparison DNS names require. `question` starts at the QNAME's first
    /// length byte. Returns the offset just past the terminating zero-length
    /// label, i.e. where QTYPE/QCLASS begins.
    ///
    /// This is the reference implementation of that algorithm, used by
    /// `cache::cache_key_with_variant` (hashing fresh from raw wire bytes;
    /// now test-only) and mirrored inline by
    /// `dns::query::skip_query_question` (which fuses the identical
    /// byte-for-byte sequence into `parse_query_fast`'s validation walk, so
    /// every query's QNAME is scanned once instead of twice — see that
    /// function's doc comment for why it's a mirrored copy rather than a call
    /// through this method, and `cache::tests` for the equivalence tests
    /// pinning the two together).
    #[cfg(test)]
    pub(crate) fn write_qname_wire(&mut self, question: &[u8]) -> usize {
        let mut pos = 0usize;
        while let Some(&len) = question.get(pos) {
            self.write_byte(len);
            pos += 1;
            if len == 0 {
                break;
            }
            let end = (pos + len as usize).min(question.len());
            for &b in &question[pos..end] {
                self.write_byte(b.to_ascii_lowercase());
            }
            pos = end;
        }
        pos
    }

    #[inline]
    pub(crate) fn finish(self) -> u64 {
        self.0
    }
}
