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

    #[inline]
    pub(crate) fn finish(self) -> u64 {
        self.0
    }
}
