#![no_main]

//! Fuzzes the mihomo `.mrs` domain-set decoder (`pathdns::mrs::decode_domain_patterns`).
//!
//! This decoder already had a real DoS/memory-exhaustion bug fixed by hand
//! (a crafted `labelBitmap` could make the trie walk revisit the same nodes
//! from many parents — a decompression-bomb-style blowup from a tiny file on
//! disk). It parses a `.mrs` ruleset file, which on a router is often fetched
//! from a remote URL — untrusted input by pathdns's own threat model.

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = pathdns::mrs::decode_domain_patterns(data);
});
