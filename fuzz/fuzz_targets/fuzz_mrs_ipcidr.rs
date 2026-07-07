#![no_main]

//! Fuzzes the mihomo `.mrs` ipcidr-set decoder (`pathdns::mrs::decode_ipcidr_ranges`).
//! See `fuzz_mrs_domain.rs` for why `.mrs` files are treated as untrusted input.

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = pathdns::mrs::decode_ipcidr_ranges(data);
});
