// The application lives in `lib.rs` so it can also be linked as a library —
// used by the fuzz targets under `fuzz/`. This binary is just the entry point.
fn main() {
    pathdns::main();
}
