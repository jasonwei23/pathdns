//! Shared helper for atomic file persistence (write to `.tmp`, then rename).
//!
//! Used by the DNS response cache and the verdict cache to ensure that a
//! partially-written file is never left in place on crash or power loss.

use anyhow::{Context, Result};
use std::fs::File;
use std::io::{BufWriter, Write};
use std::path::Path;

/// Write a file atomically:
///   1. Create a sibling `<path>.tmp` file.
///   2. Call `write_fn` with a `BufWriter` over that file.
///   3. Flush + close the writer.
///   4. Rename the `.tmp` file over `path`.
///
/// If `write_fn` returns an error the `.tmp` file is left in place for
/// diagnostics but the target `path` is not touched.
pub fn atomic_write<F>(path: &Path, write_fn: F) -> Result<()>
where
    F: FnOnce(&mut BufWriter<File>) -> Result<()>,
{
    let tmp = path.with_extension("tmp");
    let file = File::create(&tmp).with_context(|| format!("create {}", tmp.display()))?;
    let mut w = BufWriter::new(file);
    write_fn(&mut w)?;
    w.flush().context("flush")?;
    drop(w);
    std::fs::rename(&tmp, path)
        .with_context(|| format!("rename {} -> {}", tmp.display(), path.display()))
}
