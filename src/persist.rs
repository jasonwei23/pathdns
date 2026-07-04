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
///   3. Flush and fsync the temporary file.
///   4. Rename the `.tmp` file over `path` and fsync its parent directory.
///
/// If `write_fn` returns an error the `.tmp` file is left in place for
/// diagnostics but the target `path` is not touched.
pub fn atomic_write<F>(path: &Path, write_fn: F) -> Result<()>
where
    F: FnOnce(&mut BufWriter<File>) -> Result<()>,
{
    let mut tmp_name = path.as_os_str().to_os_string();
    tmp_name.push(".tmp");
    let tmp = std::path::PathBuf::from(tmp_name);
    let file = File::create(&tmp).with_context(|| format!("create {}", tmp.display()))?;
    let mut w = BufWriter::new(file);
    write_fn(&mut w)?;
    w.flush().context("flush")?;
    w.get_ref().sync_all().context("fsync temporary file")?;
    drop(w);
    std::fs::rename(&tmp, path)
        .with_context(|| format!("rename {} -> {}", tmp.display(), path.display()))?;
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    File::open(parent)
        .with_context(|| format!("open parent directory {}", parent.display()))?
        .sync_all()
        .with_context(|| format!("fsync parent directory {}", parent.display()))
}
