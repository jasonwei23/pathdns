//! Shared helpers for atomic file persistence: the `.tmp`-then-rename write
//! primitive, and the magic+fingerprint+count header framing common to every
//! persisted cache file (the DNS response cache and the verdict cache), so
//! neither has to hand-roll its own copy of that boilerplate.

use anyhow::{Context, Result};
use std::fs::File;
use std::io::{BufWriter, Read, Write};
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

/// Write the shared persisted-cache file header: an 8-byte format magic, an
/// 8-byte config fingerprint, then a 4-byte entry count. Every persisted
/// cache file (DNS response cache, verdict cache) starts with exactly this,
/// followed by `count` entries in a format specific to that cache.
pub(crate) fn write_header(
    w: &mut impl Write,
    magic: &[u8; 8],
    fingerprint: u64,
    count: u32,
) -> Result<()> {
    w.write_all(magic)?;
    w.write_all(&fingerprint.to_le_bytes())?;
    w.write_all(&count.to_le_bytes())?;
    Ok(())
}

/// Read and validate the shared header written by [`write_header`], returning
/// the stored entry count. `label` names the file kind (e.g. "cache",
/// "verdict cache") for the error messages a mismatch produces.
pub(crate) fn read_and_check_header(
    r: &mut impl Read,
    magic: &[u8; 8],
    fingerprint: u64,
    label: &str,
) -> Result<u32> {
    let mut stored_magic = [0u8; 8];
    r.read_exact(&mut stored_magic).context("read magic")?;
    anyhow::ensure!(
        &stored_magic == magic,
        "unrecognised {label} file format (magic mismatch)"
    );
    let stored_fp = read_u64(r).context("read fingerprint")?;
    anyhow::ensure!(
        stored_fp == fingerprint,
        "{label} file was built with a different config (fingerprint mismatch) — discarding"
    );
    read_u32(r).context("read count")
}

pub(crate) fn read_u16(r: &mut impl Read) -> Result<u16> {
    let mut buf = [0u8; 2];
    r.read_exact(&mut buf)?;
    Ok(u16::from_le_bytes(buf))
}

pub(crate) fn read_u32(r: &mut impl Read) -> Result<u32> {
    let mut buf = [0u8; 4];
    r.read_exact(&mut buf)?;
    Ok(u32::from_le_bytes(buf))
}

pub(crate) fn read_u64(r: &mut impl Read) -> Result<u64> {
    let mut buf = [0u8; 8];
    r.read_exact(&mut buf)?;
    Ok(u64::from_le_bytes(buf))
}

/// Upper bound on a single `read_bytes` field. Every persisted byte string
/// (a DNS packet, query, or qname) is bounded by the DNS wire format itself
/// (max message size 65535, over TCP framed with a 2-byte length prefix), so
/// this is already generous. Without this cap, a truncated or corrupted
/// persist file would feed an attacker/corruption-controlled `u32` straight
/// into `vec![0u8; len]` — up to 4 GiB from a single 4-byte length field —
/// which can abort the whole process on allocation failure (Rust's global
/// allocator aborts rather than returning an error, independent of the
/// `panic = "abort"` release profile setting).
const MAX_PERSISTED_BYTES: usize = 1 << 16;

pub(crate) fn read_bytes(r: &mut impl Read) -> Result<Vec<u8>> {
    let len = read_u32(r)? as usize;
    anyhow::ensure!(
        len <= MAX_PERSISTED_BYTES,
        "persisted byte field too large ({len} > {MAX_PERSISTED_BYTES}); file is likely corrupt"
    );
    let mut buf = vec![0u8; len];
    r.read_exact(&mut buf)?;
    Ok(buf)
}
