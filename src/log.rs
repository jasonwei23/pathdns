//! Minimal process logging macros.
//!
//! - `log_error!`: always printed to stderr; for fatal startup failures.
//! - `warn!`, `startup!`, `warn_rate_limited!`: silenced (info available via web dashboard).
//! - `verbose!`: printed only when `--verbose` is active; for per-query diagnostics.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

static VERBOSE: AtomicBool = AtomicBool::new(false);

pub fn configure(verbose: bool) {
    VERBOSE.store(verbose, Ordering::Relaxed);
}

pub fn verbose_enabled() -> bool {
    VERBOSE.load(Ordering::Relaxed)
}

pub fn emit_error(args: std::fmt::Arguments<'_>) {
    eprintln!("error: {args}");
}

pub fn emit_warn(_: std::fmt::Arguments<'_>) {}
pub fn emit_startup(_: std::fmt::Arguments<'_>) {}
pub fn warn_rate_limited(_: &AtomicU64, _: u64, _: std::fmt::Arguments<'_>) {}

pub(crate) fn emit_verbose(args: std::fmt::Arguments<'_>) {
    eprintln!("debug: {args}");
}

/// Always printed. Use for fatal startup failures.
#[macro_export]
macro_rules! log_error {
    ($($arg:tt)*) => {
        $crate::log::emit_error(format_args!($($arg)*))
    };
}

/// Silenced — operational events are visible in the web dashboard.
#[macro_export]
macro_rules! warn {
    ($($arg:tt)*) => {
        $crate::log::emit_warn(format_args!($($arg)*))
    };
}

/// Silenced — startup summaries are visible in the web dashboard.
#[macro_export]
macro_rules! startup {
    ($($arg:tt)*) => {
        $crate::log::emit_startup(format_args!($($arg)*))
    };
}

/// Silenced.
#[macro_export]
macro_rules! warn_rate_limited {
    ($last:expr, $interval:expr, $($arg:tt)*) => {
        $crate::log::warn_rate_limited($last, $interval, format_args!($($arg)*))
    };
}

/// Printed only when --verbose is active.
#[macro_export]
macro_rules! verbose {
    ($($arg:tt)*) => {
        if $crate::log::verbose_enabled() {
            $crate::log::emit_verbose(format_args!($($arg)*))
        }
    };
}
