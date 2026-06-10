//! Minimal process logging macros.
//!
//! - `log_error!`: always printed to stderr; for startup failures and permanent errors.
//! - `warn!`: always printed to stderr; for risky configuration or degraded operation.
//! - `startup!`: always printed; for configuration summaries at startup.

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

pub fn emit_error(args: std::fmt::Arguments<'_>) {
    eprintln!("error: {args}");
}

pub fn emit_warn(args: std::fmt::Arguments<'_>) {
    eprintln!("warn: {args}");
}

pub fn emit_startup(args: std::fmt::Arguments<'_>) {
    eprintln!("info: {args}");
}

/// Emit a `warn!` at most once per `interval_secs` seconds across all callers sharing `last`.
/// Uses compare-and-swap so concurrent calls don't double-emit.
pub fn warn_rate_limited(last: &AtomicU64, interval_secs: u64, args: std::fmt::Arguments<'_>) {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let old = last.load(Ordering::Relaxed);
    if now.saturating_sub(old) >= interval_secs
        && last
            .compare_exchange(old, now, Ordering::Relaxed, Ordering::Relaxed)
            .is_ok()
    {
        emit_warn(args);
    }
}

/// Always printed. Use for startup failures and permanent error conditions.
#[macro_export]
macro_rules! log_error {
    ($($arg:tt)*) => {
        $crate::log::emit_error(format_args!($($arg)*))
    };
}

/// Always printed. Use for degraded operation that does not stop startup.
#[macro_export]
macro_rules! warn {
    ($($arg:tt)*) => {
        $crate::log::emit_warn(format_args!($($arg)*))
    };
}

/// Always printed. Use for startup configuration summaries.
#[macro_export]
macro_rules! startup {
    ($($arg:tt)*) => {
        $crate::log::emit_startup(format_args!($($arg)*))
    };
}

/// Like `warn!` but rate-limited: at most one message per `$interval` seconds.
/// `$last` must be a `&'static AtomicU64` shared across all callers for that event type.
#[macro_export]
macro_rules! warn_rate_limited {
    ($last:expr, $interval:expr, $($arg:tt)*) => {
        $crate::log::warn_rate_limited($last, $interval, format_args!($($arg)*))
    };
}
