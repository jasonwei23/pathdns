//! Minimal process logging macros.
//!
//! - `log_error!`: always printed to stderr; for fatal startup failures.
//! - `log_info!`: always printed to stderr; for listen addresses at startup.
//! - `warn!`, `startup!`, `warn_rate_limited!`: silenced (info available via web dashboard).

use std::sync::atomic::AtomicU64;

pub fn emit_error(args: std::fmt::Arguments<'_>) {
    eprintln!("error: {args}");
}

pub fn emit_info(args: std::fmt::Arguments<'_>) {
    eprintln!("{args}");
}

pub fn emit_warn(_: std::fmt::Arguments<'_>) {}
pub fn emit_startup(_: std::fmt::Arguments<'_>) {}
pub fn warn_rate_limited(_: &AtomicU64, _: u64, _: std::fmt::Arguments<'_>) {}

/// Always printed. Use for fatal startup failures.
#[macro_export]
macro_rules! log_error {
    ($($arg:tt)*) => {
        $crate::log::emit_error(format_args!($($arg)*))
    };
}

/// Always printed. Use for listening address/port announcements.
#[macro_export]
macro_rules! log_info {
    ($($arg:tt)*) => {
        $crate::log::emit_info(format_args!($($arg)*))
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
