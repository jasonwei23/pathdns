//! Minimal process logging macros.
//!
//! - `log_error!`: always printed to stderr; for fatal startup failures.
//! - `log_info!`: always printed to stderr; for listen addresses at startup.
//! - `warn!`, `startup!`: printed to stderr so headless deployments remain observable.
//! - `warn_rate_limited!`: printed to stderr at most once per configured interval.

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

pub fn emit_error(args: std::fmt::Arguments<'_>) {
    eprintln!("error: {args}");
}

pub fn emit_info(args: std::fmt::Arguments<'_>) {
    eprintln!("{args}");
}

pub fn emit_warn(args: std::fmt::Arguments<'_>) {
    eprintln!("warning: {args}");
}

pub fn emit_startup(args: std::fmt::Arguments<'_>) {
    eprintln!("{args}");
}

pub fn warn_rate_limited(last: &AtomicU64, interval_secs: u64, args: std::fmt::Arguments<'_>) {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
        .max(1);
    let mut previous = last.load(Ordering::Relaxed);
    loop {
        if previous != 0 && now.saturating_sub(previous) < interval_secs {
            return;
        }
        match last.compare_exchange_weak(previous, now, Ordering::Relaxed, Ordering::Relaxed) {
            Ok(_) => {
                emit_warn(args);
                return;
            }
            Err(actual) => previous = actual,
        }
    }
}

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

/// Operational warning, also visible without the web dashboard.
#[macro_export]
macro_rules! warn {
    ($($arg:tt)*) => {
        $crate::log::emit_warn(format_args!($($arg)*))
    };
}

/// Startup summary, also visible without the web dashboard.
#[macro_export]
macro_rules! startup {
    ($($arg:tt)*) => {
        $crate::log::emit_startup(format_args!($($arg)*))
    };
}

/// Operational warning limited by a shared last-emission timestamp.
#[macro_export]
macro_rules! warn_rate_limited {
    ($last:expr, $interval:expr, $($arg:tt)*) => {
        $crate::log::warn_rate_limited($last, $interval, format_args!($($arg)*))
    };
}
