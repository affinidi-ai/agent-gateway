//! Channel-specific logging utilities
//!
//! Provides macros for logging with channel context prepended as
//! `[CHANNEL:config_id]`. The `*_tp` variants additionally append
//! `[TP:alias]` so the dashboard can filter outbound (Transit Point)
//! traffic apart from inbound (Access Point) traffic for the same
//! surface.

/// Log info message with channel prefix
#[macro_export]
macro_rules! channel_info {
    ($config_id:expr, $($arg:tt)*) => {
        tracing::info!("[CHANNEL:{}] {}", $config_id, format!($($arg)*))
    };
}

/// Log warn message with channel prefix
#[macro_export]
macro_rules! channel_warn {
    ($config_id:expr, $($arg:tt)*) => {
        tracing::warn!("[CHANNEL:{}] {}", $config_id, format!($($arg)*))
    };
}

/// Log error message with channel prefix
#[macro_export]
macro_rules! channel_error {
    ($config_id:expr, $($arg:tt)*) => {
        tracing::error!("[CHANNEL:{}] {}", $config_id, format!($($arg)*))
    };
}

/// Log debug message with channel prefix
#[macro_export]
macro_rules! channel_debug {
    ($config_id:expr, $($arg:tt)*) => {
        tracing::debug!("[CHANNEL:{}] {}", $config_id, format!($($arg)*))
    };
}

/// Log info message with channel + Transit Point prefix.
#[macro_export]
macro_rules! channel_info_tp {
    ($config_id:expr, $tp_alias:expr, $($arg:tt)*) => {
        tracing::info!("[CHANNEL:{}][TP:{}] {}", $config_id, $tp_alias, format!($($arg)*))
    };
}

/// Log warn message with channel + Transit Point prefix.
#[macro_export]
macro_rules! channel_warn_tp {
    ($config_id:expr, $tp_alias:expr, $($arg:tt)*) => {
        tracing::warn!("[CHANNEL:{}][TP:{}] {}", $config_id, $tp_alias, format!($($arg)*))
    };
}

/// Log error message with channel + Transit Point prefix.
#[macro_export]
macro_rules! channel_error_tp {
    ($config_id:expr, $tp_alias:expr, $($arg:tt)*) => {
        tracing::error!("[CHANNEL:{}][TP:{}] {}", $config_id, $tp_alias, format!($($arg)*))
    };
}

/// Log debug message with channel + Transit Point prefix.
#[macro_export]
macro_rules! channel_debug_tp {
    ($config_id:expr, $tp_alias:expr, $($arg:tt)*) => {
        tracing::debug!("[CHANNEL:{}][TP:{}] {}", $config_id, $tp_alias, format!($($arg)*))
    };
}
