#![deny(missing_docs)]
//! Shared utilities for Jetstreamer components.
//!
//! Currently this crate provides helpers for spawning local ClickHouse
//! instances that were previously part of the deprecated Geyser plugin crate.

/// ClickHouse process management helpers.
pub mod clickhouse;

/// Bounded diagnostic assembly of pinned Solana v1.4.25 data shreds.
pub mod horizon_legacy_shred;

/// Re-exported ClickHouse utility types and functions.
pub use clickhouse::{
    ClickhouseError, ClickhouseStartResult, start, start_client, stop, stop_sync,
};
