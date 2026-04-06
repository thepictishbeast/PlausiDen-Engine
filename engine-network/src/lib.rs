//! Network artifact generation -- DNS, HTTP timing, TLS fingerprints, and packet flows.
//!
//! This crate generates forensically plausible network traffic artifacts:
//! DNS query logs with realistic domain pools and browsing patterns,
//! HTTP request timing with log-normal response distributions,
//! TLS connection fingerprints with real JA3 hashes for major browsers,
//! and NetFlow-style packet flow records.

pub mod dns;
pub mod http;
pub mod http_timing;
pub mod packets;
pub mod tls;
pub mod tls_fingerprint;
