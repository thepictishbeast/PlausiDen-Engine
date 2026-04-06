//! System artifact generation -- logs, processes, installs, crash dumps, syslog,
//! package history, and login history.
//!
//! This crate generates forensically plausible system-level artifacts that
//! appear in Linux forensic investigations: syslog entries, package management
//! events, and user login sessions. Each generator implements the
//! [`engine_core::traits::DataGenerator`] trait.

pub mod crash;
pub mod installs;
pub mod login_history;
pub mod logs;
pub mod package_history;
pub mod processes;
pub mod syslog;
