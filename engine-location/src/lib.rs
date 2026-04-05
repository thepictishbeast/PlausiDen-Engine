//! Location artifact generation — GPS traces, WiFi history, cell towers, EXIF.
//!
//! This crate generates forensically plausible location data including GPS
//! traces with realistic movement patterns, WiFi connection histories that
//! follow daily routines, and (future) cell tower and EXIF metadata.

pub mod gps;
pub mod wifi;
pub mod cell;
pub mod exif;

pub use gps::{GpsEntry, GpsGenerator, LocationSource, MovementMode};
pub use wifi::{NetworkCategory, WifiEntry, WifiGenerator};
pub use cell::{CellEntry, CellGenerator};
pub use exif::{ExifEntry, ExifGenerator};
