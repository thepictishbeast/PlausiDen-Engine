//! Location artifact generation — GPS traces, WiFi history, cell towers, EXIF.
//!
//! This crate generates forensically plausible location data including GPS
//! traces with realistic circadian movement patterns, WiFi connection
//! histories with signal-strength variation, cell tower logs with US
//! carrier codes and movement-correlated handoffs, and EXIF photo metadata.

pub mod cell_tower;
pub mod exif;
pub mod gps;
pub mod wifi;

pub use cell_tower::{CellTowerGenerator, CellTowerLog};
pub use exif::{ExifEntry, ExifGenerator};
pub use gps::{GpsPoint, GpsTraceGenerator, LocationSource, MovementMode};
pub use wifi::{NetworkCategory, WifiGenerator, WifiSighting};
