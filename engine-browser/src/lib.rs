//! # PlausiDen Engine — Browser Module
//!
//! Generates forensically plausible browser artifacts: history entries,
//! cookies, search queries, bookmarks, downloads, autofill data, and
//! localStorage entries.
//!
//! This crate compiles to both native and WASM targets, enabling use
//! in the browser extension (Tier 0) via wasm-bindgen.

pub mod autofill;
pub mod bookmarks;
pub mod cookies;
pub mod downloads;
pub mod history;
pub mod localstorage;
pub mod patterns;
pub mod searches;

pub mod url_corpus;

pub use autofill::AutofillGenerator;
pub use bookmarks::BookmarkGenerator;
pub use cookies::CookieGenerator;
pub use downloads::DownloadGenerator;
pub use history::HistoryGenerator;
pub use localstorage::LocalStorageGenerator;
pub use searches::SearchGenerator;
