//! Filesystem artifact generation -- files, metadata, thumbnails, trash.
//!
//! Generates forensically plausible filesystem artifacts: recently-accessed
//! documents, thumbnail cache entries (Freedesktop spec), trash/recycle bin
//! metadata (Freedesktop spec), and extended file attributes including
//! download provenance and creator application metadata.

pub mod files;
pub mod metadata;
pub mod thumbnails;
pub mod trash;

pub use files::{RecentDocumentEntry, RecentDocumentsGenerator};
pub use metadata::{FileMetadataEntry, FileMetadataGenerator, XAttr};
pub use thumbnails::{ThumbnailCacheEntry, ThumbnailCacheGenerator, ThumbnailSize};
pub use trash::{TrashEntry, TrashGenerator};
