//! Communications artifact generation -- contacts, calls, SMS, calendar, email headers.
//!
//! Generates forensically plausible communications data: contact lists with
//! realistic names and phone numbers, call logs following circadian patterns,
//! and related messaging artifacts.

pub mod calls;
pub mod calendar;
pub mod contacts;
pub mod email_headers;
pub mod notifications;
pub mod sms;

// Re-export primary generators for convenience.
pub use calls::{CallDirection, CallEntry, CallGenerator};
pub use contacts::{ContactCategory, ContactEntry, ContactGenerator};
pub use email_headers::{EmailHeaderEntry, EmailHeaderGenerator};
pub use sms::{ReadStatus, SmsDirection, SmsEntry, SmsGenerator};
