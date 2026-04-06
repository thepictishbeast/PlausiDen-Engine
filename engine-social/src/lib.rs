//! Social media artifact generation -- activity, messaging, notifications.
//!
//! This crate generates forensically plausible social media artifacts:
//!
//! - [`activity`] -- Social media activity (posts, likes, comments, shares, follows)
//!   with circadian timing patterns across generic platforms.
//! - [`messaging`] -- Instant messaging conversations with conversational clustering
//!   (rapid back-and-forth bursts separated by natural gaps).
//! - [`notification`] -- Social notification streams (likes, comments, follows,
//!   mentions, DMs) with engagement-scaled frequency.
//! - [`content`] -- Social media post content (text, photos, stories, shares).
//! - [`engagement`] -- Engagement metrics snapshots (followers, likes, growth trends).

pub mod activity;
pub mod content;
pub mod engagement;
pub mod messaging;
pub mod notification;
