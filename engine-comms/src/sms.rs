//! SMS message generation -- realistic text message artifacts.
//!
//! Generates forensically plausible SMS entries with sender/receiver phone numbers,
//! message text drawn from common conversational templates, timestamps following
//! circadian patterns, and read/unread status distributions.

use chrono::{DateTime, Duration, Utc};
use engine_core::error::{EngineError, Result};
use engine_core::profile::UserProfile;
use engine_core::traits::{
    Artifact, ArtifactMetadata, DataCategory, DataGenerator, GenerationContext, ResourceCost,
};
use rand::distributions::{Distribution, Uniform};
use rand::seq::SliceRandom;
use rand::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};

/// Phone number pool for SMS participants.
const PHONE_POOL: &[&str] = &[
    "(202) 555-0147", "(312) 555-0198", "(415) 555-0123", "(718) 555-0176",
    "(213) 555-0134", "(305) 555-0189", "(404) 555-0156", "(617) 555-0112",
    "(503) 555-0167", "(512) 555-0143", "(206) 555-0178", "(303) 555-0121",
    "(614) 555-0195", "(704) 555-0132", "(919) 555-0187", "(602) 555-0154",
    "(480) 555-0116", "(816) 555-0169", "(314) 555-0141", "(612) 555-0193",
    "(913) 555-0128", "(408) 555-0185", "(510) 555-0152", "(916) 555-0117",
    "(720) 555-0163", "(469) 555-0139", "(972) 555-0191", "(678) 555-0126",
    "(770) 555-0183", "(407) 555-0148", "(813) 555-0114", "(757) 555-0165",
];

/// Common SMS message templates covering everyday conversational patterns.
const MESSAGE_TEMPLATES: &[&str] = &[
    // Greetings and check-ins
    "Hey, how are you?",
    "Hi! What are you up to?",
    "Good morning!",
    "Hey, are you free later?",
    "Just checking in",
    // Logistics
    "On my way",
    "Running about 10 minutes late",
    "I'm here",
    "Be there in 5",
    "Just left, see you soon",
    "Can you pick up some milk?",
    "What time works for you?",
    "Let me know when you get there",
    "I'll be home around 6",
    "Leaving work now",
    // Confirmations
    "Sounds good!",
    "Sure, no problem",
    "Ok",
    "Got it, thanks",
    "See you then",
    "Perfect, see you there",
    "Works for me",
    "Will do",
    // Social
    "Want to grab lunch?",
    "Are you coming tonight?",
    "Had a great time today!",
    "Thanks for dinner",
    "Let's plan something this weekend",
    "Happy birthday!",
    "Miss you!",
    "Can't wait to see you",
    // Quick responses
    "lol",
    "haha yeah",
    "Definitely",
    "Maybe, I'll let you know",
    "Not sure yet",
    "Sorry, just saw this",
    "Call me when you can",
    "I'll text you later",
    // Practical
    "What's the address?",
    "Can you send me the link?",
    "Did you see my email?",
    "Meeting got moved to 3pm",
    "Don't forget your keys",
    "The package arrived",
    "I'll pick up the kids",
    "Dinner is ready",
];

/// Direction of the SMS message relative to the device owner.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SmsDirection {
    /// Message sent by the device owner.
    Sent,
    /// Message received by the device owner.
    Received,
}

/// Read status of the message.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ReadStatus {
    /// Message has been opened and read.
    Read,
    /// Message has not been read yet.
    Unread,
}

/// A single SMS message entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SmsEntry {
    /// Artifact metadata (timestamps, category, size).
    pub meta: ArtifactMetadata,
    /// Phone number of the message sender.
    pub sender: String,
    /// Phone number of the message receiver.
    pub receiver: String,
    /// Direction relative to device owner.
    pub direction: SmsDirection,
    /// Message text content.
    pub message: String,
    /// When the message was sent.
    pub timestamp: DateTime<Utc>,
    /// Whether the message has been read.
    pub read_status: ReadStatus,
}

impl Artifact for SmsEntry {
    fn metadata(&self) -> &ArtifactMetadata {
        &self.meta
    }

    fn validate_plausibility(&self) -> Result<()> {
        self.meta.validate_timestamps()?;

        if self.sender.is_empty() {
            return Err(EngineError::ImplausibleArtifact {
                reason: "SMS sender phone number is empty".to_string(),
            });
        }

        if self.receiver.is_empty() {
            return Err(EngineError::ImplausibleArtifact {
                reason: "SMS receiver phone number is empty".to_string(),
            });
        }

        if self.sender == self.receiver {
            return Err(EngineError::ImplausibleArtifact {
                reason: "SMS sender and receiver are the same number".to_string(),
            });
        }

        if self.message.is_empty() {
            return Err(EngineError::ImplausibleArtifact {
                reason: "SMS message text is empty".to_string(),
            });
        }

        // Sent messages should always be read.
        if self.direction == SmsDirection::Sent && self.read_status == ReadStatus::Unread {
            return Err(EngineError::ImplausibleArtifact {
                reason: "sent message cannot be unread".to_string(),
            });
        }

        Ok(())
    }

    fn to_bytes(&self) -> Result<Vec<u8>> {
        serde_json::to_vec(self).map_err(EngineError::Serialization)
    }
}

/// Generates realistic SMS message entries.
pub struct SmsGenerator;

impl SmsGenerator {
    /// Create a new SMS generator.
    pub fn new() -> Self {
        Self
    }

    /// The device owner's phone number (consistent across a session).
    const OWNER_PHONE: &str = "(555) 555-0100";

    /// Generate a timestamp for the SMS within the last 30 days.
    fn generate_timestamp(
        context: &GenerationContext,
        rng: &mut (impl RngCore + CryptoRng),
    ) -> DateTime<Utc> {
        let day_offset = Uniform::new_inclusive(0i64, 29).sample(rng);
        let base = context.now - Duration::days(day_offset);

        // Messages cluster during waking hours (7am-11pm).
        let hour = if Uniform::new_inclusive(0u32, 99).sample(rng) < 85 {
            Uniform::new_inclusive(7u32, 22).sample(rng)
        } else {
            // Some late-night/early-morning messages.
            let sleep_hours: Vec<u32> = (0..7).chain(23..24).collect();
            *sleep_hours.choose(rng).unwrap_or(&2)
        };

        let minute = Uniform::new_inclusive(0u32, 59).sample(rng);
        let second = Uniform::new_inclusive(0u32, 59).sample(rng);

        base.date_naive()
            .and_hms_opt(hour, minute, second)
            .map(|ndt| DateTime::<Utc>::from_naive_utc_and_offset(ndt, Utc))
            .unwrap_or(base)
    }
}

impl Default for SmsGenerator {
    fn default() -> Self {
        Self::new()
    }
}

impl DataGenerator for SmsGenerator {
    fn generate(
        &self,
        _profile: &UserProfile,
        context: &GenerationContext,
        rng: &mut (impl RngCore + CryptoRng),
    ) -> Result<Box<dyn Artifact>> {
        let other_phone = PHONE_POOL
            .choose(rng)
            .ok_or_else(|| EngineError::InvalidContext("empty phone pool".to_string()))?
            .to_string();

        let message = MESSAGE_TEMPLATES
            .choose(rng)
            .ok_or_else(|| EngineError::InvalidContext("empty message template pool".to_string()))?
            .to_string();

        let timestamp = Self::generate_timestamp(context, rng);

        // 55% received, 45% sent.
        let direction = if Uniform::new_inclusive(0u32, 99).sample(rng) < 55 {
            SmsDirection::Received
        } else {
            SmsDirection::Sent
        };

        let (sender, receiver) = match direction {
            SmsDirection::Sent => (Self::OWNER_PHONE.to_string(), other_phone),
            SmsDirection::Received => (other_phone, Self::OWNER_PHONE.to_string()),
        };

        let read_status = match direction {
            SmsDirection::Sent => ReadStatus::Read,
            SmsDirection::Received => {
                // 85% of received messages are read.
                if Uniform::new_inclusive(0u32, 99).sample(rng) < 85 {
                    ReadStatus::Read
                } else {
                    ReadStatus::Unread
                }
            }
        };

        let size_estimate =
            sender.len() as u64 + receiver.len() as u64 + message.len() as u64 + 128;

        let meta = ArtifactMetadata::new(
            DataCategory::Communications,
            timestamp,
            timestamp,
            size_estimate,
        )?;

        let entry = SmsEntry {
            meta,
            sender,
            receiver,
            direction,
            message,
            timestamp,
            read_status,
        };

        entry.validate_plausibility()?;
        Ok(Box::new(entry))
    }

    fn category(&self) -> DataCategory {
        DataCategory::Communications
    }

    fn forensic_weight(&self) -> u32 {
        90 // SMS logs are heavily relied upon in forensic analysis.
    }

    fn resource_cost(&self) -> ResourceCost {
        ResourceCost {
            cpu_us: 20,
            disk_bytes: 256,
            network_bytes: 0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use engine_core::entropy::seeded_rng;

    fn test_profile() -> UserProfile {
        UserProfile::default()
    }

    #[test]
    fn test_basic_sms_generation() {
        let g = SmsGenerator::new();
        let p = test_profile();
        let c = GenerationContext::new();
        let mut r = seeded_rng(42);

        let a = g.generate(&p, &c, &mut r).unwrap();
        a.validate_plausibility().unwrap();

        let b = a.to_bytes().unwrap();
        let e: SmsEntry = serde_json::from_slice(&b).unwrap();

        assert!(!e.sender.is_empty());
        assert!(!e.receiver.is_empty());
        assert_ne!(e.sender, e.receiver);
        assert!(!e.message.is_empty());
    }

    #[test]
    fn test_500_sms_entries_valid() {
        let g = SmsGenerator::new();
        let p = test_profile();
        let c = GenerationContext::new();
        for s in 0..500 {
            let mut r = seeded_rng(s);
            g.generate(&p, &c, &mut r)
                .unwrap()
                .validate_plausibility()
                .unwrap_or_else(|err| panic!("entry {s} failed: {err}"));
        }
    }

    #[test]
    fn test_sent_messages_always_read() {
        let g = SmsGenerator::new();
        let p = test_profile();
        let c = GenerationContext::new();
        for s in 0..500 {
            let mut r = seeded_rng(s);
            let a = g.generate(&p, &c, &mut r).unwrap();
            let b = a.to_bytes().unwrap();
            let e: SmsEntry = serde_json::from_slice(&b).unwrap();
            if e.direction == SmsDirection::Sent {
                assert_eq!(
                    e.read_status,
                    ReadStatus::Read,
                    "sent message must be marked as read"
                );
            }
        }
    }

    #[test]
    fn test_direction_variety() {
        let g = SmsGenerator::new();
        let p = test_profile();
        let c = GenerationContext::new();
        let mut sent = 0u32;
        let mut received = 0u32;
        for s in 0..500 {
            let mut r = seeded_rng(s);
            let a = g.generate(&p, &c, &mut r).unwrap();
            let b = a.to_bytes().unwrap();
            let e: SmsEntry = serde_json::from_slice(&b).unwrap();
            match e.direction {
                SmsDirection::Sent => sent += 1,
                SmsDirection::Received => received += 1,
            }
        }
        assert!(sent > 0, "should have sent messages");
        assert!(received > 0, "should have received messages");
    }

    #[test]
    fn test_some_received_messages_unread() {
        let g = SmsGenerator::new();
        let p = test_profile();
        let c = GenerationContext::new();
        let mut unread_count = 0u32;
        for s in 0..500 {
            let mut r = seeded_rng(s);
            let a = g.generate(&p, &c, &mut r).unwrap();
            let b = a.to_bytes().unwrap();
            let e: SmsEntry = serde_json::from_slice(&b).unwrap();
            if e.read_status == ReadStatus::Unread {
                assert_eq!(
                    e.direction,
                    SmsDirection::Received,
                    "only received messages can be unread"
                );
                unread_count += 1;
            }
        }
        assert!(unread_count > 0, "should have some unread received messages");
    }
}
