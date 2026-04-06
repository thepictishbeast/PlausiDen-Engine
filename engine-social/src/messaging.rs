//! Instant messaging artifact generation -- conversations, typing clusters, read receipts.
//!
//! Generates plausible instant messaging artifacts with realistic conversational
//! patterns: rapid back-and-forth message clusters followed by gaps, mixed
//! directions (sent/received), and short preview text.

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

/// A single instant message entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MessageEntry {
    /// Artifact metadata.
    pub meta: ArtifactMetadata,
    /// Messaging platform (generic names).
    pub platform: String,
    /// Contact name for this conversation.
    pub contact_name: String,
    /// Whether the message was sent or received.
    pub direction: MessageDirection,
    /// Short message preview text.
    pub preview: String,
    /// Timestamp of the message.
    pub timestamp: DateTime<Utc>,
    /// Whether the message has been read.
    pub read: bool,
}

/// Direction of a message relative to the device owner.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum MessageDirection {
    /// Message sent by the user.
    Sent,
    /// Message received from a contact.
    Received,
}

impl Artifact for MessageEntry {
    fn metadata(&self) -> &ArtifactMetadata {
        &self.meta
    }

    fn validate_plausibility(&self) -> Result<()> {
        self.meta.validate_timestamps()?;
        if self.platform.is_empty() {
            return Err(EngineError::ImplausibleArtifact {
                reason: "empty messaging platform".into(),
            });
        }
        if self.contact_name.is_empty() {
            return Err(EngineError::ImplausibleArtifact {
                reason: "empty contact name".into(),
            });
        }
        if self.preview.is_empty() {
            return Err(EngineError::ImplausibleArtifact {
                reason: "empty message preview".into(),
            });
        }
        // Sent messages should always be marked as read.
        if self.direction == MessageDirection::Sent && !self.read {
            return Err(EngineError::ImplausibleArtifact {
                reason: "sent message marked as unread is implausible".into(),
            });
        }
        Ok(())
    }

    fn to_bytes(&self) -> Result<Vec<u8>> {
        serde_json::to_vec(self).map_err(EngineError::Serialization)
    }
}

/// Generic messaging platform names.
const MESSAGING_PLATFORMS: &[&str] = &[
    "quickchat",
    "buzzmsg",
    "pingsend",
    "directline",
    "grouplink",
];

/// First names for generating contact names.
const FIRST_NAMES: &[&str] = &[
    "Alex", "Jordan", "Morgan", "Casey", "Riley", "Quinn", "Avery", "Taylor",
    "Drew", "Jamie", "Sam", "Robin", "Pat", "Dana", "Lee", "Skyler",
];

/// Last initials for generating contact names.
const LAST_INITIALS: &[char] = &[
    'A', 'B', 'C', 'D', 'F', 'G', 'H', 'J', 'K', 'L', 'M', 'N', 'P', 'R', 'S', 'T',
];

/// Greetings and openers.
const GREETING_PREVIEWS: &[&str] = &[
    "Hey, how are you?",
    "Hi! Long time no talk",
    "Good morning!",
    "Hey there",
    "What's up?",
    "Hope you're doing well",
    "Hello!",
    "Hey, got a sec?",
];

/// Plan-making messages.
const PLAN_PREVIEWS: &[&str] = &[
    "Want to grab lunch tomorrow?",
    "Are you free this weekend?",
    "Should we meet at the usual place?",
    "What time works for you?",
    "I was thinking we could try that new place",
    "Can you make it on Saturday?",
    "Let me know when you're available",
    "Dinner tonight?",
];

/// Short response messages.
const RESPONSE_PREVIEWS: &[&str] = &[
    "Sounds good!",
    "Sure, let me check",
    "Perfect, see you then",
    "I'll be there",
    "Running a bit late",
    "On my way",
    "Got it, thanks",
    "No worries",
    "Absolutely",
    "Let me think about it",
    "haha yeah",
    "ok!",
    "Awesome",
    "One sec",
    "Definitely",
    "I'll let you know",
];

/// Generate a contact name from the name pools.
fn random_contact_name(rng: &mut (impl RngCore + CryptoRng)) -> Result<String> {
    let first = FIRST_NAMES
        .choose(rng)
        .ok_or_else(|| EngineError::InvalidContext("empty first name pool".into()))?;
    let initial = LAST_INITIALS
        .choose(rng)
        .ok_or_else(|| EngineError::InvalidContext("empty last initial pool".into()))?;
    Ok(format!("{first} {initial}."))
}

/// Pick a message preview based on weighted categories.
fn random_preview(rng: &mut (impl RngCore + CryptoRng)) -> Result<String> {
    // Distribution: greetings (20%), plans (30%), responses (50%)
    let roll = Uniform::new_inclusive(0u32, 99).sample(rng);
    let pool = match roll {
        0..=19 => GREETING_PREVIEWS,
        20..=49 => PLAN_PREVIEWS,
        _ => RESPONSE_PREVIEWS,
    };
    pool.choose(rng)
        .map(|s| (*s).to_string())
        .ok_or_else(|| EngineError::InvalidContext("empty preview pool".into()))
}

/// Generates instant messaging artifacts with conversational clustering.
///
/// Messages come in clusters (rapid back-and-forth within minutes)
/// separated by gaps (hours between clusters), mimicking real conversations.
pub struct MessagingGenerator;

impl MessagingGenerator {
    /// Create a new messaging generator.
    pub fn new() -> Self {
        Self
    }
}

impl Default for MessagingGenerator {
    fn default() -> Self {
        Self::new()
    }
}

impl DataGenerator for MessagingGenerator {
    fn generate(
        &self,
        profile: &UserProfile,
        context: &GenerationContext,
        rng: &mut (impl RngCore + CryptoRng),
    ) -> Result<Box<dyn Artifact>> {
        let platform = MESSAGING_PLATFORMS
            .choose(rng)
            .ok_or_else(|| EngineError::InvalidContext("empty platform list".into()))?;

        let contact_name = random_contact_name(rng)?;

        // Typing pattern: cluster vs gap.
        // 60% chance this message is part of a rapid cluster (0-5 min offset),
        // 40% chance it follows a gap (1-12 hours offset).
        let cluster_roll = Uniform::new_inclusive(0u32, 99).sample(rng);
        let offset_secs = if cluster_roll < 60 {
            // Rapid cluster: 5 seconds to 5 minutes apart.
            Uniform::new_inclusive(5i64, 300).sample(rng)
        } else {
            // Gap: 1 hour to 12 hours apart.
            Uniform::new_inclusive(3600i64, 43200).sample(rng)
        };
        let timestamp = context.now - Duration::seconds(offset_secs);

        // Direction: slight bias toward received (55%) vs sent (45%).
        let dir_roll = Uniform::new_inclusive(0u32, 99).sample(rng);
        let direction = if dir_roll < 45 {
            MessageDirection::Sent
        } else {
            MessageDirection::Received
        };

        let preview = random_preview(rng)?;

        // Read status: sent messages are always read.
        // Received messages: 80% read, 20% unread (scaled by activity).
        let read = match direction {
            MessageDirection::Sent => true,
            MessageDirection::Received => {
                let read_roll = Uniform::new_inclusive(0u32, 99).sample(rng);
                // Higher risk level = more active = more likely to have read messages.
                let read_threshold = (80.0 * profile.risk_level.rate_multiplier()).min(99.0) as u32;
                read_roll < read_threshold
            }
        };

        let meta = ArtifactMetadata::new(DataCategory::Social, timestamp, timestamp, 192)?;

        let entry = MessageEntry {
            meta,
            platform: (*platform).to_string(),
            contact_name,
            direction,
            preview,
            timestamp,
            read,
        };
        entry.validate_plausibility()?;
        Ok(Box::new(entry))
    }

    fn category(&self) -> DataCategory {
        DataCategory::Social
    }

    fn forensic_weight(&self) -> u32 {
        55
    }

    fn resource_cost(&self) -> ResourceCost {
        ResourceCost {
            cpu_us: 40,
            disk_bytes: 192,
            network_bytes: 0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use engine_core::entropy::seeded_rng;

    #[test]
    fn test_generate_message_basic() {
        let generator = MessagingGenerator::new();
        let profile = UserProfile::default();
        let ctx = GenerationContext::new();
        let mut rng = seeded_rng(42);
        let artifact = generator.generate(&profile, &ctx, &mut rng).expect("generation failed");
        artifact.validate_plausibility().expect("plausibility failed");
    }

    #[test]
    fn test_500_messages_all_valid() {
        let generator = MessagingGenerator::new();
        let profile = UserProfile::default();
        let ctx = GenerationContext::new();
        for seed in 0..500 {
            let mut rng = seeded_rng(seed);
            let artifact = generator
                .generate(&profile, &ctx, &mut rng)
                .unwrap_or_else(|e| panic!("seed {seed} failed: {e}"));
            artifact
                .validate_plausibility()
                .unwrap_or_else(|e| panic!("seed {seed} plausibility failed: {e}"));
        }
    }

    #[test]
    fn test_sent_messages_always_read() {
        let generator = MessagingGenerator::new();
        let profile = UserProfile::default();
        let ctx = GenerationContext::new();
        for seed in 0..500 {
            let mut rng = seeded_rng(seed);
            let artifact = generator.generate(&profile, &ctx, &mut rng).expect("gen");
            let bytes = artifact.to_bytes().expect("serialize");
            let msg: MessageEntry = serde_json::from_slice(&bytes).expect("deserialize");
            if msg.direction == MessageDirection::Sent {
                assert!(msg.read, "sent message at seed {seed} was unread");
            }
        }
    }

    #[test]
    fn test_direction_distribution() {
        let generator = MessagingGenerator::new();
        let profile = UserProfile::default();
        let ctx = GenerationContext::new();
        let mut sent_count = 0u32;
        let mut received_count = 0u32;

        for seed in 0..1000 {
            let mut rng = seeded_rng(seed);
            let artifact = generator.generate(&profile, &ctx, &mut rng).expect("gen");
            let bytes = artifact.to_bytes().expect("serialize");
            let msg: MessageEntry = serde_json::from_slice(&bytes).expect("deserialize");
            match msg.direction {
                MessageDirection::Sent => sent_count += 1,
                MessageDirection::Received => received_count += 1,
            }
        }
        // Sent ~45%, Received ~55%
        assert!(
            sent_count > 350 && sent_count < 550,
            "sent ~45%, got {sent_count}/1000"
        );
        assert!(
            received_count > 450 && received_count < 650,
            "received ~55%, got {received_count}/1000"
        );
    }

    #[test]
    fn test_cluster_vs_gap_timing() {
        let generator = MessagingGenerator::new();
        let profile = UserProfile::default();
        let ctx = GenerationContext::new();
        let mut cluster_count = 0u32;
        let mut gap_count = 0u32;

        for seed in 0..1000 {
            let mut rng = seeded_rng(seed);
            let artifact = generator.generate(&profile, &ctx, &mut rng).expect("gen");
            let bytes = artifact.to_bytes().expect("serialize");
            let msg: MessageEntry = serde_json::from_slice(&bytes).expect("deserialize");
            let offset = (ctx.now - msg.timestamp).num_seconds();
            if offset <= 300 {
                cluster_count += 1;
            } else {
                gap_count += 1;
            }
        }
        // Cluster ~60%, Gap ~40%
        assert!(
            cluster_count > 450 && cluster_count < 750,
            "cluster ~60%, got {cluster_count}/1000"
        );
        assert!(
            gap_count > 250 && gap_count < 550,
            "gap ~40%, got {gap_count}/1000"
        );
    }

    #[test]
    fn test_platforms_are_generic() {
        let generator = MessagingGenerator::new();
        let profile = UserProfile::default();
        let ctx = GenerationContext::new();
        let generic_names = ["quickchat", "buzzmsg", "pingsend", "directline", "grouplink"];

        for seed in 0..200 {
            let mut rng = seeded_rng(seed);
            let artifact = generator.generate(&profile, &ctx, &mut rng).expect("gen");
            let bytes = artifact.to_bytes().expect("serialize");
            let msg: MessageEntry = serde_json::from_slice(&bytes).expect("deserialize");
            assert!(
                generic_names.contains(&msg.platform.as_str()),
                "platform '{}' not generic at seed {seed}",
                msg.platform
            );
        }
    }

    #[test]
    fn test_roundtrip_serialization() {
        let generator = MessagingGenerator::new();
        let profile = UserProfile::default();
        let ctx = GenerationContext::new();
        let mut rng = seeded_rng(99);
        let artifact = generator.generate(&profile, &ctx, &mut rng).expect("gen");
        let bytes = artifact.to_bytes().expect("to_bytes");
        let msg: MessageEntry = serde_json::from_slice(&bytes).expect("deserialize");
        assert!(!msg.platform.is_empty());
        assert!(!msg.contact_name.is_empty());
        assert!(!msg.preview.is_empty());
    }
}
