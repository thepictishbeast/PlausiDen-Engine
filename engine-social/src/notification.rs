//! Social notification artifact generation -- likes, mentions, follows, DMs.
//!
//! Generates plausible social media notification streams. Notification frequency
//! scales with the user's activity level (risk level), and notification types
//! are distributed to mirror real platform patterns.

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

/// A single social media notification.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SocialNotification {
    /// Artifact metadata.
    pub meta: ArtifactMetadata,
    /// Platform the notification originated from (generic names).
    pub platform: String,
    /// Type of notification.
    pub notification_type: NotificationType,
    /// Username that triggered the notification.
    pub from_user: String,
    /// Notification content or summary text.
    pub content: String,
    /// Timestamp of the notification.
    pub timestamp: DateTime<Utc>,
    /// Whether the notification has been read/acknowledged.
    pub read: bool,
}

/// Types of social media notifications.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum NotificationType {
    /// Someone liked your content.
    Like,
    /// Someone commented on your content.
    Comment,
    /// Someone followed you.
    Follow,
    /// Someone mentioned you in a post or comment.
    Mention,
    /// You received a direct message.
    DM,
}

impl Artifact for SocialNotification {
    fn metadata(&self) -> &ArtifactMetadata {
        &self.meta
    }

    fn validate_plausibility(&self) -> Result<()> {
        self.meta.validate_timestamps()?;
        if self.platform.is_empty() {
            return Err(EngineError::ImplausibleArtifact {
                reason: "empty notification platform".into(),
            });
        }
        if self.from_user.is_empty() {
            return Err(EngineError::ImplausibleArtifact {
                reason: "empty from_user in notification".into(),
            });
        }
        if self.content.is_empty() {
            return Err(EngineError::ImplausibleArtifact {
                reason: "empty notification content".into(),
            });
        }
        Ok(())
    }

    fn to_bytes(&self) -> Result<Vec<u8>> {
        serde_json::to_vec(self).map_err(EngineError::Serialization)
    }
}

/// Generic platform names matching the activity module.
const PLATFORMS: &[&str] = &[
    "microblog",
    "photoshare",
    "videotube",
    "linkboard",
    "chatroom",
];

/// Username prefixes for generating from_user handles.
const USER_PREFIXES: &[&str] = &[
    "sunny", "night", "blue", "red", "cool", "happy", "wild", "calm", "swift", "bright", "quiet",
    "bold", "free", "warm", "crisp", "keen",
];

/// Username suffixes for generating from_user handles.
const USER_SUFFIXES: &[&str] = &[
    "fox", "owl", "wave", "leaf", "star", "bird", "wolf", "bear", "moon", "rain", "sky", "tree",
    "wind", "fish", "haze", "glow",
];

/// Like notification content templates.
const LIKE_CONTENT: &[&str] = &[
    "liked your post",
    "liked your photo",
    "liked your comment",
    "liked your reply",
    "favorited your status",
];

/// Comment notification content templates.
const COMMENT_CONTENT: &[&str] = &[
    "commented: \"Great post!\"",
    "commented: \"Interesting perspective\"",
    "commented: \"I agree with this\"",
    "replied to your comment",
    "commented: \"Thanks for sharing\"",
    "commented: \"Love this\"",
];

/// Follow notification content templates.
const FOLLOW_CONTENT: &[&str] = &[
    "started following you",
    "followed you",
    "is now following you",
];

/// Mention notification content templates.
const MENTION_CONTENT: &[&str] = &[
    "mentioned you in a post",
    "tagged you in a comment",
    "mentioned you in a discussion",
    "tagged you in a photo",
    "mentioned you in a thread",
];

/// DM notification content templates.
const DM_CONTENT: &[&str] = &[
    "sent you a message",
    "sent you a photo",
    "sent a voice message",
    "shared a link with you",
    "sent you a message: \"Hey!\"",
    "sent you a message: \"Are you free?\"",
];

/// Generate a random username handle.
fn random_username(rng: &mut (impl RngCore + CryptoRng)) -> Result<String> {
    let prefix = USER_PREFIXES
        .choose(rng)
        .ok_or_else(|| EngineError::InvalidContext("empty username prefix pool".into()))?;
    let suffix = USER_SUFFIXES
        .choose(rng)
        .ok_or_else(|| EngineError::InvalidContext("empty username suffix pool".into()))?;
    let num = Uniform::new_inclusive(1u32, 999).sample(rng);
    Ok(format!("{prefix}_{suffix}{num}"))
}

/// Pick notification content based on type.
fn notification_content(
    notif_type: &NotificationType,
    rng: &mut (impl RngCore + CryptoRng),
) -> Result<String> {
    let pool = match notif_type {
        NotificationType::Like => LIKE_CONTENT,
        NotificationType::Comment => COMMENT_CONTENT,
        NotificationType::Follow => FOLLOW_CONTENT,
        NotificationType::Mention => MENTION_CONTENT,
        NotificationType::DM => DM_CONTENT,
    };
    pool.choose(rng)
        .map(|s| (*s).to_string())
        .ok_or_else(|| EngineError::InvalidContext("empty notification content pool".into()))
}

/// Generates social media notification artifacts.
///
/// Notification frequency scales with the user's activity level (risk level).
/// Higher activity produces more notifications as engagement begets engagement.
pub struct NotificationGenerator;

impl NotificationGenerator {
    /// Create a new notification generator.
    pub fn new() -> Self {
        Self
    }
}

impl Default for NotificationGenerator {
    fn default() -> Self {
        Self::new()
    }
}

impl DataGenerator for NotificationGenerator {
    fn generate(
        &self,
        profile: &UserProfile,
        context: &GenerationContext,
        rng: &mut (impl RngCore + CryptoRng),
    ) -> Result<Box<dyn Artifact>> {
        let platform = PLATFORMS
            .choose(rng)
            .ok_or_else(|| EngineError::InvalidContext("empty platform list".into()))?;

        // Notification type distribution:
        // Like (35%), Comment (25%), Follow (15%), Mention (15%), DM (10%)
        let roll = Uniform::new_inclusive(0u32, 99).sample(rng);
        let notification_type = match roll {
            0..=34 => NotificationType::Like,
            35..=59 => NotificationType::Comment,
            60..=74 => NotificationType::Follow,
            75..=89 => NotificationType::Mention,
            _ => NotificationType::DM,
        };

        let from_user = random_username(rng)?;
        let content = notification_content(&notification_type, rng)?;

        // Timestamp: notification frequency scales with activity level.
        // Higher risk = more active = notifications arrive more frequently (smaller gaps).
        let multiplier = profile.risk_level.rate_multiplier();
        // Base max offset: 6 hours. Scale inversely with activity.
        let max_offset_secs = (21600.0 / multiplier).max(600.0) as i64;
        let offset_secs = Uniform::new_inclusive(0i64, max_offset_secs).sample(rng);
        let timestamp = context.now - Duration::seconds(offset_secs);

        // Read status: 70% read for active users, scaling with activity level.
        let read_roll = Uniform::new_inclusive(0u32, 99).sample(rng);
        let read_threshold = (70.0 * multiplier.sqrt()).min(95.0) as u32;
        let read = read_roll < read_threshold;

        let meta = ArtifactMetadata::new(DataCategory::Social, timestamp, timestamp, 192)?;

        let notification = SocialNotification {
            meta,
            platform: (*platform).to_string(),
            notification_type,
            from_user,
            content,
            timestamp,
            read,
        };
        notification.validate_plausibility()?;
        Ok(Box::new(notification))
    }

    fn category(&self) -> DataCategory {
        DataCategory::Social
    }

    fn forensic_weight(&self) -> u32 {
        45
    }

    fn resource_cost(&self) -> ResourceCost {
        ResourceCost {
            cpu_us: 35,
            disk_bytes: 192,
            network_bytes: 0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use engine_core::entropy::seeded_rng;
    use engine_core::profile::RiskLevel;

    #[test]
    fn test_generate_notification_basic() {
        let generator = NotificationGenerator::new();
        let profile = UserProfile::default();
        let ctx = GenerationContext::new();
        let mut rng = seeded_rng(42);
        let artifact = generator
            .generate(&profile, &ctx, &mut rng)
            .expect("generation failed");
        artifact
            .validate_plausibility()
            .expect("plausibility failed");
    }

    #[test]
    fn test_500_notifications_all_valid() {
        let generator = NotificationGenerator::new();
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
    fn test_notification_type_distribution() {
        let generator = NotificationGenerator::new();
        let profile = UserProfile::default();
        let ctx = GenerationContext::new();
        let mut likes = 0u32;
        let mut comments = 0u32;
        let mut follows = 0u32;
        let mut mentions = 0u32;
        let mut dms = 0u32;

        for seed in 0..1000 {
            let mut rng = seeded_rng(seed);
            let artifact = generator.generate(&profile, &ctx, &mut rng).expect("gen");
            let bytes = artifact.to_bytes().expect("serialize");
            let notif: SocialNotification = serde_json::from_slice(&bytes).expect("deserialize");
            match notif.notification_type {
                NotificationType::Like => likes += 1,
                NotificationType::Comment => comments += 1,
                NotificationType::Follow => follows += 1,
                NotificationType::Mention => mentions += 1,
                NotificationType::DM => dms += 1,
            }
        }
        // Like ~35%, Comment ~25%, Follow ~15%, Mention ~15%, DM ~10%
        assert!(likes > 250 && likes < 450, "likes ~35%, got {likes}/1000");
        assert!(
            comments > 170 && comments < 330,
            "comments ~25%, got {comments}/1000"
        );
        assert!(
            follows > 80 && follows < 250,
            "follows ~15%, got {follows}/1000"
        );
        assert!(
            mentions > 80 && mentions < 250,
            "mentions ~15%, got {mentions}/1000"
        );
        assert!(dms > 40 && dms < 180, "dms ~10%, got {dms}/1000");
    }

    #[test]
    fn test_high_activity_more_frequent_notifications() {
        let generator = NotificationGenerator::new();
        let ctx = GenerationContext::new();

        // Low activity profile.
        let mut low_profile = UserProfile::default();
        low_profile.risk_level = RiskLevel::Low;
        let mut low_offsets = Vec::new();
        for seed in 0..200 {
            let mut rng = seeded_rng(seed);
            let artifact = generator
                .generate(&low_profile, &ctx, &mut rng)
                .expect("gen");
            let bytes = artifact.to_bytes().expect("serialize");
            let notif: SocialNotification = serde_json::from_slice(&bytes).expect("deserialize");
            low_offsets.push((ctx.now - notif.timestamp).num_seconds());
        }

        // High activity profile.
        let mut high_profile = UserProfile::default();
        high_profile.risk_level = RiskLevel::High;
        let mut high_offsets = Vec::new();
        for seed in 0..200 {
            let mut rng = seeded_rng(seed);
            let artifact = generator
                .generate(&high_profile, &ctx, &mut rng)
                .expect("gen");
            let bytes = artifact.to_bytes().expect("serialize");
            let notif: SocialNotification = serde_json::from_slice(&bytes).expect("deserialize");
            high_offsets.push((ctx.now - notif.timestamp).num_seconds());
        }

        let avg_low: f64 = low_offsets.iter().sum::<i64>() as f64 / low_offsets.len() as f64;
        let avg_high: f64 = high_offsets.iter().sum::<i64>() as f64 / high_offsets.len() as f64;

        // High activity should produce more recent (smaller offset) notifications.
        assert!(
            avg_high < avg_low,
            "high activity avg offset ({avg_high:.0}s) should be less than low ({avg_low:.0}s)"
        );
    }

    #[test]
    fn test_platforms_are_generic() {
        let generator = NotificationGenerator::new();
        let profile = UserProfile::default();
        let ctx = GenerationContext::new();
        let generic_names = [
            "microblog",
            "photoshare",
            "videotube",
            "linkboard",
            "chatroom",
        ];

        for seed in 0..200 {
            let mut rng = seeded_rng(seed);
            let artifact = generator.generate(&profile, &ctx, &mut rng).expect("gen");
            let bytes = artifact.to_bytes().expect("serialize");
            let notif: SocialNotification = serde_json::from_slice(&bytes).expect("deserialize");
            assert!(
                generic_names.contains(&notif.platform.as_str()),
                "platform '{}' not generic at seed {seed}",
                notif.platform
            );
        }
    }

    #[test]
    fn test_from_user_not_empty() {
        let generator = NotificationGenerator::new();
        let profile = UserProfile::default();
        let ctx = GenerationContext::new();
        for seed in 0..200 {
            let mut rng = seeded_rng(seed);
            let artifact = generator.generate(&profile, &ctx, &mut rng).expect("gen");
            let bytes = artifact.to_bytes().expect("serialize");
            let notif: SocialNotification = serde_json::from_slice(&bytes).expect("deserialize");
            assert!(
                !notif.from_user.is_empty(),
                "from_user empty at seed {seed}"
            );
        }
    }

    #[test]
    fn test_roundtrip_serialization() {
        let generator = NotificationGenerator::new();
        let profile = UserProfile::default();
        let ctx = GenerationContext::new();
        let mut rng = seeded_rng(77);
        let artifact = generator.generate(&profile, &ctx, &mut rng).expect("gen");
        let bytes = artifact.to_bytes().expect("to_bytes");
        let notif: SocialNotification = serde_json::from_slice(&bytes).expect("deserialize");
        assert!(!notif.platform.is_empty());
        assert!(!notif.from_user.is_empty());
        assert!(!notif.content.is_empty());
    }
}
