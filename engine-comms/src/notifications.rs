//! # Synthetic notification entries.
//!
//! Scaffold implementation of v1.2 §D.3 + v1.1 §4.1. The Prairie
//! Land precedent (*In re Prairie Land Cooperative*, N.D. Iowa 2019)
//! made notification cache data admissible as evidence of
//! conversations that were never contemporaneously observed —
//! messages the user never actually saw but whose preview text
//! persisted in the device's notification cache. This module
//! generates synthetic cache entries with that precedent in mind:
//! realistic app bundle IDs, plausible diurnal arrival timing,
//! believable interaction latency, and a high forensic weight
//! (900) marking them as priority targets for any pollution run.
//!
//! **Status as of 2026-04-17 (task #25 scaffold tick):** types
//! + a single NotificationGenerator that produces well-formed
//! minimal entries with realistic bundle IDs. Full distribution
//! modelling (circadian arrival rates, burst patterns, per-profile
//! app mixes, Signal-specific handling) lands in follow-on ticks.
//!
//! FORENSIC-WEIGHT RATIONALE: notifications sit at weight 900 (versus
//! 100 for browser history, 85 for cookies) because the Prairie
//! Land pathway bypasses the "was the user actually looking at the
//! device?" question that weakens screen-based evidence. A cache
//! entry exists; the court accepts it. That is the pathway this
//! generator exists to pollute.

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

/// A synthetic notification cache entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NotificationEntry {
    pub meta: ArtifactMetadata,
    /// Real app bundle ID — e.g. "org.whispersystems.signal".
    /// Chosen from the per-profile app mix.
    pub app_bundle_id: String,
    /// Display title (typically sender name or app category).
    pub title: String,
    /// Preview body — the text that persists in the cache and is the
    /// Prairie-Land-admissible content.
    pub body: String,
    /// Posted time (when the notification arrived).
    pub posted_at: DateTime<Utc>,
    /// Whether the user "interacted" (expanded, dismissed, tapped).
    /// Forensic examiners cross-reference this against user lock/unlock
    /// events; the realistic interaction latency matters.
    pub interacted: bool,
    /// Latency from post to interaction. None if not interacted.
    pub interaction_latency: Option<Duration>,
    /// Notification category — affects grouping in the cache.
    pub category: NotificationCategory,
}

/// Coarse notification category. Maps roughly to Android / iOS
/// notification channels.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum NotificationCategory {
    /// Signal, WhatsApp, iMessage, Telegram — encrypted messengers.
    MessagingSecure,
    /// SMS / MMS / RCS.
    MessagingSms,
    /// Slack / Teams / Discord.
    MessagingTeam,
    /// Email.
    Email,
    /// Social apps (Instagram / Facebook / TikTok / X).
    Social,
    /// Bank / payment / shopping confirmations.
    Financial,
    /// News / sports / weather — broadcast.
    Broadcast,
    /// System / OS / updates.
    System,
}

/// Known real app bundle IDs. This is the Signal-equivalent mandate
/// from v1.1 §4.1 — generators MUST include Signal specifically
/// because notification cache extraction is a documented FBI forensic
/// pathway.
///
/// Format: `(bundle_id, category)`.
const APP_CATALOG: &[(&str, NotificationCategory)] = &[
    // Secure messaging — Signal must appear
    (
        "org.whispersystems.signal",
        NotificationCategory::MessagingSecure,
    ),
    ("com.whatsapp", NotificationCategory::MessagingSecure),
    (
        "org.telegram.messenger",
        NotificationCategory::MessagingSecure,
    ),
    ("ch.threema.app", NotificationCategory::MessagingSecure),
    // SMS apps
    (
        "com.google.android.apps.messaging",
        NotificationCategory::MessagingSms,
    ),
    (
        "com.samsung.android.messaging",
        NotificationCategory::MessagingSms,
    ),
    // Team chat
    ("com.slack", NotificationCategory::MessagingTeam),
    ("com.microsoft.teams", NotificationCategory::MessagingTeam),
    ("com.discord", NotificationCategory::MessagingTeam),
    // Email
    ("com.google.android.gm", NotificationCategory::Email),
    ("com.microsoft.office.outlook", NotificationCategory::Email),
    ("com.fastmail.app", NotificationCategory::Email),
    // Social
    ("com.instagram.android", NotificationCategory::Social),
    ("com.facebook.katana", NotificationCategory::Social),
    ("com.twitter.android", NotificationCategory::Social),
    ("com.zhiliaoapp.musically", NotificationCategory::Social),
    // Financial
    ("com.venmo", NotificationCategory::Financial),
    ("com.paypal.android", NotificationCategory::Financial),
    // Broadcast
    ("com.weather.Weather", NotificationCategory::Broadcast),
    ("com.nytimes.android", NotificationCategory::Broadcast),
    // System
    ("com.google.android.gms", NotificationCategory::System),
    ("com.android.systemui", NotificationCategory::System),
];

/// Per-category behavioral profile. Consolidates what used to be four
/// separate `match category { ... }` lookups (titles, bodies, median
/// latency, interaction probability) into one struct so a new category
/// or an existing tuning change touches one table, not four.
struct CategoryProfile {
    titles: &'static [&'static str],
    bodies: &'static [&'static str],
    /// Median interaction latency in seconds. The actual sample is drawn
    /// from a log-normal-ish distribution around this median (placeholder
    /// linear-random until follow-on tick lands proper distribution
    /// modelling).
    median_latency_s: u32,
    /// Probability (0-100) that a notification of this category is
    /// interacted with (expanded / dismissed / tapped). The complement
    /// are fire-and-forget notifications the user never looks at.
    interaction_prob_pct: u32,
}

fn profile_for(category: NotificationCategory) -> &'static CategoryProfile {
    use NotificationCategory::*;
    match category {
        MessagingSecure => &MESSAGING_SECURE,
        MessagingSms => &MESSAGING_SMS,
        MessagingTeam => &MESSAGING_TEAM,
        Email => &EMAIL,
        Social => &SOCIAL,
        Financial => &FINANCIAL,
        Broadcast => &BROADCAST,
        System => &SYSTEM,
    }
}

static MESSAGING_SECURE: CategoryProfile = CategoryProfile {
    titles: &["Sam", "Alex", "Jordan", "Robin", "Casey"],
    bodies: &[
        "Sounds good, see you then",
        "Running a bit late",
        "Can we push to tomorrow?",
        "Thanks for the heads up",
    ],
    median_latency_s: 180, // 2-5 min median
    interaction_prob_pct: 70,
};
static MESSAGING_SMS: CategoryProfile = CategoryProfile {
    titles: &["Sam", "Alex", "Jordan", "Robin", "Casey"],
    bodies: &[
        "Your verification code is 482193",
        "Pickup is ready",
        "On my way",
    ],
    median_latency_s: 180,
    interaction_prob_pct: 70,
};
static MESSAGING_TEAM: CategoryProfile = CategoryProfile {
    titles: &["#general", "#eng-ops", "DM: teammate"],
    bodies: &[
        "PR is ready for review",
        "Standup in 5",
        "Deploy window confirmed",
    ],
    median_latency_s: 180,
    interaction_prob_pct: 70,
};
static EMAIL: CategoryProfile = CategoryProfile {
    // REGRESSION-GUARD (2026-04-17): earlier revisions used
    // `newsletter@example.org` and `no-reply@vendor` here, which the
    // leak audit correctly flagged as synthetic-TLD / placeholder
    // fingerprints. Replaced with real, plausible sender labels that
    // match what organic email notifications actually display on
    // Android / iOS (sender domain truncated to name + "via domain").
    titles: &[
        "The Atlantic Weekly",
        "GitHub",
        "Your order has shipped",
        "Medium Daily Digest",
        "LinkedIn",
    ],
    bodies: &[
        "Your weekly digest is here",
        "Invoice attached",
        "Meeting notes for Thursday",
    ],
    median_latency_s: 1800, // 30 min
    interaction_prob_pct: 40,
};
static SOCIAL: CategoryProfile = CategoryProfile {
    titles: &["New follower", "Tagged you", "3 new likes"],
    bodies: &["Someone liked your post", "You have new activity"],
    median_latency_s: 900, // 15 min
    interaction_prob_pct: 30,
};
static FINANCIAL: CategoryProfile = CategoryProfile {
    titles: &["Payment received", "Card charged"],
    bodies: &["$14.27 paid to local shop", "Deposit posted"],
    median_latency_s: 45, // near-immediate
    interaction_prob_pct: 50,
};
static BROADCAST: CategoryProfile = CategoryProfile {
    titles: &["Morning Brief", "Severe weather alert"],
    bodies: &["Top stories from your region", "Wind advisory until 8pm"],
    median_latency_s: 60, // brief glance
    interaction_prob_pct: 20,
};
static SYSTEM: CategoryProfile = CategoryProfile {
    titles: &["System update", "Backup complete"],
    bodies: &[
        "An update is available for your device",
        "Battery saver enabled",
    ],
    median_latency_s: 3600, // rarely interacted
    interaction_prob_pct: 5,
};

/// Generator for synthetic notification cache entries.
pub struct NotificationGenerator;

impl NotificationGenerator {
    pub fn new() -> Self {
        Self
    }

    fn pick_app(
        rng: &mut (impl RngCore + CryptoRng),
    ) -> &'static (&'static str, NotificationCategory) {
        APP_CATALOG.choose(rng).expect("APP_CATALOG non-empty")
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
        _profile: &UserProfile,
        context: &GenerationContext,
        rng: &mut (impl RngCore + CryptoRng),
    ) -> Result<Box<dyn Artifact>> {
        let (bundle_id, category) = Self::pick_app(rng);

        let cat_profile = profile_for(*category);
        let title = cat_profile
            .titles
            .choose(rng)
            .copied()
            .unwrap_or("Notification")
            .to_string();
        let body = cat_profile
            .bodies
            .choose(rng)
            .copied()
            .unwrap_or("")
            .to_string();

        // Posted time: up to 72 h before context.now.
        let posted_offset_s = Uniform::new_inclusive(0i64, 72 * 3600).sample(rng);
        let posted_at = context.now - Duration::seconds(posted_offset_s);

        // Interaction decision driven by per-category probability.
        let roll = Uniform::new(0u32, 100).sample(rng);
        let interacted = roll < cat_profile.interaction_prob_pct;

        let interaction_latency = if interacted {
            let median = cat_profile.median_latency_s as i64;
            // Jitter placeholder: uniform over [median/4, 2*median].
            let low = (median / 4).max(1);
            let high = (median * 2).max(low + 1);
            let secs = Uniform::new_inclusive(low, high).sample(rng);
            Some(Duration::seconds(secs))
        } else {
            None
        };

        let size = (bundle_id.len() + title.len() + body.len()) as u64 + 128;
        let meta = ArtifactMetadata::new(DataCategory::Communications, posted_at, posted_at, size)?;

        let entry = NotificationEntry {
            meta,
            app_bundle_id: bundle_id.to_string(),
            title,
            body,
            posted_at,
            interacted,
            interaction_latency,
            category: *category,
        };

        entry.validate_plausibility()?;
        Ok(Box::new(entry))
    }

    fn category(&self) -> DataCategory {
        DataCategory::Communications
    }

    fn forensic_weight(&self) -> u32 {
        900 // Prairie Land precedent — highest-value forensic target.
    }

    fn resource_cost(&self) -> ResourceCost {
        ResourceCost {
            cpu_us: 40,
            disk_bytes: 384,
            network_bytes: 0,
        }
    }
}

impl Artifact for NotificationEntry {
    fn metadata(&self) -> &ArtifactMetadata {
        &self.meta
    }

    fn validate_plausibility(&self) -> Result<()> {
        self.meta.validate_timestamps()?;

        // SECURITY: bounded field lengths. Real notifications on Android
        // truncate title and body at OS-level limits; emitting strings
        // beyond those is a fingerprint (no real Android app pushes a
        // 4KB notification title — that's a tell that the cache was
        // populated programmatically). Caps here match the roughly-
        // reasonable upper bounds observed across major messaging apps:
        // - title:  ≤ 100 chars  (real cap varies 20-60 across apps;
        //           100 gives headroom for edge cases without allowing
        //           dump-a-message-as-title abuse)
        // - body:   ≤ 500 chars  (Android truncates display at ~200
        //           but the cache retains up to ~1024; 500 is midway)
        // - bundle: ≤ 128 chars  (reverse-DNS style packages are
        //           typically < 80 chars; 128 is a safe ceiling)
        const MAX_TITLE_LEN: usize = 100;
        const MAX_BODY_LEN: usize = 500;
        const MAX_BUNDLE_LEN: usize = 128;

        if self.app_bundle_id.is_empty() {
            return Err(EngineError::ImplausibleArtifact {
                reason: "empty app bundle id".into(),
            });
        }
        if self.app_bundle_id.len() > MAX_BUNDLE_LEN {
            return Err(EngineError::ImplausibleArtifact {
                reason: format!(
                    "app bundle id too long: {} > {}",
                    self.app_bundle_id.len(),
                    MAX_BUNDLE_LEN
                ),
            });
        }
        if self.title.len() > MAX_TITLE_LEN {
            return Err(EngineError::ImplausibleArtifact {
                reason: format!(
                    "notification title too long: {} > {}",
                    self.title.len(),
                    MAX_TITLE_LEN
                ),
            });
        }
        if self.body.len() > MAX_BODY_LEN {
            return Err(EngineError::ImplausibleArtifact {
                reason: format!(
                    "notification body too long: {} > {}",
                    self.body.len(),
                    MAX_BODY_LEN
                ),
            });
        }
        if self.body.is_empty() && self.title.is_empty() {
            return Err(EngineError::ImplausibleArtifact {
                reason: "notification has neither title nor body".into(),
            });
        }
        if let Some(lat) = self.interaction_latency {
            if lat < Duration::zero() {
                return Err(EngineError::ImplausibleArtifact {
                    reason: "negative interaction latency".into(),
                });
            }
        }
        if self.interacted && self.interaction_latency.is_none() {
            return Err(EngineError::ImplausibleArtifact {
                reason: "interacted=true but no latency recorded".into(),
            });
        }
        Ok(())
    }

    fn to_bytes(&self) -> Result<Vec<u8>> {
        serde_json::to_vec(self).map_err(EngineError::Serialization)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use engine_core::entropy::seeded_rng;

    #[test]
    fn catalog_contains_signal() {
        // v1.1 §4.1 mandate: Signal must be in the app mix.
        let has_signal = APP_CATALOG
            .iter()
            .any(|(b, _)| *b == "org.whispersystems.signal");
        assert!(has_signal, "APP_CATALOG missing Signal bundle id");
    }

    #[test]
    fn every_category_has_a_title_pool() {
        // Every category must have at least one title and one body
        // template or generate() will emit empties that validate_
        // plausibility rejects.
        use NotificationCategory::*;
        for c in [
            MessagingSecure,
            MessagingSms,
            MessagingTeam,
            Email,
            Social,
            Financial,
            Broadcast,
            System,
        ] {
            let p = profile_for(c);
            assert!(!p.titles.is_empty(), "no titles for {c:?}");
            assert!(!p.bodies.is_empty(), "no bodies for {c:?}");
        }
    }

    #[test]
    fn forensic_weight_matches_spec() {
        let g = NotificationGenerator::new();
        assert_eq!(g.forensic_weight(), 900);
    }

    #[test]
    fn generates_valid_artifact() {
        let g = NotificationGenerator::new();
        let profile = UserProfile::default();
        let ctx = GenerationContext::new();
        let mut rng = seeded_rng(42);

        let artifact = g.generate(&profile, &ctx, &mut rng).unwrap();
        artifact.validate_plausibility().unwrap();
        let bytes = artifact.to_bytes().unwrap();
        let entry: NotificationEntry = serde_json::from_slice(&bytes).unwrap();

        assert!(!entry.app_bundle_id.is_empty());
        assert!(!entry.title.is_empty() || !entry.body.is_empty());
        assert!(entry.posted_at <= Utc::now() + Duration::seconds(1));
    }

    #[test]
    fn interaction_invariant_holds_across_many_seeds() {
        // Pin the invariant: interacted XOR latency-absent.
        let g = NotificationGenerator::new();
        let profile = UserProfile::default();
        let ctx = GenerationContext::new();

        for seed in 0..50u64 {
            let mut rng = seeded_rng(seed);
            let artifact = g.generate(&profile, &ctx, &mut rng).unwrap();
            let bytes = artifact.to_bytes().unwrap();
            let entry: NotificationEntry = serde_json::from_slice(&bytes).unwrap();
            assert_eq!(
                entry.interacted,
                entry.interaction_latency.is_some(),
                "seed {seed}: interacted/latency desync",
            );
        }
    }

    #[test]
    fn rejects_oversize_title() {
        let mut e = NotificationEntry {
            meta: ArtifactMetadata::new(
                DataCategory::Communications,
                Utc::now() - Duration::minutes(5),
                Utc::now() - Duration::minutes(5),
                256,
            )
            .unwrap(),
            app_bundle_id: "org.whispersystems.signal".into(),
            title: "x".repeat(101),
            body: "ok".into(),
            posted_at: Utc::now() - Duration::minutes(5),
            interacted: false,
            interaction_latency: None,
            category: NotificationCategory::MessagingSecure,
        };
        assert!(e.validate_plausibility().is_err());
        // At the cap: should pass.
        e.title = "x".repeat(100);
        assert!(e.validate_plausibility().is_ok());
    }

    #[test]
    fn rejects_oversize_body() {
        let e = NotificationEntry {
            meta: ArtifactMetadata::new(
                DataCategory::Communications,
                Utc::now() - Duration::minutes(5),
                Utc::now() - Duration::minutes(5),
                256,
            )
            .unwrap(),
            app_bundle_id: "com.whatsapp".into(),
            title: "ok".into(),
            body: "x".repeat(501),
            posted_at: Utc::now() - Duration::minutes(5),
            interacted: false,
            interaction_latency: None,
            category: NotificationCategory::MessagingSecure,
        };
        assert!(e.validate_plausibility().is_err());
    }

    #[test]
    fn rejects_oversize_bundle() {
        let e = NotificationEntry {
            meta: ArtifactMetadata::new(
                DataCategory::Communications,
                Utc::now() - Duration::minutes(5),
                Utc::now() - Duration::minutes(5),
                256,
            )
            .unwrap(),
            app_bundle_id: "x".repeat(129),
            title: "ok".into(),
            body: "ok".into(),
            posted_at: Utc::now() - Duration::minutes(5),
            interacted: false,
            interaction_latency: None,
            category: NotificationCategory::System,
        };
        assert!(e.validate_plausibility().is_err());
    }

    #[test]
    fn bundle_ids_are_real_syntax() {
        // Package IDs are reverse-DNS in Android convention.
        // This is a weak check — only asserts we don't emit obvious
        // placeholder strings (which would fingerprint).
        for (b, _) in APP_CATALOG {
            assert!(b.contains('.'), "bundle id {b} not reverse-DNS");
            assert!(!b.starts_with("com.example"), "synthetic bundle id: {b}");
            assert!(!b.contains("synthetic"), "marker in bundle id: {b}");
        }
    }
}

#[cfg(test)]
mod proptests {
    use super::*;
    use engine_core::entropy::seeded_rng;
    use proptest::prelude::*;

    proptest! {
        /// Pin the core invariant: for any seed, the emitted artifact
        /// must pass its own validate_plausibility check. If this ever
        /// fails, the generator is emitting things it would immediately
        /// reject — a hard regression.
        #[test]
        fn generated_artifact_always_validates(seed in 0u64..u64::MAX) {
            let g = NotificationGenerator::new();
            let profile = UserProfile::default();
            let ctx = GenerationContext::new();
            let mut rng = seeded_rng(seed);
            let artifact = g.generate(&profile, &ctx, &mut rng).unwrap();
            artifact.validate_plausibility().unwrap();
        }

        /// Bundle IDs emitted at runtime are always in APP_CATALOG.
        /// The generator never invents a bundle ID — if it does, it's
        /// a synthetic fingerprint we didn't consent to.
        #[test]
        fn generated_bundle_in_catalog(seed in 0u64..u64::MAX) {
            let g = NotificationGenerator::new();
            let profile = UserProfile::default();
            let ctx = GenerationContext::new();
            let mut rng = seeded_rng(seed);
            let artifact = g.generate(&profile, &ctx, &mut rng).unwrap();
            let bytes = artifact.to_bytes().unwrap();
            let entry: NotificationEntry = serde_json::from_slice(&bytes).unwrap();
            let known: Vec<&'static str> =
                APP_CATALOG.iter().map(|(b, _)| *b).collect();
            prop_assert!(
                known.contains(&entry.app_bundle_id.as_str()),
                "emitted bundle id not in catalog: {}",
                entry.app_bundle_id,
            );
        }

        /// Posted time is never in the future (allow 1s slack for clock
        /// skew between generation and assertion).
        #[test]
        fn posted_time_is_in_past(seed in 0u64..u64::MAX) {
            let g = NotificationGenerator::new();
            let profile = UserProfile::default();
            let ctx = GenerationContext::new();
            let mut rng = seeded_rng(seed);
            let artifact = g.generate(&profile, &ctx, &mut rng).unwrap();
            let bytes = artifact.to_bytes().unwrap();
            let entry: NotificationEntry = serde_json::from_slice(&bytes).unwrap();
            prop_assert!(entry.posted_at <= Utc::now() + Duration::seconds(1));
        }
    }
}
