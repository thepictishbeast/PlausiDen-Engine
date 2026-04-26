//! Cross-platform consistency tests for social media generators.
//!
//! Validates that the activity, engagement, content, messaging, and notification
//! generators produce plausible, internally consistent artifacts when run at scale.

use engine_core::entropy::seeded_rng;
use engine_core::profile::UserProfile;
use engine_core::traits::{DataGenerator, GenerationContext};
use engine_social::activity::{ActionType, ActivityGenerator, SocialActivity};
use engine_social::content::{ContentGenerator, ContentPost, ContentType};
use engine_social::engagement::{EngagementGenerator, EngagementSnapshot};
use engine_social::messaging::{MessageDirection, MessageEntry, MessagingGenerator};
use engine_social::notification::{NotificationGenerator, SocialNotification};

/// Generic platform names used by the activity/notification generators.
const ACTIVITY_PLATFORMS: &[&str] = &[
    "microblog",
    "photoshare",
    "videotube",
    "linkboard",
    "chatroom",
];

/// Platform names used by legacy content/engagement generators.
const CONTENT_PLATFORMS: &[&str] = &[
    "Twitter/X",
    "Instagram",
    "Facebook",
    "Reddit",
    "LinkedIn",
    "TikTok",
    "Mastodon",
    "Threads",
];

/// Messaging platform names.
const MESSAGING_PLATFORMS: &[&str] = &[
    "quickchat",
    "buzzmsg",
    "pingsend",
    "directline",
    "grouplink",
];

/// Helper: generate a `SocialActivity` from a seed.
fn social_activity(seed: u64) -> SocialActivity {
    let activity_gen = ActivityGenerator::new();
    let profile = UserProfile::default();
    let ctx = GenerationContext::new();
    let mut rng = seeded_rng(seed);
    let artifact = activity_gen.generate(&profile, &ctx, &mut rng).unwrap();
    let bytes = artifact.to_bytes().unwrap();
    serde_json::from_slice(&bytes).unwrap()
}

/// Helper: generate an `EngagementSnapshot` from a seed.
fn engagement_snap(seed: u64) -> EngagementSnapshot {
    let eng_gen = EngagementGenerator::new();
    let profile = UserProfile::default();
    let ctx = GenerationContext::new();
    let mut rng = seeded_rng(seed);
    let artifact = eng_gen.generate(&profile, &ctx, &mut rng).unwrap();
    let bytes = artifact.to_bytes().unwrap();
    serde_json::from_slice(&bytes).unwrap()
}

/// Helper: generate a `ContentPost` from a seed.
fn content_post(seed: u64) -> ContentPost {
    let content_gen = ContentGenerator::new();
    let profile = UserProfile::default();
    let ctx = GenerationContext::new();
    let mut rng = seeded_rng(seed);
    let artifact = content_gen.generate(&profile, &ctx, &mut rng).unwrap();
    let bytes = artifact.to_bytes().unwrap();
    serde_json::from_slice(&bytes).unwrap()
}

/// Helper: generate a `MessageEntry` from a seed.
fn message_entry(seed: u64) -> MessageEntry {
    let msg_gen = MessagingGenerator::new();
    let profile = UserProfile::default();
    let ctx = GenerationContext::new();
    let mut rng = seeded_rng(seed);
    let artifact = msg_gen.generate(&profile, &ctx, &mut rng).unwrap();
    let bytes = artifact.to_bytes().unwrap();
    serde_json::from_slice(&bytes).unwrap()
}

/// Helper: generate a `SocialNotification` from a seed.
fn notification_entry(seed: u64) -> SocialNotification {
    let notif_gen = NotificationGenerator::new();
    let profile = UserProfile::default();
    let ctx = GenerationContext::new();
    let mut rng = seeded_rng(seed);
    let artifact = notif_gen.generate(&profile, &ctx, &mut rng).unwrap();
    let bytes = artifact.to_bytes().unwrap();
    serde_json::from_slice(&bytes).unwrap()
}

// ---------------------------------------------------------------------------
// 1. Activity actions follow realistic distribution
// ---------------------------------------------------------------------------
#[test]
fn activity_actions_follow_realistic_distribution() {
    let n = 2000u32;
    let mut likes = 0u32;
    let mut posts = 0u32;
    let mut comments = 0u32;

    for seed in 0..n {
        let entry = social_activity(u64::from(seed));
        match entry.action_type {
            ActionType::Like => likes += 1,
            ActionType::Post => posts += 1,
            ActionType::Comment => comments += 1,
            _ => {}
        }
    }

    // Likes should be dominant (~35%).
    assert!(
        likes > n / 4,
        "likes should be dominant (>25%), got {likes}/{n}"
    );
    // Comments should be common (~20%).
    assert!(
        comments > n / 8,
        "comments should be common (>12.5%), got {comments}/{n}"
    );
    // Posts should be rarer than likes.
    assert!(
        posts < likes,
        "posts ({posts}) should be rarer than likes ({likes})"
    );
}

// ---------------------------------------------------------------------------
// 2. Content posts never exceed 280 characters
// ---------------------------------------------------------------------------
#[test]
fn content_posts_never_exceed_280_characters() {
    for seed in 0..1000u64 {
        let post = content_post(seed);
        assert!(
            post.body.len() <= 280,
            "post body {} chars at seed {seed}, content_type {:?}",
            post.body.len(),
            post.content_type,
        );
    }
}

// ---------------------------------------------------------------------------
// 3. Engagement followers/following ratio is realistic (< 50:1)
// ---------------------------------------------------------------------------
#[test]
fn engagement_follower_following_ratio_realistic() {
    for seed in 0..1000u64 {
        let snap = engagement_snap(seed);
        if snap.audience.followers > 0 {
            let ratio = snap.audience.following as f64 / snap.audience.followers as f64;
            assert!(
                ratio < 50.0,
                "following/followers ratio {ratio:.1} >= 50 at seed {seed} \
                 (following={}, followers={})",
                snap.audience.following,
                snap.audience.followers,
            );
        }
    }
}

// ---------------------------------------------------------------------------
// 4. Engagement rate is always between 0 and 1
// ---------------------------------------------------------------------------
#[test]
fn engagement_rate_always_between_zero_and_one() {
    for seed in 0..1000u64 {
        let snap = engagement_snap(seed);
        assert!(
            (0.0..=1.0).contains(&snap.engagement_rate),
            "engagement rate {:.6} out of [0.0, 1.0] at seed {seed}",
            snap.engagement_rate,
        );
    }
}

// ---------------------------------------------------------------------------
// 5. Photo captions have hashtags (at least 1)
// ---------------------------------------------------------------------------
#[test]
fn photo_captions_have_at_least_one_hashtag() {
    let mut photo_count = 0u32;
    for seed in 0..2000u64 {
        let post = content_post(seed);
        if post.content_type == ContentType::PhotoCaption {
            photo_count += 1;
            assert!(
                !post.hashtags.is_empty(),
                "photo caption at seed {seed} has no hashtags"
            );
            for tag in &post.hashtags {
                assert!(
                    tag.starts_with('#'),
                    "hashtag {tag:?} missing '#' prefix at seed {seed}"
                );
            }
        }
    }
    assert!(
        photo_count > 400,
        "expected >400 photo captions in 2000 samples, got {photo_count}"
    );
}

// ---------------------------------------------------------------------------
// 6. Stories have view counts > 0
// ---------------------------------------------------------------------------
#[test]
fn stories_have_positive_view_counts() {
    let mut story_count = 0u32;
    for seed in 0..2000u64 {
        let post = content_post(seed);
        if post.content_type == ContentType::StoryReel {
            story_count += 1;
            let views = post
                .view_count
                .unwrap_or_else(|| panic!("story at seed {seed} has no view_count"));
            assert!(views > 0, "story at seed {seed} has zero view count");
        }
    }
    assert!(
        story_count > 300,
        "expected >300 stories in 2000 samples, got {story_count}"
    );
}

// ---------------------------------------------------------------------------
// 7. Share posts have original author metadata
// ---------------------------------------------------------------------------
#[test]
fn share_posts_have_original_author_metadata() {
    let mut share_count = 0u32;
    for seed in 0..2000u64 {
        let post = content_post(seed);
        if post.content_type == ContentType::ShareRepost {
            share_count += 1;
            let sm = post
                .share_meta
                .as_ref()
                .unwrap_or_else(|| panic!("share at seed {seed} missing share_meta"));
            assert!(
                !sm.original_author.is_empty(),
                "share at seed {seed} has empty original_author"
            );
            assert!(
                !sm.original_platform.is_empty(),
                "share at seed {seed} has empty original_platform"
            );
            assert!(
                CONTENT_PLATFORMS.contains(&sm.original_platform.as_str()),
                "share at seed {seed} has unknown original_platform {:?}",
                sm.original_platform,
            );
        }
    }
    assert!(
        share_count > 100,
        "expected >100 shares in 2000 samples, got {share_count}"
    );
}

// ---------------------------------------------------------------------------
// 8. All generators produce valid platform names from their known lists
// ---------------------------------------------------------------------------
#[test]
fn all_entries_have_valid_platform_names() {
    for seed in 0..500u64 {
        let activity = social_activity(seed);
        assert!(
            ACTIVITY_PLATFORMS.contains(&activity.platform.as_str()),
            "activity at seed {seed}: unknown platform {:?}",
            activity.platform,
        );

        let snap = engagement_snap(seed);
        assert!(
            CONTENT_PLATFORMS.contains(&snap.platform.as_str()),
            "engagement at seed {seed}: unknown platform {:?}",
            snap.platform,
        );

        let post = content_post(seed);
        assert!(
            CONTENT_PLATFORMS.contains(&post.platform.as_str()),
            "content at seed {seed}: unknown platform {:?}",
            post.platform,
        );

        let msg = message_entry(seed);
        assert!(
            MESSAGING_PLATFORMS.contains(&msg.platform.as_str()),
            "messaging at seed {seed}: unknown platform {:?}",
            msg.platform,
        );

        let notif = notification_entry(seed);
        assert!(
            ACTIVITY_PLATFORMS.contains(&notif.platform.as_str()),
            "notification at seed {seed}: unknown platform {:?}",
            notif.platform,
        );
    }
}

// ---------------------------------------------------------------------------
// 9. 1000-entry stress: all 5 generators valid
// ---------------------------------------------------------------------------
#[test]
fn stress_1000_entries_all_generators_valid() {
    let activity_gen = ActivityGenerator::new();
    let eng_gen = EngagementGenerator::new();
    let content_gen = ContentGenerator::new();
    let msg_gen = MessagingGenerator::new();
    let notif_gen = NotificationGenerator::new();
    let profile = UserProfile::default();
    let ctx = GenerationContext::new();

    for seed in 0..1000u64 {
        let mut rng = seeded_rng(seed);
        let a = activity_gen.generate(&profile, &ctx, &mut rng).unwrap();
        a.validate_plausibility()
            .unwrap_or_else(|e| panic!("activity seed {seed}: {e}"));

        let mut rng = seeded_rng(seed + 10_000);
        let b = eng_gen.generate(&profile, &ctx, &mut rng).unwrap();
        b.validate_plausibility()
            .unwrap_or_else(|e| panic!("engagement seed {seed}: {e}"));

        let mut rng = seeded_rng(seed + 20_000);
        let c = content_gen.generate(&profile, &ctx, &mut rng).unwrap();
        c.validate_plausibility()
            .unwrap_or_else(|e| panic!("content seed {seed}: {e}"));

        let mut rng = seeded_rng(seed + 30_000);
        let d = msg_gen.generate(&profile, &ctx, &mut rng).unwrap();
        d.validate_plausibility()
            .unwrap_or_else(|e| panic!("messaging seed {seed}: {e}"));

        let mut rng = seeded_rng(seed + 40_000);
        let e_artifact = notif_gen.generate(&profile, &ctx, &mut rng).unwrap();
        e_artifact
            .validate_plausibility()
            .unwrap_or_else(|e| panic!("notification seed {seed}: {e}"));
    }
}

// ---------------------------------------------------------------------------
// 10. Cross-generator: engagement metrics proportional to content volume
// ---------------------------------------------------------------------------
#[test]
fn cross_generator_engagement_proportional_to_content_volume() {
    let n = 500u64;

    // --- Content volume ---
    let mut total_content_items = 0u64;
    let mut text_post_count = 0u64;
    for seed in 0..n {
        let post = content_post(seed);
        total_content_items += 1;
        if post.content_type == ContentType::TextPost {
            text_post_count += 1;
        }
    }

    assert!(total_content_items == n);
    assert!(
        text_post_count > n / 4,
        "expected significant text post volume, got {text_post_count}/{n}"
    );

    // --- Engagement snapshots ---
    let mut total_interactions = 0u64;
    let mut total_followers = 0u64;
    let mut snapshot_count = 0u64;
    for seed in 0..n {
        let snap = engagement_snap(seed);
        let interactions = snap.post_engagement.likes
            + snap.post_engagement.retweets
            + snap.post_engagement.replies;
        total_interactions += interactions;
        total_followers += snap.audience.followers;
        snapshot_count += 1;

        assert!(
            interactions <= snap.audience.followers,
            "seed {seed}: interactions ({interactions}) > followers ({})",
            snap.audience.followers,
        );
    }

    let avg_interactions = total_interactions as f64 / snapshot_count as f64;
    let avg_followers = total_followers as f64 / snapshot_count as f64;
    let overall_rate = avg_interactions / avg_followers;

    assert!(
        overall_rate < 0.15,
        "average engagement rate {overall_rate:.4} is implausibly high (>15%)"
    );
    assert!(
        overall_rate > 0.001,
        "average engagement rate {overall_rate:.6} is implausibly low (<0.1%)"
    );

    // --- Activity volume ---
    let mut activity_count = 0u64;
    let mut post_actions = 0u64;
    for seed in 0..n {
        let entry = social_activity(seed);
        activity_count += 1;
        if matches!(entry.action_type, ActionType::Post) {
            post_actions += 1;
        }
    }

    assert!(
        post_actions > 0 && text_post_count > 0,
        "both generators should produce posts"
    );
    let ratio = text_post_count as f64 / post_actions as f64;
    assert!(
        (0.1..=10.0).contains(&ratio),
        "content text posts ({text_post_count}) and activity post actions \
         ({post_actions}) should be within an order of magnitude, ratio={ratio:.2}"
    );

    assert_eq!(activity_count, n, "all activity seeds produced output");
}

// ---------------------------------------------------------------------------
// 11. Messaging: sent messages are always read
// ---------------------------------------------------------------------------
#[test]
fn messaging_sent_messages_always_read() {
    for seed in 0..500u64 {
        let msg = message_entry(seed);
        if msg.direction == MessageDirection::Sent {
            assert!(msg.read, "sent message at seed {seed} is unread");
        }
    }
}

// ---------------------------------------------------------------------------
// 12. Notifications: all have non-empty from_user and content
// ---------------------------------------------------------------------------
#[test]
fn notification_fields_non_empty() {
    for seed in 0..500u64 {
        let notif = notification_entry(seed);
        assert!(
            !notif.from_user.is_empty(),
            "notification at seed {seed} has empty from_user"
        );
        assert!(
            !notif.content.is_empty(),
            "notification at seed {seed} has empty content"
        );
    }
}
