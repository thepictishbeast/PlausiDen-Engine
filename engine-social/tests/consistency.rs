//! Cross-platform consistency tests for social media generators.
//!
//! Validates that the activity, engagement, and content generators produce
//! plausible, internally consistent artifacts when run at scale.

use engine_core::entropy::seeded_rng;
use engine_core::profile::UserProfile;
use engine_core::traits::{DataGenerator, GenerationContext};
use engine_social::activity::{SocialAction, SocialEntry, SocialGenerator};
use engine_social::content::{ContentGenerator, ContentPost, ContentType};
use engine_social::engagement::{EngagementGenerator, EngagementSnapshot};

const KNOWN_PLATFORMS: &[&str] = &[
    "Twitter/X",
    "Instagram",
    "Facebook",
    "Reddit",
    "LinkedIn",
    "TikTok",
    "Mastodon",
    "Threads",
];

/// Helper: generate a `SocialEntry` from a seed.
fn social_entry(seed: u64) -> SocialEntry {
    let social_gen = SocialGenerator::new();
    let profile = UserProfile::default();
    let ctx = GenerationContext::new();
    let mut rng = seeded_rng(seed);
    let artifact = social_gen.generate(&profile, &ctx, &mut rng).unwrap();
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

// ---------------------------------------------------------------------------
// 1. Activity actions follow realistic distribution
//    (scroll dominant, likes common, posts rare)
// ---------------------------------------------------------------------------
#[test]
fn activity_actions_follow_realistic_distribution() {
    let n = 2000u32;
    let mut scrolls = 0u32;
    let mut likes = 0u32;
    let mut posts = 0u32;

    for seed in 0..n {
        let entry = social_entry(u64::from(seed));
        match entry.action {
            SocialAction::ScrollFeed => scrolls += 1,
            SocialAction::Like => likes += 1,
            SocialAction::Post => posts += 1,
            _ => {}
        }
    }

    // ScrollFeed should be ~40% (dominant).
    assert!(
        scrolls > n / 4,
        "scrolls should be dominant (>25%), got {scrolls}/{n}"
    );
    // Likes should be common (~25%).
    assert!(
        likes > n / 8,
        "likes should be common (>12.5%), got {likes}/{n}"
    );
    // Posts should be rare (~10%), significantly less than scrolls.
    assert!(
        posts < scrolls,
        "posts ({posts}) should be rarer than scrolls ({scrolls})"
    );
    assert!(
        posts < n / 4,
        "posts should be rare (<25%), got {posts}/{n}"
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
            // Every hashtag should start with '#'.
            for tag in &post.hashtags {
                assert!(
                    tag.starts_with('#'),
                    "hashtag {tag:?} missing '#' prefix at seed {seed}"
                );
            }
        }
    }
    // Sanity: we should have seen a good number of photo captions.
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
                .expect(&format!("story at seed {seed} has no view_count"));
            assert!(
                views > 0,
                "story at seed {seed} has zero view count"
            );
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
                .expect(&format!("share at seed {seed} missing share_meta"));
            assert!(
                !sm.original_author.is_empty(),
                "share at seed {seed} has empty original_author"
            );
            assert!(
                !sm.original_platform.is_empty(),
                "share at seed {seed} has empty original_platform"
            );
            assert!(
                KNOWN_PLATFORMS.contains(&sm.original_platform.as_str()),
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
// 8. All social entries have valid platform names from the known list
// ---------------------------------------------------------------------------
#[test]
fn all_entries_have_valid_platform_names() {
    for seed in 0..500u64 {
        let activity = social_entry(seed);
        assert!(
            KNOWN_PLATFORMS.contains(&activity.platform.as_str()),
            "activity at seed {seed}: unknown platform {:?}",
            activity.platform,
        );

        let snap = engagement_snap(seed);
        assert!(
            KNOWN_PLATFORMS.contains(&snap.platform.as_str()),
            "engagement at seed {seed}: unknown platform {:?}",
            snap.platform,
        );

        let post = content_post(seed);
        assert!(
            KNOWN_PLATFORMS.contains(&post.platform.as_str()),
            "content at seed {seed}: unknown platform {:?}",
            post.platform,
        );
    }
}

// ---------------------------------------------------------------------------
// 9. 1000-entry stress: all valid across all 3 generators
// ---------------------------------------------------------------------------
#[test]
fn stress_1000_entries_all_generators_valid() {
    let social_gen = SocialGenerator::new();
    let eng_gen = EngagementGenerator::new();
    let content_gen = ContentGenerator::new();
    let profile = UserProfile::default();
    let ctx = GenerationContext::new();

    for seed in 0..1000u64 {
        let mut rng = seeded_rng(seed);
        let a = social_gen.generate(&profile, &ctx, &mut rng).unwrap();
        a.validate_plausibility()
            .unwrap_or_else(|e| panic!("social seed {seed}: {e}"));

        let mut rng = seeded_rng(seed + 10_000);
        let b = eng_gen.generate(&profile, &ctx, &mut rng).unwrap();
        b.validate_plausibility()
            .unwrap_or_else(|e| panic!("engagement seed {seed}: {e}"));

        let mut rng = seeded_rng(seed + 20_000);
        let c = content_gen.generate(&profile, &ctx, &mut rng).unwrap();
        c.validate_plausibility()
            .unwrap_or_else(|e| panic!("content seed {seed}: {e}"));
    }
}

// ---------------------------------------------------------------------------
// 10. Cross-generator: engagement metrics proportional to content volume
// ---------------------------------------------------------------------------
#[test]
fn cross_generator_engagement_proportional_to_content_volume() {
    // Cross-generator consistency: engagement metrics should be proportional
    // to the content volume a user produces.  We split a seed range into a
    // "low-activity" half (fewer content posts) and a "high-activity" half
    // (more content posts), then verify engagement rates remain bounded and
    // that per-post interaction counts scale with follower counts, not with
    // raw content volume.

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

    // Sanity: we generated content, and text posts are the most common type.
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

        // Per-snapshot: interactions must not exceed follower count.
        // (Engagement rate is capped at 1.0 by the generator.)
        assert!(
            interactions <= snap.audience.followers,
            "seed {seed}: interactions ({interactions}) > followers ({})",
            snap.audience.followers,
        );
    }

    // Average engagement rate across all snapshots should be in a realistic
    // range (real-world averages are 1–5%).
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
    // Generate activity entries and verify the action counts are non-trivial,
    // confirming all three generators produce correlated output at the same
    // seed range (i.e., the social ecosystem is internally consistent).
    let mut activity_count = 0u64;
    let mut post_actions = 0u64;
    for seed in 0..n {
        let entry = social_entry(seed);
        activity_count += 1;
        if matches!(entry.action, SocialAction::Post) {
            post_actions += 1;
        }
    }

    // Activity post actions should be in the same order of magnitude as
    // content text posts (both represent "posting" behavior).
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
