//! Fuzz-style input validation tests.
//!
//! Throws garbage, edge-case, and extreme values at every public API to find
//! crashes. Every parser, constructor, and generator that accepts external input
//! gets hammered with adversarial inputs. No test here verifies "correctness" --
//! the only assertion is "does not crash."

use engine_browser::bookmarks::{BookmarkEntry, BookmarkGenerator};
use engine_browser::cookies::{CookieEntry, CookieGenerator};
use engine_browser::downloads::{DownloadEntry, DownloadGenerator};
use engine_browser::history::{HistoryEntry, HistoryGenerator};
use engine_browser::searches::{SearchEntry, SearchGenerator};
use engine_core::entropy::seeded_rng;
use engine_core::profile::{
    ActivitySchedule, BrowserType, DemographicProfile, DeviceProfile, InterestCategory, Locale,
    OccupationCategory, OsFamily, RiskLevel, UserProfile, UserProfileBuilder,
};
use engine_core::schedule::OrganicScheduler;
use engine_core::traits::{
    ArtifactMetadata, DataCategory, DataGenerator, GenerationContext,
};
use chrono::{Duration, Utc};
use proptest::prelude::*;

// ============================================================================
// Helpers
// ============================================================================

/// Build a profile with the given interests and risk level.
fn profile_with(interests: Vec<InterestCategory>, risk: RiskLevel) -> UserProfile {
    UserProfileBuilder::new()
        .interests(interests)
        .risk_level(risk)
        .build()
}

/// Minimal profile -- every field at its default.
fn minimal_profile() -> UserProfile {
    UserProfileBuilder::new().build()
}

// ============================================================================
// 1. Every generator with empty interest lists
// ============================================================================

#[test]
fn fuzz_history_empty_interests() {
    let profile = profile_with(vec![], RiskLevel::Medium);
    let ctx = GenerationContext::new();
    let mut rng = seeded_rng(1);
    let generator = HistoryGenerator::new();

    for _ in 0..100 {
        let result = generator.generate(&profile, &ctx, &mut rng);
        // Must not panic. May return Ok or Err, both are acceptable.
        let _ = result;
    }
}

#[test]
fn fuzz_cookie_empty_interests() {
    let profile = profile_with(vec![], RiskLevel::Medium);
    let ctx = GenerationContext::new();
    let mut rng = seeded_rng(2);
    let generator = CookieGenerator::new();

    for _ in 0..100 {
        let _ = generator.generate(&profile, &ctx, &mut rng);
    }
}

#[test]
fn fuzz_search_empty_interests() {
    let profile = profile_with(vec![], RiskLevel::Medium);
    let ctx = GenerationContext::new();
    let mut rng = seeded_rng(3);
    let generator = SearchGenerator::new();

    for _ in 0..100 {
        let _ = generator.generate(&profile, &ctx, &mut rng);
    }
}

// ============================================================================
// 2. Every generator with maximum risk level
// ============================================================================

#[test]
fn fuzz_history_maximum_risk() {
    let profile = profile_with(
        vec![InterestCategory::News, InterestCategory::Technology],
        RiskLevel::Maximum,
    );
    let ctx = GenerationContext::new();
    let mut rng = seeded_rng(10);
    let generator = HistoryGenerator::new();

    for _ in 0..200 {
        let result = generator.generate(&profile, &ctx, &mut rng);
        assert!(result.is_ok(), "maximum risk must not crash history generator");
    }
}

#[test]
fn fuzz_cookie_maximum_risk() {
    let profile = profile_with(
        vec![InterestCategory::Shopping],
        RiskLevel::Maximum,
    );
    let ctx = GenerationContext::new();
    let mut rng = seeded_rng(11);
    let generator = CookieGenerator::new();

    for _ in 0..200 {
        let result = generator.generate(&profile, &ctx, &mut rng);
        assert!(result.is_ok(), "maximum risk must not crash cookie generator");
    }
}

#[test]
fn fuzz_search_maximum_risk() {
    let profile = profile_with(
        vec![InterestCategory::Finance, InterestCategory::Health],
        RiskLevel::Maximum,
    );
    let ctx = GenerationContext::new();
    let mut rng = seeded_rng(12);
    let generator = SearchGenerator::new();

    for _ in 0..200 {
        let result = generator.generate(&profile, &ctx, &mut rng);
        assert!(result.is_ok(), "maximum risk must not crash search generator");
    }
}

// ============================================================================
// 3. Extreme activity schedules (wake=0, sleep=24 mapped to 23)
// ============================================================================

#[test]
fn fuzz_history_extreme_schedule_full_day() {
    let mut profile = UserProfile::default();
    profile.activity_schedule = ActivitySchedule {
        wake_hour: 0,
        sleep_hour: 23,
        active_days: vec![0, 1, 2, 3, 4, 5, 6],
        timezone_offset_hours: 0,
    };
    let ctx = GenerationContext::new();
    let mut rng = seeded_rng(20);
    let generator = HistoryGenerator::new();

    for _ in 0..100 {
        let _ = generator.generate(&profile, &ctx, &mut rng);
    }
}

#[test]
fn fuzz_cookie_extreme_schedule_full_day() {
    let mut profile = UserProfile::default();
    profile.activity_schedule = ActivitySchedule {
        wake_hour: 0,
        sleep_hour: 23,
        active_days: vec![0, 1, 2, 3, 4, 5, 6],
        timezone_offset_hours: 0,
    };
    let ctx = GenerationContext::new();
    let mut rng = seeded_rng(21);
    let generator = CookieGenerator::new();

    for _ in 0..100 {
        let _ = generator.generate(&profile, &ctx, &mut rng);
    }
}

#[test]
fn fuzz_search_extreme_schedule_full_day() {
    let mut profile = UserProfile::default();
    profile.activity_schedule = ActivitySchedule {
        wake_hour: 0,
        sleep_hour: 23,
        active_days: vec![0, 1, 2, 3, 4, 5, 6],
        timezone_offset_hours: 0,
    };
    let ctx = GenerationContext::new();
    let mut rng = seeded_rng(22);
    let generator = SearchGenerator::new();

    for _ in 0..100 {
        let _ = generator.generate(&profile, &ctx, &mut rng);
    }
}

// ============================================================================
// 4. Minimal profile (all defaults)
// ============================================================================

#[test]
fn fuzz_history_minimal_profile() {
    let profile = minimal_profile();
    let ctx = GenerationContext::new();
    let mut rng = seeded_rng(30);
    let generator = HistoryGenerator::new();

    for _ in 0..100 {
        let result = generator.generate(&profile, &ctx, &mut rng);
        assert!(result.is_ok(), "minimal profile must not crash history generator");
    }
}

#[test]
fn fuzz_cookie_minimal_profile() {
    let profile = minimal_profile();
    let ctx = GenerationContext::new();
    let mut rng = seeded_rng(31);
    let generator = CookieGenerator::new();

    for _ in 0..100 {
        let result = generator.generate(&profile, &ctx, &mut rng);
        assert!(result.is_ok(), "minimal profile must not crash cookie generator");
    }
}

#[test]
fn fuzz_search_minimal_profile() {
    let profile = minimal_profile();
    let ctx = GenerationContext::new();
    let mut rng = seeded_rng(32);
    let generator = SearchGenerator::new();

    for _ in 0..100 {
        let result = generator.generate(&profile, &ctx, &mut rng);
        assert!(result.is_ok(), "minimal profile must not crash search generator");
    }
}

// ============================================================================
// 5. Generate 10,000 history entries -- verify none crash
// ============================================================================

#[test]
fn fuzz_10000_history_entries_no_crash() {
    let profile = UserProfile::default();
    let ctx = GenerationContext::new();
    let mut rng = seeded_rng(42);
    let mut generator = HistoryGenerator::new();

    for i in 0..10_000u64 {
        let result = generator.generate(&profile, &ctx, &mut rng);
        assert!(result.is_ok(), "history entry {i} crashed: {:?}", result.err());
        let artifact = result.unwrap();
        let bytes = artifact.to_bytes().unwrap();
        let entry: HistoryEntry = serde_json::from_slice(&bytes).unwrap();
        generator.recent_urls.push(entry.url);
        if generator.recent_urls.len() > 50 {
            generator.recent_urls.remove(0);
        }
    }
}

// ============================================================================
// 6. Seed edge cases: 0, u64::MAX, every power of 2
// ============================================================================

#[test]
fn fuzz_history_seed_zero() {
    let profile = UserProfile::default();
    let ctx = GenerationContext::new();
    let mut rng = seeded_rng(0);
    let generator = HistoryGenerator::new();
    let result = generator.generate(&profile, &ctx, &mut rng);
    assert!(result.is_ok(), "seed 0 must not crash");
}

#[test]
fn fuzz_history_seed_u64_max() {
    let profile = UserProfile::default();
    let ctx = GenerationContext::new();
    let mut rng = seeded_rng(u64::MAX);
    let generator = HistoryGenerator::new();
    let result = generator.generate(&profile, &ctx, &mut rng);
    assert!(result.is_ok(), "seed u64::MAX must not crash");
}

#[test]
fn fuzz_generators_every_power_of_two_seed() {
    let profile = UserProfile::default();
    let ctx = GenerationContext::new();
    let history_gen = HistoryGenerator::new();
    let cookie_gen = CookieGenerator::new();
    let search_gen = SearchGenerator::new();

    for exp in 0..64u32 {
        let seed = 1u64 << exp;
        let mut rng = seeded_rng(seed);

        let h = history_gen.generate(&profile, &ctx, &mut rng);
        assert!(h.is_ok(), "history crashed at seed 2^{exp} ({seed})");

        let mut rng = seeded_rng(seed);
        let c = cookie_gen.generate(&profile, &ctx, &mut rng);
        assert!(c.is_ok(), "cookie crashed at seed 2^{exp} ({seed})");

        let mut rng = seeded_rng(seed);
        let s = search_gen.generate(&profile, &ctx, &mut rng);
        assert!(s.is_ok(), "search crashed at seed 2^{exp} ({seed})");
    }
}

// ============================================================================
// 7. No generated URL contains null bytes
// ============================================================================

#[test]
fn fuzz_no_null_bytes_in_urls() {
    let profile = UserProfile::default();
    let ctx = GenerationContext::new();
    let mut rng = seeded_rng(70);
    let mut generator = HistoryGenerator::new();

    for i in 0..2000u64 {
        let artifact = generator.generate(&profile, &ctx, &mut rng).unwrap();
        let bytes = artifact.to_bytes().unwrap();
        let entry: HistoryEntry = serde_json::from_slice(&bytes).unwrap();

        assert!(
            !entry.url.contains('\0'),
            "entry {i}: URL contains null byte: {:?}",
            entry.url,
        );

        if let Some(ref referrer) = entry.referrer {
            assert!(
                !referrer.contains('\0'),
                "entry {i}: referrer contains null byte: {:?}",
                referrer,
            );
        }

        generator.recent_urls.push(entry.url);
        if generator.recent_urls.len() > 20 {
            generator.recent_urls.remove(0);
        }
    }
}

// ============================================================================
// 8. No generated title contains control characters
// ============================================================================

#[test]
fn fuzz_no_control_chars_in_titles() {
    let profile = UserProfile::default();
    let ctx = GenerationContext::new();
    let mut rng = seeded_rng(80);
    let mut generator = HistoryGenerator::new();

    for i in 0..2000u64 {
        let artifact = generator.generate(&profile, &ctx, &mut rng).unwrap();
        let bytes = artifact.to_bytes().unwrap();
        let entry: HistoryEntry = serde_json::from_slice(&bytes).unwrap();

        for ch in entry.title.chars() {
            assert!(
                !ch.is_control(),
                "entry {i}: title contains control character U+{:04X} in {:?}",
                ch as u32,
                entry.title,
            );
        }

        generator.recent_urls.push(entry.url);
        if generator.recent_urls.len() > 20 {
            generator.recent_urls.remove(0);
        }
    }
}

// ============================================================================
// 9. No generated cookie value contains newlines (HTTP header injection)
// ============================================================================

#[test]
fn fuzz_no_newlines_in_cookie_values() {
    let profile = UserProfile::default();
    let ctx = GenerationContext::new();
    let cookie_gen = CookieGenerator::new();

    for seed in 0..2000u64 {
        let mut rng = seeded_rng(seed);
        let artifact = cookie_gen.generate(&profile, &ctx, &mut rng).unwrap();
        let bytes = artifact.to_bytes().unwrap();
        let cookie: CookieEntry = serde_json::from_slice(&bytes).unwrap();

        assert!(
            !cookie.value.contains('\n'),
            "seed {seed}: cookie value contains newline (header injection risk): {:?}",
            cookie.value,
        );
        assert!(
            !cookie.value.contains('\r'),
            "seed {seed}: cookie value contains carriage return (header injection risk): {:?}",
            cookie.value,
        );
        assert!(
            !cookie.name.contains('\n') && !cookie.name.contains('\r'),
            "seed {seed}: cookie name contains newline/CR: {:?}",
            cookie.name,
        );
        assert!(
            !cookie.domain.contains('\n') && !cookie.domain.contains('\r'),
            "seed {seed}: cookie domain contains newline/CR: {:?}",
            cookie.domain,
        );
    }
}

// ============================================================================
// 10. UserProfile with extreme age ranges
// ============================================================================

#[test]
fn fuzz_profile_age_zero_zero() {
    let profile = UserProfileBuilder::new()
        .demographic(DemographicProfile {
            age_range: (0, 0),
            language: "en".to_string(),
            country: "US".to_string(),
            occupation: OccupationCategory::General,
        })
        .build();
    let ctx = GenerationContext::new();
    let mut rng = seeded_rng(100);
    let generator = HistoryGenerator::new();

    for _ in 0..50 {
        let _ = generator.generate(&profile, &ctx, &mut rng);
    }
}

#[test]
fn fuzz_profile_age_200_200() {
    let profile = UserProfileBuilder::new()
        .demographic(DemographicProfile {
            age_range: (200, 200),
            language: "en".to_string(),
            country: "US".to_string(),
            occupation: OccupationCategory::Retired,
        })
        .build();
    let ctx = GenerationContext::new();
    let mut rng = seeded_rng(101);
    let generator = HistoryGenerator::new();

    for _ in 0..50 {
        let _ = generator.generate(&profile, &ctx, &mut rng);
    }
}

#[test]
fn fuzz_profile_age_inverted() {
    // age min > age max -- should not crash
    let profile = UserProfileBuilder::new()
        .demographic(DemographicProfile {
            age_range: (80, 20),
            language: "en".to_string(),
            country: "US".to_string(),
            occupation: OccupationCategory::General,
        })
        .build();
    let ctx = GenerationContext::new();
    let mut rng = seeded_rng(102);
    let generator = HistoryGenerator::new();

    for _ in 0..50 {
        let _ = generator.generate(&profile, &ctx, &mut rng);
    }
}

// ============================================================================
// 11. OrganicScheduler with wake == sleep (zero-width activity window)
// ============================================================================

#[test]
fn fuzz_scheduler_wake_equals_sleep() {
    for hour in 0..24u8 {
        let schedule = ActivitySchedule {
            wake_hour: hour,
            sleep_hour: hour,
            active_days: vec![0, 1, 2, 3, 4, 5, 6],
            timezone_offset_hours: 0,
        };
        let scheduler = OrganicScheduler::new(schedule, RiskLevel::Medium);
        let mut rng = seeded_rng(110 + hour as u64);
        let now = Utc::now();

        // Must not panic or produce infinite loop
        let next = scheduler.next_timestamp(now, &mut rng);
        assert!(next > now, "wake==sleep at hour {hour}: timestamp must still advance");
    }
}

#[test]
fn fuzz_scheduler_zero_width_session() {
    let schedule = ActivitySchedule {
        wake_hour: 12,
        sleep_hour: 12,
        active_days: vec![],
        timezone_offset_hours: 0,
    };
    let scheduler = OrganicScheduler::new(schedule, RiskLevel::Maximum);
    let mut rng = seeded_rng(111);
    let now = Utc::now();

    // Generate a session with 0 length
    let timestamps = scheduler.generate_session_timestamps(now, 0, &mut rng);
    assert!(timestamps.is_empty());

    // Generate a session with 1 entry
    let timestamps = scheduler.generate_session_timestamps(now, 1, &mut rng);
    assert_eq!(timestamps.len(), 1);
    assert!(timestamps[0] > now);
}

#[test]
fn fuzz_scheduler_extreme_timezone_offsets() {
    for tz_offset in [-12i8, -11, -6, 0, 5, 9, 12] {
        let schedule = ActivitySchedule {
            wake_hour: 7,
            sleep_hour: 23,
            active_days: vec![0, 1, 2, 3, 4, 5, 6],
            timezone_offset_hours: tz_offset,
        };
        let scheduler = OrganicScheduler::new(schedule, RiskLevel::High);
        let mut rng = seeded_rng(120 + (tz_offset + 12) as u64);
        let now = Utc::now();

        let next = scheduler.next_timestamp(now, &mut rng);
        assert!(
            next > now,
            "tz_offset={tz_offset}: timestamp must advance"
        );
    }
}

// ============================================================================
// 12. ArtifactMetadata with extreme size_bytes values
// ============================================================================

#[test]
fn fuzz_metadata_size_bytes_zero() {
    let now = Utc::now();
    let meta = ArtifactMetadata::new(DataCategory::BrowserActivity, now, now, 0);
    assert!(meta.is_ok(), "size_bytes=0 must not crash");
}

#[test]
fn fuzz_metadata_size_bytes_u64_max() {
    let now = Utc::now();
    let meta = ArtifactMetadata::new(DataCategory::BrowserActivity, now, now, u64::MAX);
    assert!(meta.is_ok(), "size_bytes=u64::MAX must not crash");
}

#[test]
fn fuzz_metadata_every_category() {
    let now = Utc::now();
    let categories = [
        DataCategory::BrowserActivity,
        DataCategory::FileSystem,
        DataCategory::Communications,
        DataCategory::Location,
        DataCategory::Network,
        DataCategory::Input,
        DataCategory::System,
        DataCategory::Social,
    ];
    for cat in &categories {
        let meta = ArtifactMetadata::new(*cat, now, now, 42);
        assert!(meta.is_ok(), "category {:?} must not crash", cat);
    }
}

// ============================================================================
// GenerationContext edge cases
// ============================================================================

#[test]
fn fuzz_context_extreme_artifact_counts() {
    let mut ctx = GenerationContext::new();
    ctx.session_artifact_count = u64::MAX;
    ctx.total_artifact_count = u64::MAX;

    let profile = UserProfile::default();
    let mut rng = seeded_rng(200);
    let generator = HistoryGenerator::new();

    let result = generator.generate(&profile, &ctx, &mut rng);
    assert!(result.is_ok(), "extreme artifact counts must not crash");
}

#[test]
fn fuzz_context_at_epoch() {
    let epoch = chrono::DateTime::UNIX_EPOCH;
    let ctx = GenerationContext::at(epoch);

    let profile = UserProfile::default();
    let mut rng = seeded_rng(201);
    let generator = HistoryGenerator::new();

    // May fail plausibility (far-past timestamps) but must not panic.
    let _ = generator.generate(&profile, &ctx, &mut rng);
}

// ============================================================================
// Device profile edge cases
// ============================================================================

#[test]
fn fuzz_profile_no_browsers() {
    let profile = UserProfileBuilder::new()
        .device(DeviceProfile {
            os: OsFamily::Linux,
            browsers: vec![],
            has_gps: false,
            has_cellular: false,
            available_storage_bytes: 0,
        })
        .build();
    let ctx = GenerationContext::new();
    let mut rng = seeded_rng(300);
    let generator = HistoryGenerator::new();

    for _ in 0..50 {
        let _ = generator.generate(&profile, &ctx, &mut rng);
    }
}

#[test]
fn fuzz_profile_zero_storage() {
    let profile = UserProfileBuilder::new()
        .device(DeviceProfile {
            os: OsFamily::Android,
            browsers: vec![BrowserType::Chrome],
            has_gps: true,
            has_cellular: true,
            available_storage_bytes: 0,
        })
        .build();
    let ctx = GenerationContext::new();
    let mut rng = seeded_rng(301);
    let cookie_gen = CookieGenerator::new();

    for _ in 0..50 {
        let _ = cookie_gen.generate(&profile, &ctx, &mut rng);
    }
}

#[test]
fn fuzz_profile_max_storage() {
    let profile = UserProfileBuilder::new()
        .device(DeviceProfile {
            os: OsFamily::Windows,
            browsers: vec![
                BrowserType::Firefox,
                BrowserType::Chrome,
                BrowserType::Edge,
                BrowserType::Brave,
                BrowserType::Safari,
            ],
            has_gps: false,
            has_cellular: false,
            available_storage_bytes: u64::MAX,
        })
        .build();
    let ctx = GenerationContext::new();
    let mut rng = seeded_rng(302);
    let search_gen = SearchGenerator::new();

    for _ in 0..50 {
        let _ = search_gen.generate(&profile, &ctx, &mut rng);
    }
}

// ============================================================================
// All interest categories individually
// ============================================================================

#[test]
fn fuzz_every_interest_category_individually() {
    let all_categories = [
        InterestCategory::News,
        InterestCategory::Technology,
        InterestCategory::Sports,
        InterestCategory::Entertainment,
        InterestCategory::Shopping,
        InterestCategory::Social,
        InterestCategory::Academic,
        InterestCategory::Finance,
        InterestCategory::Health,
        InterestCategory::Travel,
        InterestCategory::Food,
        InterestCategory::Gaming,
        InterestCategory::Music,
        InterestCategory::Government,
        InterestCategory::Legal,
        InterestCategory::Weather,
        InterestCategory::Reference,
        InterestCategory::Documentation,
    ];

    let ctx = GenerationContext::new();
    let history_gen = HistoryGenerator::new();
    let cookie_gen = CookieGenerator::new();
    let search_gen = SearchGenerator::new();

    for (idx, cat) in all_categories.iter().enumerate() {
        let profile = profile_with(vec![cat.clone()], RiskLevel::High);
        let mut rng = seeded_rng(400 + idx as u64);

        let h = history_gen.generate(&profile, &ctx, &mut rng);
        assert!(h.is_ok(), "history crashed for interest {:?}", cat);

        let mut rng = seeded_rng(400 + idx as u64);
        let c = cookie_gen.generate(&profile, &ctx, &mut rng);
        assert!(c.is_ok(), "cookie crashed for interest {:?}", cat);

        let mut rng = seeded_rng(400 + idx as u64);
        let s = search_gen.generate(&profile, &ctx, &mut rng);
        assert!(s.is_ok(), "search crashed for interest {:?}", cat);
    }
}

// ============================================================================
// All risk levels across all generators
// ============================================================================

#[test]
fn fuzz_every_risk_level() {
    let risks = [RiskLevel::Low, RiskLevel::Medium, RiskLevel::High, RiskLevel::Maximum];
    let ctx = GenerationContext::new();
    let history_gen = HistoryGenerator::new();
    let cookie_gen = CookieGenerator::new();
    let search_gen = SearchGenerator::new();

    for risk in &risks {
        let profile = profile_with(
            vec![InterestCategory::News, InterestCategory::Technology],
            *risk,
        );
        let mut rng = seeded_rng(500);

        let h = history_gen.generate(&profile, &ctx, &mut rng);
        assert!(h.is_ok(), "history crashed at risk {:?}", risk);

        let mut rng = seeded_rng(500);
        let c = cookie_gen.generate(&profile, &ctx, &mut rng);
        assert!(c.is_ok(), "cookie crashed at risk {:?}", risk);

        let mut rng = seeded_rng(500);
        let s = search_gen.generate(&profile, &ctx, &mut rng);
        assert!(s.is_ok(), "search crashed at risk {:?}", risk);
    }
}

// ============================================================================
// Locale edge cases
// ============================================================================

#[test]
fn fuzz_profile_empty_locale_strings() {
    let profile = UserProfileBuilder::new()
        .locale(Locale {
            language_tag: String::new(),
            date_format: String::new(),
            currency: String::new(),
        })
        .build();
    let ctx = GenerationContext::new();
    let mut rng = seeded_rng(600);
    let generator = HistoryGenerator::new();

    for _ in 0..50 {
        let _ = generator.generate(&profile, &ctx, &mut rng);
    }
}

// ============================================================================
// Metadata timestamp edge cases
// ============================================================================

#[test]
fn fuzz_metadata_created_equals_modified() {
    let now = Utc::now();
    let meta = ArtifactMetadata::new(DataCategory::BrowserActivity, now, now, 100);
    assert!(meta.is_ok());
}

#[test]
fn fuzz_metadata_modified_before_created_rejected() {
    let now = Utc::now();
    let earlier = now - Duration::hours(1);
    let meta = ArtifactMetadata::new(DataCategory::BrowserActivity, now, earlier, 100);
    assert!(meta.is_err(), "modified < created must be rejected");
}

// ============================================================================
// Proptest: random profiles through all generators
// ============================================================================

fn arb_risk_level() -> impl Strategy<Value = RiskLevel> {
    prop_oneof![
        Just(RiskLevel::Low),
        Just(RiskLevel::Medium),
        Just(RiskLevel::High),
        Just(RiskLevel::Maximum),
    ]
}

fn arb_interest() -> impl Strategy<Value = InterestCategory> {
    prop_oneof![
        Just(InterestCategory::News),
        Just(InterestCategory::Technology),
        Just(InterestCategory::Sports),
        Just(InterestCategory::Entertainment),
        Just(InterestCategory::Shopping),
        Just(InterestCategory::Social),
        Just(InterestCategory::Academic),
        Just(InterestCategory::Finance),
        Just(InterestCategory::Health),
        Just(InterestCategory::Travel),
        Just(InterestCategory::Food),
        Just(InterestCategory::Gaming),
        Just(InterestCategory::Music),
        Just(InterestCategory::Government),
        Just(InterestCategory::Legal),
        Just(InterestCategory::Weather),
        Just(InterestCategory::Reference),
        Just(InterestCategory::Documentation),
    ]
}

proptest! {
    #[test]
    fn prop_history_never_crashes(
        seed in 0u64..100_000,
        risk in arb_risk_level(),
        interests in prop::collection::vec(arb_interest(), 0..6),
    ) {
        let profile = profile_with(interests, risk);
        let ctx = GenerationContext::new();
        let mut rng = seeded_rng(seed);
        let generator = HistoryGenerator::new();
        let _ = generator.generate(&profile, &ctx, &mut rng);
    }

    #[test]
    fn prop_cookie_never_crashes(
        seed in 0u64..100_000,
        risk in arb_risk_level(),
        interests in prop::collection::vec(arb_interest(), 0..6),
    ) {
        let profile = profile_with(interests, risk);
        let ctx = GenerationContext::new();
        let mut rng = seeded_rng(seed);
        let generator = CookieGenerator::new();
        let _ = generator.generate(&profile, &ctx, &mut rng);
    }

    #[test]
    fn prop_search_never_crashes(
        seed in 0u64..100_000,
        risk in arb_risk_level(),
        interests in prop::collection::vec(arb_interest(), 0..6),
    ) {
        let profile = profile_with(interests, risk);
        let ctx = GenerationContext::new();
        let mut rng = seeded_rng(seed);
        let generator = SearchGenerator::new();
        let _ = generator.generate(&profile, &ctx, &mut rng);
    }

    #[test]
    fn prop_scheduler_never_crashes(
        seed in 0u64..50_000,
        wake in 0u8..24,
        sleep in 0u8..24,
        tz_offset in -12i8..=12,
        risk in arb_risk_level(),
    ) {
        let schedule = ActivitySchedule {
            wake_hour: wake,
            sleep_hour: sleep,
            active_days: vec![0, 1, 2, 3, 4, 5, 6],
            timezone_offset_hours: tz_offset,
        };
        let scheduler = OrganicScheduler::new(schedule, risk);
        let mut rng = seeded_rng(seed);
        let now = Utc::now();
        let next = scheduler.next_timestamp(now, &mut rng);
        prop_assert!(next > now);
    }

    #[test]
    fn prop_metadata_size_never_crashes(
        size in any::<u64>(),
    ) {
        let now = Utc::now();
        let result = ArtifactMetadata::new(DataCategory::BrowserActivity, now, now, size);
        prop_assert!(result.is_ok());
    }

    #[test]
    fn prop_no_null_bytes_in_generated_urls(
        seed in 0u64..10_000,
    ) {
        let profile = UserProfile::default();
        let ctx = GenerationContext::new();
        let mut rng = seeded_rng(seed);
        let generator = HistoryGenerator::new();
        if let Ok(artifact) = generator.generate(&profile, &ctx, &mut rng) {
            let bytes = artifact.to_bytes().unwrap();
            let entry: HistoryEntry = serde_json::from_slice(&bytes).unwrap();
            prop_assert!(!entry.url.contains('\0'), "URL contains null byte at seed {}", seed);
        }
    }

    #[test]
    fn prop_no_newlines_in_cookie_values(
        seed in 0u64..10_000,
    ) {
        let profile = UserProfile::default();
        let ctx = GenerationContext::new();
        let mut rng = seeded_rng(seed);
        let generator = CookieGenerator::new();
        if let Ok(artifact) = generator.generate(&profile, &ctx, &mut rng) {
            let bytes = artifact.to_bytes().unwrap();
            let cookie: CookieEntry = serde_json::from_slice(&bytes).unwrap();
            prop_assert!(!cookie.value.contains('\n'), "cookie value contains newline at seed {}", seed);
            prop_assert!(!cookie.value.contains('\r'), "cookie value contains CR at seed {}", seed);
        }
    }
}

// ============================================================================
// Serialization roundtrip under stress
// ============================================================================

#[test]
fn fuzz_history_serde_roundtrip_1000() {
    let profile = UserProfile::default();
    let ctx = GenerationContext::new();
    let mut rng = seeded_rng(700);
    let mut generator = HistoryGenerator::new();

    for i in 0..1000u64 {
        let artifact = generator.generate(&profile, &ctx, &mut rng).unwrap();
        let bytes = artifact.to_bytes().unwrap();

        // Must deserialize without error
        let entry: HistoryEntry = serde_json::from_slice(&bytes)
            .unwrap_or_else(|e| panic!("entry {i}: deserialization failed: {e}"));

        // Re-serialize must also succeed
        let re_bytes = serde_json::to_vec(&entry)
            .unwrap_or_else(|e| panic!("entry {i}: re-serialization failed: {e}"));

        // Roundtrip must be stable
        let re_entry: HistoryEntry = serde_json::from_slice(&re_bytes)
            .unwrap_or_else(|e| panic!("entry {i}: double roundtrip failed: {e}"));
        assert_eq!(entry.url, re_entry.url, "entry {i}: URL changed in roundtrip");

        generator.recent_urls.push(entry.url);
        if generator.recent_urls.len() > 20 {
            generator.recent_urls.remove(0);
        }
    }
}

#[test]
fn fuzz_cookie_serde_roundtrip_1000() {
    let profile = UserProfile::default();
    let ctx = GenerationContext::new();
    let cookie_gen = CookieGenerator::new();

    for seed in 0..1000u64 {
        let mut rng = seeded_rng(seed);
        let artifact = cookie_gen.generate(&profile, &ctx, &mut rng).unwrap();
        let bytes = artifact.to_bytes().unwrap();
        let cookie: CookieEntry = serde_json::from_slice(&bytes)
            .unwrap_or_else(|e| panic!("seed {seed}: deserialization failed: {e}"));
        let re_bytes = serde_json::to_vec(&cookie)
            .unwrap_or_else(|e| panic!("seed {seed}: re-serialization failed: {e}"));
        let re_cookie: CookieEntry = serde_json::from_slice(&re_bytes)
            .unwrap_or_else(|e| panic!("seed {seed}: double roundtrip failed: {e}"));
        assert_eq!(cookie.name, re_cookie.name);
        assert_eq!(cookie.value, re_cookie.value);
        assert_eq!(cookie.domain, re_cookie.domain);
    }
}

#[test]
fn fuzz_search_serde_roundtrip_1000() {
    let profile = UserProfile::default();
    let ctx = GenerationContext::new();
    let search_gen = SearchGenerator::new();

    for seed in 0..1000u64 {
        let mut rng = seeded_rng(seed);
        let artifact = search_gen.generate(&profile, &ctx, &mut rng).unwrap();
        let bytes = artifact.to_bytes().unwrap();
        let entry: SearchEntry = serde_json::from_slice(&bytes)
            .unwrap_or_else(|e| panic!("seed {seed}: deserialization failed: {e}"));
        let re_bytes = serde_json::to_vec(&entry)
            .unwrap_or_else(|e| panic!("seed {seed}: re-serialization failed: {e}"));
        let re_entry: SearchEntry = serde_json::from_slice(&re_bytes)
            .unwrap_or_else(|e| panic!("seed {seed}: double roundtrip failed: {e}"));
        assert_eq!(entry.query, re_entry.query);
        assert_eq!(entry.search_engine, re_entry.search_engine);
    }
}

// ============================================================================
// All occupation categories through generators
// ============================================================================

#[test]
fn fuzz_every_occupation() {
    let occupations = [
        OccupationCategory::General,
        OccupationCategory::Student,
        OccupationCategory::Academic,
        OccupationCategory::Journalist,
        OccupationCategory::LegalProfessional,
        OccupationCategory::TechWorker,
        OccupationCategory::HealthcareWorker,
        OccupationCategory::TradesWorker,
        OccupationCategory::Retired,
    ];

    let ctx = GenerationContext::new();
    let history_gen = HistoryGenerator::new();

    for (idx, occ) in occupations.iter().enumerate() {
        let profile = UserProfileBuilder::new()
            .demographic(DemographicProfile {
                age_range: (25, 45),
                language: "en".to_string(),
                country: "US".to_string(),
                occupation: occ.clone(),
            })
            .build();
        let mut rng = seeded_rng(800 + idx as u64);
        let result = history_gen.generate(&profile, &ctx, &mut rng);
        assert!(result.is_ok(), "occupation {:?} must not crash", occ);
    }
}

// ============================================================================
// All OS families through generators
// ============================================================================

#[test]
fn fuzz_every_os_family() {
    let os_families = [
        OsFamily::Linux,
        OsFamily::MacOS,
        OsFamily::Windows,
        OsFamily::Android,
        OsFamily::IOS,
    ];

    let ctx = GenerationContext::new();
    let history_gen = HistoryGenerator::new();

    for (idx, os) in os_families.iter().enumerate() {
        let profile = UserProfileBuilder::new()
            .device(DeviceProfile {
                os: *os,
                browsers: vec![BrowserType::Firefox],
                has_gps: false,
                has_cellular: false,
                available_storage_bytes: 1024 * 1024,
            })
            .build();
        let mut rng = seeded_rng(900 + idx as u64);
        let result = history_gen.generate(&profile, &ctx, &mut rng);
        assert!(result.is_ok(), "OS {:?} must not crash", os);
    }
}

// ============================================================================
// Bookmark generator — adversarial & fuzz tests
// ============================================================================

/// Known bookmark folders from the generator's BOOKMARK_SITES constant.
const KNOWN_BOOKMARK_FOLDERS: &[&str] = &[
    "Development", "News", "Reference", "Email", "Cloud",
    "Shopping", "Entertainment", "Social", "Professional",
    "Productivity", "Utilities",
];

#[test]
fn fuzz_bookmark_empty_interests() {
    let profile = profile_with(vec![], RiskLevel::Medium);
    let ctx = GenerationContext::new();
    let mut rng = seeded_rng(4000);
    let generator = BookmarkGenerator::new();

    for _ in 0..100 {
        let _ = generator.generate(&profile, &ctx, &mut rng);
    }
}

#[test]
fn fuzz_1000_bookmarks_all_valid() {
    let generator = BookmarkGenerator::new();
    let profile = UserProfile::default();
    let ctx = GenerationContext::new();

    for seed in 0..1000u64 {
        let mut rng = seeded_rng(seed);
        let artifact = generator
            .generate(&profile, &ctx, &mut rng)
            .unwrap_or_else(|e| panic!("bookmark seed {seed} failed: {e}"));
        artifact
            .validate_plausibility()
            .unwrap_or_else(|e| panic!("bookmark seed {seed} implausible: {e}"));
    }
}

#[test]
fn fuzz_bookmark_urls_are_https() {
    let generator = BookmarkGenerator::new();
    let profile = UserProfile::default();
    let ctx = GenerationContext::new();

    for seed in 0..1000u64 {
        let mut rng = seeded_rng(seed);
        let artifact = generator.generate(&profile, &ctx, &mut rng).unwrap();
        let bytes = artifact.to_bytes().unwrap();
        let entry: BookmarkEntry = serde_json::from_slice(&bytes).unwrap();
        assert!(
            entry.url.starts_with("https://"),
            "seed {seed}: bookmark URL must be HTTPS, got: {}",
            entry.url,
        );
    }
}

#[test]
fn fuzz_bookmark_titles_non_empty() {
    let generator = BookmarkGenerator::new();
    let profile = UserProfile::default();
    let ctx = GenerationContext::new();

    for seed in 0..1000u64 {
        let mut rng = seeded_rng(seed);
        let artifact = generator.generate(&profile, &ctx, &mut rng).unwrap();
        let bytes = artifact.to_bytes().unwrap();
        let entry: BookmarkEntry = serde_json::from_slice(&bytes).unwrap();
        assert!(
            !entry.title.is_empty(),
            "seed {seed}: bookmark title must not be empty",
        );
        assert!(
            !entry.title.trim().is_empty(),
            "seed {seed}: bookmark title must not be whitespace-only: '{}'",
            entry.title,
        );
    }
}

#[test]
fn fuzz_bookmark_folders_from_known_set() {
    let generator = BookmarkGenerator::new();
    let profile = UserProfile::default();
    let ctx = GenerationContext::new();

    for seed in 0..1000u64 {
        let mut rng = seeded_rng(seed);
        let artifact = generator.generate(&profile, &ctx, &mut rng).unwrap();
        let bytes = artifact.to_bytes().unwrap();
        let entry: BookmarkEntry = serde_json::from_slice(&bytes).unwrap();
        assert!(
            KNOWN_BOOKMARK_FOLDERS.contains(&entry.folder.as_str()),
            "seed {seed}: unexpected bookmark folder '{}', expected one of {:?}",
            entry.folder,
            KNOWN_BOOKMARK_FOLDERS,
        );
    }
}

#[test]
fn fuzz_bookmark_dates_in_past() {
    let generator = BookmarkGenerator::new();
    let profile = UserProfile::default();
    let ctx = GenerationContext::new();

    for seed in 0..1000u64 {
        let mut rng = seeded_rng(seed);
        let artifact = generator.generate(&profile, &ctx, &mut rng).unwrap();
        let bytes = artifact.to_bytes().unwrap();
        let entry: BookmarkEntry = serde_json::from_slice(&bytes).unwrap();
        assert!(
            entry.added_at <= ctx.now,
            "seed {seed}: bookmark added_at is in the future: {} > {}",
            entry.added_at,
            ctx.now,
        );
        // Also verify the metadata timestamps are not future
        let meta = artifact.metadata();
        assert!(
            meta.created_at <= ctx.now,
            "seed {seed}: bookmark meta.created_at in the future: {} > {}",
            meta.created_at,
            ctx.now,
        );
        assert!(
            meta.modified_at <= ctx.now,
            "seed {seed}: bookmark meta.modified_at in the future: {} > {}",
            meta.modified_at,
            ctx.now,
        );
    }
}

#[test]
fn fuzz_bookmark_every_risk_level() {
    let levels = [RiskLevel::Low, RiskLevel::Medium, RiskLevel::High, RiskLevel::Maximum];
    let ctx = GenerationContext::new();
    let generator = BookmarkGenerator::new();

    for (idx, level) in levels.iter().enumerate() {
        let profile = profile_with(vec![InterestCategory::Technology], *level);
        let mut rng = seeded_rng(5000 + idx as u64);
        let result = generator.generate(&profile, &ctx, &mut rng);
        assert!(result.is_ok(), "risk level {:?} must not crash", level);
    }
}

#[test]
fn fuzz_bookmark_roundtrip_serde() {
    let generator = BookmarkGenerator::new();
    let profile = UserProfile::default();
    let ctx = GenerationContext::new();

    for seed in 0..200u64 {
        let mut rng = seeded_rng(seed);
        let artifact = generator.generate(&profile, &ctx, &mut rng).unwrap();
        let bytes = artifact.to_bytes().unwrap();
        let entry: BookmarkEntry = serde_json::from_slice(&bytes).unwrap();
        // Re-serialize and compare
        let bytes2 = serde_json::to_vec(&entry).unwrap();
        let entry2: BookmarkEntry = serde_json::from_slice(&bytes2).unwrap();
        assert_eq!(entry.url, entry2.url, "seed {seed}: URL roundtrip mismatch");
        assert_eq!(entry.title, entry2.title, "seed {seed}: title roundtrip mismatch");
        assert_eq!(entry.folder, entry2.folder, "seed {seed}: folder roundtrip mismatch");
    }
}

// ============================================================================
// Download generator — adversarial & fuzz tests
// ============================================================================

#[test]
fn fuzz_download_empty_interests() {
    let profile = profile_with(vec![], RiskLevel::Medium);
    let ctx = GenerationContext::new();
    let mut rng = seeded_rng(6000);
    let generator = DownloadGenerator::new();

    for _ in 0..100 {
        let _ = generator.generate(&profile, &ctx, &mut rng);
    }
}

#[test]
fn fuzz_1000_downloads_all_valid() {
    let generator = DownloadGenerator::new();
    let profile = UserProfile::default();
    let ctx = GenerationContext::new();

    for seed in 0..1000u64 {
        let mut rng = seeded_rng(seed);
        let artifact = generator
            .generate(&profile, &ctx, &mut rng)
            .unwrap_or_else(|e| panic!("download seed {seed} failed: {e}"));
        artifact
            .validate_plausibility()
            .unwrap_or_else(|e| panic!("download seed {seed} implausible: {e}"));
    }
}

#[test]
fn fuzz_download_completed_after_started() {
    let generator = DownloadGenerator::new();
    let profile = UserProfile::default();
    let ctx = GenerationContext::new();

    for seed in 0..1000u64 {
        let mut rng = seeded_rng(seed);
        let artifact = generator.generate(&profile, &ctx, &mut rng).unwrap();
        let bytes = artifact.to_bytes().unwrap();
        let entry: DownloadEntry = serde_json::from_slice(&bytes).unwrap();
        assert!(
            entry.completed_at >= entry.started_at,
            "seed {seed}: completed_at ({}) < started_at ({})",
            entry.completed_at,
            entry.started_at,
        );
    }
}

#[test]
fn fuzz_download_file_sizes_within_template_ranges() {
    // Template ranges: smallest min is 50_000, largest max is 5_000_000_000.
    let generator = DownloadGenerator::new();
    let profile = UserProfile::default();
    let ctx = GenerationContext::new();

    let global_min: u64 = 50_000;
    let global_max: u64 = 5_000_000_000;

    for seed in 0..1000u64 {
        let mut rng = seeded_rng(seed);
        let artifact = generator.generate(&profile, &ctx, &mut rng).unwrap();
        let bytes = artifact.to_bytes().unwrap();
        let entry: DownloadEntry = serde_json::from_slice(&bytes).unwrap();
        assert!(
            entry.size_bytes >= global_min,
            "seed {seed}: size {} below minimum template range {}",
            entry.size_bytes,
            global_min,
        );
        assert!(
            entry.size_bytes <= global_max,
            "seed {seed}: size {} above maximum template range {}",
            entry.size_bytes,
            global_max,
        );
        assert!(
            entry.size_bytes > 0,
            "seed {seed}: zero-byte download should be impossible",
        );
    }
}

#[test]
fn fuzz_download_filenames_no_path_separators() {
    let generator = DownloadGenerator::new();
    let profile = UserProfile::default();
    let ctx = GenerationContext::new();

    for seed in 0..1000u64 {
        let mut rng = seeded_rng(seed);
        let artifact = generator.generate(&profile, &ctx, &mut rng).unwrap();
        let bytes = artifact.to_bytes().unwrap();
        let entry: DownloadEntry = serde_json::from_slice(&bytes).unwrap();
        assert!(
            !entry.filename.contains('/'),
            "seed {seed}: filename contains forward slash: '{}'",
            entry.filename,
        );
        assert!(
            !entry.filename.contains('\\'),
            "seed {seed}: filename contains backslash: '{}'",
            entry.filename,
        );
        assert!(
            !entry.filename.contains('\0'),
            "seed {seed}: filename contains null byte",
        );
        assert!(
            !entry.filename.is_empty(),
            "seed {seed}: filename must not be empty",
        );
    }
}

#[test]
fn fuzz_download_urls_valid_https() {
    let generator = DownloadGenerator::new();
    let profile = UserProfile::default();
    let ctx = GenerationContext::new();

    for seed in 0..1000u64 {
        let mut rng = seeded_rng(seed);
        let artifact = generator.generate(&profile, &ctx, &mut rng).unwrap();
        let bytes = artifact.to_bytes().unwrap();
        let entry: DownloadEntry = serde_json::from_slice(&bytes).unwrap();
        assert!(
            entry.url.starts_with("https://"),
            "seed {seed}: download URL must be HTTPS, got: {}",
            entry.url,
        );
        // Verify URL is parseable
        assert!(
            url::Url::parse(&entry.url).is_ok(),
            "seed {seed}: download URL is not valid: {}",
            entry.url,
        );
    }
}

#[test]
fn fuzz_download_duration_scales_with_size() {
    // The generator simulates ~10 MB/s, so larger files should take longer.
    // Collect (size, duration) pairs and verify positive correlation.
    let generator = DownloadGenerator::new();
    let profile = UserProfile::default();
    let ctx = GenerationContext::new();

    let mut small_durations = Vec::new();
    let mut large_durations = Vec::new();
    let size_threshold: u64 = 100_000_000; // 100 MB

    for seed in 0..1000u64 {
        let mut rng = seeded_rng(seed);
        let artifact = generator.generate(&profile, &ctx, &mut rng).unwrap();
        let bytes = artifact.to_bytes().unwrap();
        let entry: DownloadEntry = serde_json::from_slice(&bytes).unwrap();
        let duration_secs = (entry.completed_at - entry.started_at).num_seconds();
        assert!(
            duration_secs >= 1,
            "seed {seed}: download duration must be >= 1s, got {duration_secs}s",
        );
        if entry.size_bytes < size_threshold {
            small_durations.push(duration_secs);
        } else {
            large_durations.push(duration_secs);
        }
    }

    // Both buckets should be non-empty across 1000 samples (templates span
    // 50KB to 5GB, so we will hit both sides of 100MB).
    assert!(
        !small_durations.is_empty(),
        "no downloads below {size_threshold} bytes in 1000 samples",
    );
    assert!(
        !large_durations.is_empty(),
        "no downloads above {size_threshold} bytes in 1000 samples",
    );

    let avg_small: f64 = small_durations.iter().sum::<i64>() as f64
        / small_durations.len() as f64;
    let avg_large: f64 = large_durations.iter().sum::<i64>() as f64
        / large_durations.len() as f64;

    assert!(
        avg_large > avg_small,
        "large files should have longer average download duration: \
         avg_small={avg_small:.1}s, avg_large={avg_large:.1}s",
    );
}

#[test]
fn fuzz_download_every_risk_level() {
    let levels = [RiskLevel::Low, RiskLevel::Medium, RiskLevel::High, RiskLevel::Maximum];
    let ctx = GenerationContext::new();
    let generator = DownloadGenerator::new();

    for (idx, level) in levels.iter().enumerate() {
        let profile = profile_with(vec![InterestCategory::Technology], *level);
        let mut rng = seeded_rng(7000 + idx as u64);
        let result = generator.generate(&profile, &ctx, &mut rng);
        assert!(result.is_ok(), "risk level {:?} must not crash", level);
    }
}

#[test]
fn fuzz_download_roundtrip_serde() {
    let generator = DownloadGenerator::new();
    let profile = UserProfile::default();
    let ctx = GenerationContext::new();

    for seed in 0..200u64 {
        let mut rng = seeded_rng(seed);
        let artifact = generator.generate(&profile, &ctx, &mut rng).unwrap();
        let bytes = artifact.to_bytes().unwrap();
        let entry: DownloadEntry = serde_json::from_slice(&bytes).unwrap();
        let bytes2 = serde_json::to_vec(&entry).unwrap();
        let entry2: DownloadEntry = serde_json::from_slice(&bytes2).unwrap();
        assert_eq!(entry.url, entry2.url, "seed {seed}: URL roundtrip mismatch");
        assert_eq!(entry.filename, entry2.filename, "seed {seed}: filename roundtrip mismatch");
        assert_eq!(entry.size_bytes, entry2.size_bytes, "seed {seed}: size roundtrip mismatch");
    }
}

#[test]
fn fuzz_download_timestamps_in_past() {
    let generator = DownloadGenerator::new();
    let profile = UserProfile::default();
    let ctx = GenerationContext::new();

    for seed in 0..1000u64 {
        let mut rng = seeded_rng(seed);
        let artifact = generator.generate(&profile, &ctx, &mut rng).unwrap();
        let bytes = artifact.to_bytes().unwrap();
        let entry: DownloadEntry = serde_json::from_slice(&bytes).unwrap();
        // started_at and completed_at should both be in the past (or at now)
        // The generator uses context.now - days_ago for started_at,
        // then adds download_secs, so completed_at could slightly exceed
        // context.now for very large files started recently. Allow 1 day margin.
        let margin = chrono::Duration::days(1);
        assert!(
            entry.started_at <= ctx.now,
            "seed {seed}: started_at in the future: {} > {}",
            entry.started_at,
            ctx.now,
        );
        assert!(
            entry.completed_at <= ctx.now + margin,
            "seed {seed}: completed_at too far in the future: {} > {}",
            entry.completed_at,
            ctx.now + margin,
        );
    }
}
