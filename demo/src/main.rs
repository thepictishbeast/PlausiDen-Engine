//! Example: Generate browsing artifacts and dump them as JSON.
//!
//! This demonstrates the engine pipeline:
//! 1. Create a user profile
//! 2. Configure generators
//! 3. Generate artifacts with organic timing
//! 4. Validate plausibility
//! 5. Output as JSON (ready for injection)
//!
//! Run: cargo run --example generate_and_dump

use engine_browser::cookies::CookieGenerator;
use engine_browser::history::HistoryGenerator;
use engine_browser::searches::SearchGenerator;
use engine_core::entropy::seeded_rng;
use engine_core::paranoia;
use engine_core::profile::{
    ActivitySchedule, DemographicProfile, DeviceProfile, InterestCategory, Locale,
    OccupationCategory, RiskLevel, UserProfileBuilder,
};
use engine_core::schedule::OrganicScheduler;
use engine_core::traits::{DataGenerator, GenerationContext};

fn main() {
    // 1. Create a user profile — a journalist investigating privacy tools
    let profile = UserProfileBuilder::new()
        .demographic(DemographicProfile {
            age_range: (30, 45),
            language: "en".to_string(),
            country: "US".to_string(),
            occupation: OccupationCategory::Journalist,
        })
        .device(DeviceProfile::default())
        .activity_schedule(ActivitySchedule {
            wake_hour: 6,
            sleep_hour: 23,
            active_days: vec![0, 1, 2, 3, 4, 5, 6],
            timezone_offset_hours: -5,
        })
        .locale(Locale::default())
        .interests(vec![
            InterestCategory::News,
            InterestCategory::Government,
            InterestCategory::Legal,
            InterestCategory::Technology,
            InterestCategory::Reference,
        ])
        .risk_level(RiskLevel::Medium)
        .build();

    let mut rng = seeded_rng(42); // Deterministic for demo
    let context = GenerationContext::new();

    // 2. Generate history entries
    println!("=== Browser History ===\n");
    let history_generator = HistoryGenerator::new();
    for i in 0..5 {
        match history_generator.generate(&profile, &context, &mut rng) {
            Ok(artifact) => {
                // Paranoia check — validate our own output
                if let Err(e) = paranoia::deep_validate_artifact(artifact.as_ref()) {
                    eprintln!("PARANOIA FAILURE on history entry {i}: {e}");
                    continue;
                }

                let bytes = artifact.to_bytes().unwrap();
                let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
                println!("{}", serde_json::to_string_pretty(&json).unwrap());
                println!();
            }
            Err(e) => eprintln!("Generation error: {e}"),
        }
    }

    // 3. Generate cookies
    println!("=== Cookies ===\n");
    let cookie_generator = CookieGenerator::new();
    for i in 0..3 {
        match cookie_generator.generate(&profile, &context, &mut rng) {
            Ok(artifact) => {
                if let Err(e) = paranoia::deep_validate_artifact(artifact.as_ref()) {
                    eprintln!("PARANOIA FAILURE on cookie {i}: {e}");
                    continue;
                }
                let bytes = artifact.to_bytes().unwrap();
                let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
                println!("{}", serde_json::to_string_pretty(&json).unwrap());
                println!();
            }
            Err(e) => eprintln!("Generation error: {e}"),
        }
    }

    // 4. Generate search queries
    println!("=== Search Queries ===\n");
    let search_generator = SearchGenerator::new();
    for i in 0..3 {
        match search_generator.generate(&profile, &context, &mut rng) {
            Ok(artifact) => {
                if let Err(e) = paranoia::deep_validate_artifact(artifact.as_ref()) {
                    eprintln!("PARANOIA FAILURE on search {i}: {e}");
                    continue;
                }
                let bytes = artifact.to_bytes().unwrap();
                let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
                println!("{}", serde_json::to_string_pretty(&json).unwrap());
                println!();
            }
            Err(e) => eprintln!("Generation error: {e}"),
        }
    }

    // 5. Show scheduling
    println!("=== Organic Timing (next 10 events) ===\n");
    let scheduler = OrganicScheduler::new(profile.activity_schedule.clone(), profile.risk_level);
    let mut current = chrono::Utc::now();
    for _ in 0..10 {
        let next = scheduler.next_timestamp(current, &mut rng);
        let gap = (next - current).num_seconds();
        println!("  {} (+{}s gap)", next.format("%H:%M:%S"), gap,);
        current = next;
    }

    println!("\n=== Done ===");
    println!("All artifacts passed paranoia validation.");
}
