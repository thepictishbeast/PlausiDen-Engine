//! Integration tests verifying cross-generator consistency across the comms crate.
//!
//! These tests exercise interactions *between* generators (contacts, calls, SMS,
//! email headers, calendar) rather than individual generator correctness.

use std::collections::HashSet;

use engine_comms::calendar::{CalendarEntry, CalendarGenerator, EventType};
use engine_comms::calls::{CallDirection, CallEntry, CallGenerator};
use engine_comms::contacts::{ContactEntry, ContactGenerator};
use engine_comms::email_headers::{EmailHeaderEntry, EmailHeaderGenerator};
use engine_comms::sms::{SmsEntry, SmsGenerator};
use engine_core::entropy::seeded_rng;
use engine_core::profile::UserProfile;
use engine_core::traits::{DataGenerator, GenerationContext};

fn default_ctx() -> (UserProfile, GenerationContext) {
    (UserProfile::default(), GenerationContext::new())
}

// ---------------------------------------------------------------------------
// 1. Contacts and calls use overlapping phone numbers
//    (calls draw from a fixed pool; contacts generate random numbers --
//     this test verifies calls always come from the known pool)
// ---------------------------------------------------------------------------

/// The same phone pool embedded in `calls.rs` and `sms.rs`.
const KNOWN_PHONE_POOL: &[&str] = &[
    "(202) 555-0147", "(312) 555-0198", "(415) 555-0123", "(718) 555-0176",
    "(213) 555-0134", "(305) 555-0189", "(404) 555-0156", "(617) 555-0112",
    "(503) 555-0167", "(512) 555-0143", "(206) 555-0178", "(303) 555-0121",
    "(614) 555-0195", "(704) 555-0132", "(919) 555-0187", "(602) 555-0154",
    "(480) 555-0116", "(816) 555-0169", "(314) 555-0141", "(612) 555-0193",
    "(913) 555-0128", "(408) 555-0185", "(510) 555-0152", "(916) 555-0117",
    "(720) 555-0163", "(469) 555-0139", "(972) 555-0191", "(678) 555-0126",
    "(770) 555-0183", "(407) 555-0148", "(813) 555-0114", "(757) 555-0165",
];

#[test]
fn test_calls_use_phone_pool_numbers() {
    let pool_set: HashSet<&str> = KNOWN_PHONE_POOL.iter().copied().collect();
    let (profile, ctx) = default_ctx();
    let call_gen = CallGenerator::new();
    let contact_gen = ContactGenerator::new();
    let mut rng = seeded_rng(42);

    // Generate some contacts to build a phone book.
    let mut contact_phones: HashSet<String> = HashSet::new();
    for _ in 0..200 {
        let a = contact_gen.generate(&profile, &ctx, &mut rng).unwrap();
        let bytes = a.to_bytes().unwrap();
        let entry: ContactEntry = serde_json::from_slice(&bytes).unwrap();
        contact_phones.insert(entry.phone.clone());
    }

    // Every call number must come from the known pool.
    for i in 0..500 {
        let a = call_gen.generate(&profile, &ctx, &mut rng).unwrap();
        let bytes = a.to_bytes().unwrap();
        let entry: CallEntry = serde_json::from_slice(&bytes).unwrap();
        assert!(
            pool_set.contains(entry.phone_number.as_str()),
            "call {i}: phone '{}' not in the known pool",
            entry.phone_number,
        );
    }
}

// ---------------------------------------------------------------------------
// 2. SMS sender/receiver are never the same number
// ---------------------------------------------------------------------------

#[test]
fn test_sms_sender_receiver_never_same() {
    let (profile, ctx) = default_ctx();
    let sms_gen = SmsGenerator::new();
    let mut rng = seeded_rng(77);

    for i in 0..1000 {
        let a = sms_gen.generate(&profile, &ctx, &mut rng).unwrap();
        let bytes = a.to_bytes().unwrap();
        let entry: SmsEntry = serde_json::from_slice(&bytes).unwrap();
        assert_ne!(
            entry.sender, entry.receiver,
            "SMS {i}: sender '{}' == receiver",
            entry.sender,
        );
    }
}

// ---------------------------------------------------------------------------
// 3. Email From addresses have proper RFC 2822 format (Name <email>)
// ---------------------------------------------------------------------------

#[test]
fn test_email_from_rfc2822_format() {
    let (profile, ctx) = default_ctx();
    let email_gen = EmailHeaderGenerator::new();
    let mut rng = seeded_rng(13);

    for i in 0..500 {
        let a = email_gen.generate(&profile, &ctx, &mut rng).unwrap();
        let bytes = a.to_bytes().unwrap();
        let entry: EmailHeaderEntry = serde_json::from_slice(&bytes).unwrap();

        // Must match "Display Name <local@domain>" pattern.
        let from = &entry.from;
        let open = from.find('<');
        let close = from.find('>');
        assert!(
            open.is_some() && close.is_some(),
            "email {i}: From '{}' missing angle brackets",
            from,
        );
        let open = open.unwrap();
        let close = close.unwrap();
        assert!(
            close > open,
            "email {i}: From '{}' has malformed angle brackets",
            from,
        );

        // Display name (before '<') should be non-empty.
        let display_name = from[..open].trim();
        assert!(
            !display_name.is_empty(),
            "email {i}: From '{}' has empty display name",
            from,
        );
        // Display name should contain a space (first + last name).
        assert!(
            display_name.contains(' '),
            "email {i}: From display name '{}' should contain first and last name",
            display_name,
        );

        // Address inside angle brackets must contain '@' and a domain with '.'.
        let addr = &from[open + 1..close];
        assert!(
            addr.contains('@'),
            "email {i}: From address '{}' missing '@'",
            addr,
        );
        let parts: Vec<&str> = addr.split('@').collect();
        assert_eq!(
            parts.len(),
            2,
            "email {i}: From address '{}' should have exactly one '@'",
            addr,
        );
        assert!(
            !parts[0].is_empty(),
            "email {i}: From address '{}' has empty local part",
            addr,
        );
        assert!(
            parts[1].contains('.'),
            "email {i}: From domain '{}' missing '.'",
            parts[1],
        );
    }
}

// ---------------------------------------------------------------------------
// 4. Calendar events with attendees have valid email addresses
// ---------------------------------------------------------------------------

#[test]
fn test_calendar_attendees_valid_emails() {
    let (profile, ctx) = default_ctx();
    let cal_gen = CalendarGenerator::new();
    let mut rng = seeded_rng(88);

    let mut events_with_attendees = 0u32;

    for i in 0..500 {
        let a = cal_gen.generate(&profile, &ctx, &mut rng).unwrap();
        let bytes = a.to_bytes().unwrap();
        let entry: CalendarEntry = serde_json::from_slice(&bytes).unwrap();

        if !entry.attendees.is_empty() {
            events_with_attendees += 1;
        }

        for (j, email) in entry.attendees.iter().enumerate() {
            assert!(
                email.contains('@'),
                "event {i} attendee {j}: '{}' missing '@'",
                email,
            );
            let parts: Vec<&str> = email.split('@').collect();
            assert_eq!(
                parts.len(),
                2,
                "event {i} attendee {j}: '{}' should have exactly one '@'",
                email,
            );
            assert!(
                !parts[0].is_empty(),
                "event {i} attendee {j}: '{}' has empty local part",
                email,
            );
            assert!(
                parts[1].contains('.'),
                "event {i} attendee {j}: domain '{}' missing '.'",
                parts[1],
            );
        }
    }

    assert!(
        events_with_attendees > 50,
        "expected many events with attendees across 500 events, got {}",
        events_with_attendees,
    );
}

// ---------------------------------------------------------------------------
// 5. Call durations: incoming/outgoing > 0, missed = 0
// ---------------------------------------------------------------------------

#[test]
fn test_call_duration_invariants() {
    let (profile, ctx) = default_ctx();
    let call_gen = CallGenerator::new();
    let mut rng = seeded_rng(55);

    let mut seen_incoming = false;
    let mut seen_outgoing = false;
    let mut seen_missed = false;

    for i in 0..1000 {
        let a = call_gen.generate(&profile, &ctx, &mut rng).unwrap();
        let bytes = a.to_bytes().unwrap();
        let entry: CallEntry = serde_json::from_slice(&bytes).unwrap();

        match entry.direction {
            CallDirection::Incoming => {
                seen_incoming = true;
                assert!(
                    entry.duration_secs > 0,
                    "call {i}: incoming call has zero duration",
                );
            }
            CallDirection::Outgoing => {
                seen_outgoing = true;
                assert!(
                    entry.duration_secs > 0,
                    "call {i}: outgoing call has zero duration",
                );
            }
            CallDirection::Missed => {
                seen_missed = true;
                assert_eq!(
                    entry.duration_secs, 0,
                    "call {i}: missed call has non-zero duration ({}s)",
                    entry.duration_secs,
                );
            }
        }
    }

    assert!(seen_incoming, "no incoming calls generated in 1000 entries");
    assert!(seen_outgoing, "no outgoing calls generated in 1000 entries");
    assert!(seen_missed, "no missed calls generated in 1000 entries");
}

// ---------------------------------------------------------------------------
// 6. Calendar all-day events span >= 23 hours
// ---------------------------------------------------------------------------

#[test]
fn test_calendar_all_day_span() {
    let (profile, ctx) = default_ctx();
    let cal_gen = CalendarGenerator::new();
    let mut rng = seeded_rng(200);

    let mut found_all_day = false;

    for i in 0..1000 {
        let a = cal_gen.generate(&profile, &ctx, &mut rng).unwrap();
        let bytes = a.to_bytes().unwrap();
        let entry: CalendarEntry = serde_json::from_slice(&bytes).unwrap();

        if entry.is_all_day {
            found_all_day = true;
            let span_hours = (entry.end_time - entry.start_time).num_hours();
            assert!(
                span_hours >= 23,
                "all-day event {i} ('{}'): spans only {} hours, expected >= 23",
                entry.title,
                span_hours,
            );
            // All-day events should be Birthday or Holiday.
            assert!(
                entry.event_type == EventType::Birthday
                    || entry.event_type == EventType::Holiday,
                "all-day event {i}: unexpected type {:?}",
                entry.event_type,
            );
        }
    }

    assert!(
        found_all_day,
        "no all-day events generated in 1000 entries",
    );
}

// ---------------------------------------------------------------------------
// 7. Contact creation dates span multiple months (not all created at once)
// ---------------------------------------------------------------------------

#[test]
fn test_contact_creation_dates_multi_month() {
    let (profile, ctx) = default_ctx();
    let contact_gen = ContactGenerator::new();
    let mut rng = seeded_rng(42);

    let mut months_seen: HashSet<(i32, u32)> = HashSet::new();

    for _ in 0..500 {
        let a = contact_gen.generate(&profile, &ctx, &mut rng).unwrap();
        let bytes = a.to_bytes().unwrap();
        let entry: ContactEntry = serde_json::from_slice(&bytes).unwrap();

        let year = entry.created_at.format("%Y").to_string().parse::<i32>().unwrap();
        let month = entry.created_at.format("%m").to_string().parse::<u32>().unwrap();
        months_seen.insert((year, month));
    }

    // Creation dates span up to 3 years, so we should see many distinct months.
    assert!(
        months_seen.len() >= 6,
        "contact creation dates should span at least 6 distinct year-months, got {}",
        months_seen.len(),
    );
}

// ---------------------------------------------------------------------------
// 8. 1000-entry stress test across all 5 generators
// ---------------------------------------------------------------------------

#[test]
fn test_stress_1000_entries_all_generators() {
    let (profile, ctx) = default_ctx();
    let contact_gen = ContactGenerator::new();
    let call_gen = CallGenerator::new();
    let sms_gen = SmsGenerator::new();
    let email_gen = EmailHeaderGenerator::new();
    let cal_gen = CalendarGenerator::new();
    let mut rng = seeded_rng(999);

    for i in 0..1000u64 {
        contact_gen
            .generate(&profile, &ctx, &mut rng)
            .unwrap_or_else(|e| panic!("contact {i}: {e}"))
            .validate_plausibility()
            .unwrap_or_else(|e| panic!("contact {i} plausibility: {e}"));

        call_gen
            .generate(&profile, &ctx, &mut rng)
            .unwrap_or_else(|e| panic!("call {i}: {e}"))
            .validate_plausibility()
            .unwrap_or_else(|e| panic!("call {i} plausibility: {e}"));

        sms_gen
            .generate(&profile, &ctx, &mut rng)
            .unwrap_or_else(|e| panic!("sms {i}: {e}"))
            .validate_plausibility()
            .unwrap_or_else(|e| panic!("sms {i} plausibility: {e}"));

        email_gen
            .generate(&profile, &ctx, &mut rng)
            .unwrap_or_else(|e| panic!("email {i}: {e}"))
            .validate_plausibility()
            .unwrap_or_else(|e| panic!("email {i} plausibility: {e}"));

        cal_gen
            .generate(&profile, &ctx, &mut rng)
            .unwrap_or_else(|e| panic!("calendar {i}: {e}"))
            .validate_plausibility()
            .unwrap_or_else(|e| panic!("calendar {i} plausibility: {e}"));
    }
}
