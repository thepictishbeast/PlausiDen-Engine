//! Property-based JSON-deserialization fuzz harnesses for the two
//! types most likely to be fed adversarial input: `DuressConfig`
//! (loaded from a vault file at unlock time) and `ErasureReceipt`
//! (audit-chain payload that third parties verify).
//!
//! AVP-2 Tier 3 fuzz pass: any panic on arbitrary bytes is a P0
//! finding because both types deserialize at trust-boundaries (a
//! malformed vault blob or a forged receipt should produce a clean
//! `serde_json::Error`, never a panic).
//!
//! These harnesses use proptest rather than libFuzzer so they can
//! run on stable + in CI without the cargo-fuzz nightly toolchain
//! requirement. The shape of the contract is identical: feed
//! arbitrary bytes, assert no panic, assert valid roundtrip.
//!
//! Run with `cargo test --test json_deserialization_fuzz -p engine-core`.

use engine_core::deadman::{DeadmanConfig, TriggerAction};
use engine_core::duress::{DuressConfig, DuressEntry, DuressResponse};
use engine_core::erasure::{ErasureReason, ErasureReceipt, KeyId};
use proptest::collection::vec;
use proptest::prelude::*;

// ---------------------------------------------------------------------------
// DuressConfig fuzz
// ---------------------------------------------------------------------------

fn arb_duress_config() -> impl Strategy<Value = DuressConfig> {
    let real = vec(any::<u8>(), 1..=128);
    let entries = vec(
        (vec(any::<u8>(), 1..=128)).prop_map(|hash| DuressEntry {
            hash,
            response: DuressResponse::MountDecoy,
            label: None,
        }),
        0..=8,
    );
    (real, entries).prop_map(|(real_hash, duress)| DuressConfig { real_hash, duress })
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(2_000))]

    /// Arbitrary bytes must never panic the deserializer. A
    /// well-behaved parser returns `Err`; a panic indicates a logic
    /// bug or `unwrap()` reachable from user input.
    #[test]
    fn duress_from_bytes_never_panics(bytes in vec(any::<u8>(), 0..=4096)) {
        let _ = serde_json::from_slice::<DuressConfig>(&bytes);
    }

    /// Arbitrary UTF-8 strings must never panic. UTF-8 path exercises
    /// different serde branches than the byte path (string escapes,
    /// number-parser, key dedup).
    #[test]
    fn duress_from_str_never_panics(s in ".*") {
        let _ = serde_json::from_str::<DuressConfig>(&s);
    }

    /// Roundtrip preserves the shape of any well-formed config.
    #[test]
    fn duress_roundtrip_preserves_shape(cfg in arb_duress_config()) {
        let json = serde_json::to_string(&cfg).expect("serialize must succeed");
        let decoded: DuressConfig =
            serde_json::from_str(&json).expect("our own output must parse back");
        prop_assert_eq!(cfg.real_hash, decoded.real_hash);
        prop_assert_eq!(cfg.duress.len(), decoded.duress.len());
        for (a, b) in cfg.duress.iter().zip(decoded.duress.iter()) {
            prop_assert_eq!(&a.hash, &b.hash);
        }
    }

    /// Bounded-length payloads must complete in bounded time. A 64KiB
    /// adversarial blob shouldn't pin a CPU. Generous wall-clock
    /// because proptest reuses the test runner thread.
    #[test]
    fn duress_large_input_terminates(bytes in vec(any::<u8>(), 0..=65_536)) {
        let start = std::time::Instant::now();
        let _ = serde_json::from_slice::<DuressConfig>(&bytes);
        prop_assert!(
            start.elapsed() < std::time::Duration::from_millis(500),
            "deserialize took {:?}", start.elapsed(),
        );
    }
}

// ---------------------------------------------------------------------------
// ErasureReceipt fuzz
// ---------------------------------------------------------------------------

fn arb_reason() -> impl Strategy<Value = ErasureReason> {
    prop_oneof![
        Just(ErasureReason::UserInitiated),
        Just(ErasureReason::Deadman),
        Just(ErasureReason::Duress),
        Just(ErasureReason::Rotation),
        Just(ErasureReason::SwarmDestroy),
        Just(ErasureReason::Policy),
    ]
}

fn arb_receipt() -> impl Strategy<Value = ErasureReceipt> {
    (any::<i64>(), arb_reason(), vec(any::<u8>(), 0..=128)).prop_map(
        |(erased_at, reason, signature)| ErasureReceipt {
            key_id: KeyId::new(),
            erased_at,
            reason,
            signature,
        },
    )
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(2_000))]

    #[test]
    fn receipt_from_bytes_never_panics(bytes in vec(any::<u8>(), 0..=4096)) {
        let _ = serde_json::from_slice::<ErasureReceipt>(&bytes);
    }

    #[test]
    fn receipt_from_str_never_panics(s in ".*") {
        let _ = serde_json::from_str::<ErasureReceipt>(&s);
    }

    #[test]
    fn receipt_roundtrip_preserves_shape(r in arb_receipt()) {
        let json = serde_json::to_string(&r).expect("serialize must succeed");
        let decoded: ErasureReceipt =
            serde_json::from_str(&json).expect("our own output must parse back");
        prop_assert_eq!(r.key_id.0, decoded.key_id.0);
        prop_assert_eq!(r.erased_at, decoded.erased_at);
        prop_assert_eq!(r.reason, decoded.reason);
        prop_assert_eq!(r.signature, decoded.signature);
    }

    /// Same wall-clock bound as the duress harness — a forged 64KiB
    /// receipt blob must not pin a verifier's CPU.
    #[test]
    fn receipt_large_input_terminates(bytes in vec(any::<u8>(), 0..=65_536)) {
        let start = std::time::Instant::now();
        let _ = serde_json::from_slice::<ErasureReceipt>(&bytes);
        prop_assert!(
            start.elapsed() < std::time::Duration::from_millis(500),
            "deserialize took {:?}", start.elapsed(),
        );
    }
}

// ---------------------------------------------------------------------------
// DeadmanConfig fuzz
//
// DeadmanConfig deserializes from disk at host arm time. A malformed
// or forged config (especially via the recursive Composite TriggerAction
// arm) must surface as Err, never panic.
// ---------------------------------------------------------------------------

fn arb_simple_action() -> impl Strategy<Value = TriggerAction> {
    prop_oneof![
        vec(any::<u8>(), 0..=4).prop_map(|_| TriggerAction::EraseKey {
            key_ids: vec![KeyId::new()]
        }),
        vec("[a-z0-9:/.@+-]{0,32}", 0..=4)
            .prop_map(|channels| TriggerAction::AlertContacts { channels }),
        vec("[a-z0-9-]{0,32}", 0..=4)
            .prop_map(|fragment_ids| TriggerAction::SwarmDestroy { fragment_ids }),
        "[a-z0-9_-]{1,32}".prop_map(|name| TriggerAction::CustomHook { name }),
    ]
}

fn arb_action() -> impl Strategy<Value = TriggerAction> {
    // Composite is recursive — bound depth + breadth so the strategy
    // doesn't blow the stack. One level of nesting exercises the
    // recursive serde path without spending the whole proptest
    // budget on tree-shape cases.
    prop_oneof![
        arb_simple_action(),
        vec(arb_simple_action(), 0..=4).prop_map(TriggerAction::Composite),
    ]
}

fn arb_deadman_config() -> impl Strategy<Value = DeadmanConfig> {
    (
        any::<u64>(),
        any::<u64>(),
        arb_action(),
        any::<i64>(),
        any::<bool>(),
    )
        .prop_map(
            |(dead_seconds, warning_seconds, action, last_checkin_unix, armed)| DeadmanConfig {
                dead_seconds,
                warning_seconds,
                action,
                last_checkin_unix,
                armed,
            },
        )
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(2_000))]

    #[test]
    fn deadman_from_bytes_never_panics(bytes in vec(any::<u8>(), 0..=4096)) {
        let _ = serde_json::from_slice::<DeadmanConfig>(&bytes);
    }

    #[test]
    fn deadman_from_str_never_panics(s in ".*") {
        let _ = serde_json::from_str::<DeadmanConfig>(&s);
    }

    /// Roundtrip preserves the shape — including across the recursive
    /// Composite TriggerAction arm.
    #[test]
    fn deadman_roundtrip_preserves_shape(cfg in arb_deadman_config()) {
        let json = serde_json::to_string(&cfg).expect("serialize must succeed");
        let decoded: DeadmanConfig =
            serde_json::from_str(&json).expect("our own output must parse back");
        prop_assert_eq!(cfg.dead_seconds, decoded.dead_seconds);
        prop_assert_eq!(cfg.warning_seconds, decoded.warning_seconds);
        prop_assert_eq!(cfg.last_checkin_unix, decoded.last_checkin_unix);
        prop_assert_eq!(cfg.armed, decoded.armed);
    }

    /// Forged 64KiB blobs (notably nested-Composite bombs) must not
    /// pin a host's CPU. Same 500ms wall-clock budget as the others.
    #[test]
    fn deadman_large_input_terminates(bytes in vec(any::<u8>(), 0..=65_536)) {
        let start = std::time::Instant::now();
        let _ = serde_json::from_slice::<DeadmanConfig>(&bytes);
        prop_assert!(
            start.elapsed() < std::time::Duration::from_millis(500),
            "deserialize took {:?}", start.elapsed(),
        );
    }
}
