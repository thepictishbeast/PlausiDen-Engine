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
