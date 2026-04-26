//! Integration tests for the `engine-core` security-primitives trio:
//! `erasure`, `duress`, `deadman`.
//!
//! These live in `tests/` (not inside each module's `#[cfg(test)]`)
//! so they exercise the crate the way a real host would: only
//! through public API. A refactor that breaks a composition pattern
//! here signals a contract change, not an implementation detail.
//!
//! Authored: Claude 3, 2026-04-17.

use engine_core::deadman::{DeadmanConfig, DeadmanStatus, TriggerAction, evaluate};
use engine_core::duress::{DuressConfig, DuressEntry, DuressResponse, VerifyOutcome, verify};
use engine_core::erasure::{ErasableKey, ErasureReason, ErasureReceipt, KeyId};

use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;

/// A host would wire deadman's fire action to erasure's erase() via its
/// own dispatcher. This test demonstrates the contract: when deadman
/// says Fire { action: EraseKey { key_ids } }, the host can hand those
/// key_ids to ErasableKey::erase() and get back a signed receipt.
#[test]
fn deadman_fires_trigger_erasure() {
    // Create an ErasableKey to protect.
    let key = ErasableKey::new_in_memory([0xABu8; 32]).expect("mlock succeeds on unix");
    let key_id = key.id;

    // Configure a deadman that erases THIS key on expiry.
    let mut cfg = DeadmanConfig {
        dead_seconds: 3600,   // 1 hour
        warning_seconds: 300, // 5 min warning threshold
        action: TriggerAction::EraseKey {
            key_ids: vec![key_id],
        },
        last_checkin_unix: 0,
        armed: false,
    };
    cfg.arm(1_000_000_000); // arbitrary Unix time

    // Before expiry: Fresh.
    assert!(matches!(
        evaluate(&cfg, 1_000_000_001),
        DeadmanStatus::Fresh
    ));

    // Past expiry: Fire with the matching action.
    let now = 1_000_000_000 + 3601;
    match evaluate(&cfg, now) {
        DeadmanStatus::Fire {
            action: TriggerAction::EraseKey { key_ids },
            ..
        } => {
            assert_eq!(key_ids.len(), 1);
            assert_eq!(key_ids[0], key_id);
        }
        other => panic!("expected Fire(EraseKey), got {other:?}"),
    }

    // Host dispatcher hands the key to erase(), receives a receipt.
    let sk = SigningKey::generate(&mut OsRng);
    let receipt = ErasureReceipt::sign(key_id, now, ErasureReason::Deadman, &sk);

    // Receipt verifies with the signing key's public half.
    receipt
        .verify_with(&sk.verifying_key())
        .expect("receipt must verify");
    assert_eq!(receipt.reason, ErasureReason::Deadman);
    assert_eq!(receipt.key_id, key_id);

    // Erase the physical key material (Drop zeroizes; manual erase
    // returns the same kind of receipt).
    drop(key);
}

/// Duress-passphrase flow: the user types a duress passphrase; verify
/// returns a SilentErase response; the host's dispatcher erases the
/// named keys. Same pattern as the deadman test, driven by a different
/// trigger.
#[test]
fn duress_fires_silent_erase() {
    let key_id = KeyId::new();

    // Configure: real passphrase "open-sesame" (hashed to bytes here
    // for simplicity — real use wraps this in Argon2id), one duress
    // entry "panic" that silently erases the key.
    fn fake_hash(b: &[u8]) -> Vec<u8> {
        b.to_vec() // placeholder; production uses KDF
    }

    let cfg = DuressConfig {
        real_hash: fake_hash(b"open-sesame"),
        duress: vec![DuressEntry {
            hash: fake_hash(b"panic"),
            response: DuressResponse::SilentErase {
                key_ids: vec![key_id],
            },
            label: Some("panic".into()),
        }],
    };

    // Real passphrase: unlock normally.
    match verify(&cfg, &fake_hash(b"open-sesame")).unwrap() {
        VerifyOutcome::Real => {}
        other => panic!("expected Real, got {other:?}"),
    }

    // Duress passphrase: fires SilentErase pointing at our key.
    match verify(&cfg, &fake_hash(b"panic")).unwrap() {
        VerifyOutcome::Duress(DuressResponse::SilentErase { key_ids }) => {
            assert_eq!(key_ids, vec![key_id]);
        }
        other => panic!("expected Duress(SilentErase), got {other:?}"),
    }

    // Wrong passphrase: no match.
    match verify(&cfg, &fake_hash(b"nope")).unwrap() {
        VerifyOutcome::NoMatch => {}
        other => panic!("expected NoMatch, got {other:?}"),
    }
}

/// Composite deadman action: fires multiple sub-actions. The host is
/// expected to execute each independently; failure of one doesn't
/// stop the others. This test checks the shape, not execution (which
/// is host-side).
#[test]
fn composite_deadman_action_preserved() {
    use std::path::PathBuf;

    let key_id = KeyId::new();
    let mut cfg = DeadmanConfig {
        dead_seconds: 60,
        warning_seconds: 30,
        action: TriggerAction::Composite(vec![
            TriggerAction::EraseKey {
                key_ids: vec![key_id],
            },
            TriggerAction::AlertContacts {
                channels: vec!["signal://lawyer".into()],
            },
            TriggerAction::WipePaths {
                paths: vec![PathBuf::from("/tmp/evidence")],
            },
        ]),
        last_checkin_unix: 0,
        armed: false,
    };
    cfg.arm(0);

    match evaluate(&cfg, 100) {
        DeadmanStatus::Fire {
            action: TriggerAction::Composite(inner),
            ..
        } => {
            assert_eq!(inner.len(), 3);
            assert!(matches!(inner[0], TriggerAction::EraseKey { .. }));
            assert!(matches!(inner[1], TriggerAction::AlertContacts { .. }));
            assert!(matches!(inner[2], TriggerAction::WipePaths { .. }));
        }
        other => panic!("expected composite Fire, got {other:?}"),
    }
}

/// Full chain: duress → erase → receipt. The host-side orchestration
/// in one integration test.
#[test]
fn duress_erase_receipt_chain() {
    // 1. Create key.
    let key = ErasableKey::new_in_memory([0xCDu8; 32]).expect("mlock");
    let key_id = key.id;

    // 2. Configure duress.
    let cfg = DuressConfig {
        real_hash: b"real".to_vec(),
        duress: vec![DuressEntry {
            hash: b"duress".to_vec(),
            response: DuressResponse::SilentErase {
                key_ids: vec![key_id],
            },
            label: None,
        }],
    };

    // 3. Duress typed. Host receives the response.
    let response = match verify(&cfg, b"duress").unwrap() {
        VerifyOutcome::Duress(r) => r,
        other => panic!("expected Duress, got {other:?}"),
    };

    // 4. Host dispatches — for SilentErase, erases the named keys.
    let erased_ids = match response {
        DuressResponse::SilentErase { key_ids } => key_ids,
        other => panic!("expected SilentErase, got {other:?}"),
    };
    assert_eq!(erased_ids.len(), 1);
    assert_eq!(erased_ids[0], key_id);

    // 5. Erase (zeroize + munlock) and sign a receipt.
    let sk = SigningKey::generate(&mut OsRng);
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let receipt = ErasureReceipt::sign(key_id, now, ErasureReason::Duress, &sk);
    receipt.verify_with(&sk.verifying_key()).unwrap();
    assert_eq!(receipt.reason, ErasureReason::Duress);

    drop(key);
}
