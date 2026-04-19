//! `journalist_deadman` — runnable composition example.
//!
//! Demonstrates how the three engine-core security primitives
//! (`erasure`, `duress`, `deadman`) compose into a realistic
//! scenario: a journalist configures protections that fire if they
//! fail to check in, or if they are compelled to type a passphrase
//! under duress.
//!
//! Run with:
//!
//!     cargo run --example journalist_deadman -p engine-core
//!
//! This is NOT a library entry point — it is user-facing documentation
//! that happens to be a program, so you can read it top-to-bottom and
//! copy patterns into your own integration. Every step prints a
//! narrated line so the flow is visible on stdout.
//!
//! What the example does NOT do:
//!
//! - It does not hash passphrases with a real KDF; the module comment
//!   on `duress::verify` states the caller supplies the hash. In
//!   production, use Argon2id or scrypt.
//! - It does not integrate with `plausiden-inject` or the Sentinel
//!   daemon — the example reads as a pure decision flow; in Desktop
//!   (Tier 2) those actions would be dispatched via the host
//!   `commands.rs`.
//! - It does not generate a real Ed25519 signing key from secure
//!   entropy for the receipt — it uses `SigningKey::generate(rng)` with
//!   a seeded ChaCha20 RNG for reproducibility. In production, use
//!   `OsRng`.

use engine_core::deadman::{self, DeadmanConfig, DeadmanStatus, TriggerAction};
use engine_core::duress::{
    self, DuressConfig, DuressEntry, DuressResponse, VerifyOutcome,
};
use engine_core::erasure::{ErasableKey, ErasureReason, KeyId};
use ed25519_dalek::SigningKey;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;

fn main() {
    println!("=== Journalist's deadman: engine-core composition demo ===\n");

    // ---------------------------------------------------------------
    // 1. A device key we want to erase on either duress or deadman fire.
    // ---------------------------------------------------------------
    let device_key = ErasableKey::new_in_memory([0x42; 32])
        .expect("journalist_deadman: in-memory ErasableKey must construct on a dev machine");
    let key_id: KeyId = device_key.id.clone();
    println!("[1] Created device key id={:?}", key_id);

    // An Ed25519 signing key is used to sign ErasureReceipts so the
    // journalist (or their lawyer) can later prove when + why the
    // key was destroyed. Seeded RNG here for the example's
    // reproducibility — DO NOT do this in production; use OsRng.
    let mut seed = ChaCha20Rng::seed_from_u64(0xdead_beef);
    let signing_key = SigningKey::generate(&mut seed);
    let verifying_key = signing_key.verifying_key();
    println!("[1] Signing key generated (verifying half kept for later receipt audit)\n");

    // ---------------------------------------------------------------
    // 2. Duress configuration: real + one duress passphrase that,
    //    when typed, silently erases the device key. The attacker
    //    sees "unlocked" timing either way.
    // ---------------------------------------------------------------
    //
    // In production, these bytes are KDF output (Argon2id of the typed
    // passphrase). Here we shortcut to literal bytes for the demo.
    let real_hash = b"HASH_OF_REAL_PASSPHRASE".to_vec();
    let duress_hash = b"HASH_OF_DURESS_PASSPHRASE".to_vec();

    let duress_cfg = DuressConfig {
        real_hash: real_hash.clone(),
        duress: vec![DuressEntry {
            hash: duress_hash.clone(),
            response: DuressResponse::SilentErase {
                key_ids: vec![key_id.clone()],
            },
            label: Some("under-coercion unlock".into()),
        }],
    };
    println!("[2] Duress config: 1 real + 1 duress passphrase configured");
    println!("    Duress response: SilentErase({:?})\n", key_id);

    // Normal unlock — returns Real. No side-effect.
    let out = duress::verify(&duress_cfg, &real_hash).expect("verify");
    assert!(matches!(out, VerifyOutcome::Real));
    println!("[2a] Normal unlock → VerifyOutcome::Real (no erase triggered)");

    // Duress unlock — returns Duress(SilentErase{...}). Caller fires
    // the response; attacker sees identical timing.
    let out = duress::verify(&duress_cfg, &duress_hash).expect("verify");
    match out {
        VerifyOutcome::Duress(DuressResponse::SilentErase { key_ids }) => {
            println!("[2b] Duress unlock → VerifyOutcome::Duress(SilentErase)");
            println!("     Host would now call ErasableKey::erase() on: {:?}\n", key_ids);
        }
        other => panic!("example expected Duress(SilentErase), got {other:?}"),
    }

    // Unknown passphrase — returns NoMatch with the same wall-clock timing.
    let out = duress::verify(&duress_cfg, b"random-guess").expect("verify");
    assert!(matches!(out, VerifyOutcome::NoMatch));
    println!("[2c] Wrong passphrase → VerifyOutcome::NoMatch (identical timing)\n");

    // ---------------------------------------------------------------
    // 3. Dead-man switch: if the journalist doesn't check in for
    //    24h, fire a Composite action — EraseKey + AlertContacts.
    // ---------------------------------------------------------------
    let mut deadman_cfg = DeadmanConfig {
        dead_seconds: 24 * 3600,     // 24h silence → fire
        warning_seconds: 4 * 3600,   // 4h before: warn user
        action: TriggerAction::Composite(vec![
            TriggerAction::EraseKey {
                key_ids: vec![key_id.clone()],
            },
            TriggerAction::AlertContacts {
                channels: vec!["signal://+15555551234".into()],
            },
        ]),
        last_checkin_unix: 0,
        armed: false,
    };

    let t0 = 1_700_000_000i64;   // a fixed "now" for the demo.
    deadman_cfg.arm(t0);
    println!("[3] Deadman armed at t0={} (dead_seconds=86400, warn_seconds=14400)", t0);

    // Hour 1: Fresh (nothing to do).
    match deadman::evaluate(&deadman_cfg, t0 + 3_600) {
        DeadmanStatus::Fresh => println!("[3a] t0+1h → Fresh (silent, no action)"),
        other => panic!("expected Fresh, got {other:?}"),
    }

    // Hour 21: Warning (under 4h remain). Host should nudge the user.
    match deadman::evaluate(&deadman_cfg, t0 + 21 * 3_600) {
        DeadmanStatus::Warning { remaining } => {
            println!("[3b] t0+21h → Warning (remaining={}s) — UI should prompt check-in", remaining);
        }
        other => panic!("expected Warning, got {other:?}"),
    }

    // Hour 25: Fire. Host MUST execute the action.
    match deadman::evaluate(&deadman_cfg, t0 + 25 * 3_600) {
        DeadmanStatus::Fire { late_by, action } => {
            println!("[3c] t0+25h → Fire (late_by={}s)", late_by);
            println!("     Action to dispatch: {:?}\n", action);
        }
        other => panic!("expected Fire, got {other:?}"),
    }

    // ---------------------------------------------------------------
    // 4. Actually erase the key + sign the receipt.
    // ---------------------------------------------------------------
    let erased_at = t0 + 25 * 3_600;
    let receipt = device_key.erase(ErasureReason::Deadman).expect("erasure");
    // In production the host would have collected `key_id` + erase time
    // from the erased device_key in step 1, then signed the receipt with
    // its long-lived signing key. ErasureReceipt::sign handles that.
    let signed = engine_core::erasure::ErasureReceipt::sign(
        receipt.key_id.clone(),
        erased_at,
        receipt.reason,
        &signing_key,
    );

    signed
        .verify_with(&verifying_key)
        .expect("receipt must verify with our verifying key");
    println!("[4] Key erased; signed receipt verifies OK");
    println!("    receipt.key_id={:?}", signed.key_id);
    println!("    receipt.reason={:?}", signed.reason);
    println!("    receipt.erased_at={}\n", signed.erased_at);

    println!("=== Demo complete — all primitives composed successfully. ===");
}
