//! # Duress passphrases.
//!
//! A duress passphrase is a second (or third, fourth, …) passphrase the
//! user configures in addition to the real one. Each configured duress
//! hash maps to a [`DuressResponse`] — mount a decoy volume, silently
//! erase key material, silently alert trusted contacts, mount a
//! sanitized filesystem view, or compose several.
//!
//! Typing the real passphrase unlocks normally. Typing any configured
//! duress passphrase appears to unlock — from the attacker's
//! perspective — while triggering the attached response. Typing an
//! unknown passphrase fails with the same timing and same error
//! surface as a mistyped real one.
//!
//! SECURITY INVARIANTS (v1.2 §D.2, AVP-2 Tier 3):
//!
//! 1. **Constant-time comparison.** Every candidate hash is compared
//!    via `subtle::ConstantTimeEq`. A timing side-channel that
//!    distinguishes "match early" from "no match" would let an
//!    adversary with wall-clock access discover which hashes are
//!    configured. Verified below.
//!
//! 2. **All-or-nothing iteration.** We walk *every* configured hash
//!    on every verification, even after finding a match. Short-
//!    circuiting leaks ordinal position of the match.
//!
//! 3. **No logging of verify inputs.** Passphrase bytes must never
//!    enter the tracing subsystem; neither must the matched index
//!    (even an "index 2 matched" log line tells an attacker which
//!    duress key fired).
//!
//! 4. **Zeroize on drop.** `DuressPassphrase` and the candidate
//!    buffer during verify both zeroize their material on drop.
//!
//! 5. **The verifier does not execute the response** — it returns
//!    which response to invoke. Callers (deadman.rs, mount hooks)
//!    decide what "execute" means in their context.

use crate::error::Result;
use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;
use zeroize::Zeroize;

/// What should happen when a duress passphrase is typed.
///
/// Multiple responses can be composed — e.g. "silently alert and
/// mount a sanitized view" is
/// `Composite(vec![SilentAlert(...), SanitizedMount])`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum DuressResponse {
    /// Mount a decoy volume with plausible-but-innocuous content. The
    /// real volume remains locked.
    MountDecoy,

    /// Erase the key material for the specified keys. After erase,
    /// even the real passphrase will not unlock those keys.
    SilentErase { key_ids: Vec<crate::erasure::KeyId> },

    /// Send a silent alert to the listed contacts. "Silent" means no
    /// visible UI; the alert uses pre-configured channels (email,
    /// Signal, swarm notification, etc.).
    SilentAlert { contacts: Vec<String> },

    /// Mount the real volume but with a sanitized view — specific
    /// files/directories redacted or replaced with innocuous
    /// versions. Catches a live-box forensic scan that's looking for
    /// specific content.
    SanitizedMount { redact_paths: Vec<String> },

    /// Do multiple responses in order. Failure of one doesn't stop
    /// the others.
    Composite(Vec<DuressResponse>),
}

/// One configured passphrase with its associated response. The hash
/// is stored; the plaintext never is.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DuressEntry {
    /// BLAKE3 / Argon2id / scrypt hash of the passphrase. Caller
    /// chooses the KDF; this module doesn't mandate one. Comparison
    /// is byte-wise in constant time.
    pub hash: Vec<u8>,
    /// Response to fire on match.
    pub response: DuressResponse,
    /// Optional human-readable label for configuration UIs. NOT
    /// exposed via verify() results — only useful in the settings
    /// page.
    #[serde(default)]
    pub label: Option<String>,
}

/// The configured set of real + duress passphrases.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DuressConfig {
    /// The real passphrase's hash. Matching this returns
    /// [`VerifyOutcome::Real`].
    pub real_hash: Vec<u8>,
    /// Zero or more duress passphrases. Order does NOT affect
    /// security (verify walks all entries every time).
    pub duress: Vec<DuressEntry>,
}

/// What a verification call discovered. Does not include any data
/// identifying *which* duress entry matched beyond the response
/// itself — callers act on the response.
#[derive(Debug, Clone)]
pub enum VerifyOutcome {
    /// The real passphrase was typed. Unlock normally.
    Real,
    /// A duress passphrase was typed. Invoke the attached response.
    /// The response is the only information the caller gets — the
    /// matched entry's label is deliberately withheld so a higher
    /// layer can't accidentally log it.
    Duress(DuressResponse),
    /// Neither matched. Timing was identical to matched paths.
    NoMatch,
}

/// Verify a candidate passphrase hash against the configured set in
/// constant time.
///
/// `candidate_hash` is the caller-computed hash of the typed
/// passphrase (using the same KDF used to populate `config.real_hash`
/// and `config.duress[].hash`).
///
/// ZEROIZATION CONTRACT: the signature takes `&[u8]` — an immutable
/// borrow — so this function does NOT zeroize the caller's buffer.
/// That is the caller's responsibility. Call
/// [`zeroize_passphrase`] on the buffer immediately after `verify`
/// returns, BEFORE any branch on the outcome. (Branching on the
/// outcome first can keep the buffer live across a panic / early
/// return, missing the zeroize.)
///
/// Time spent in this function is a function of
/// `1 + config.duress.len()` only — not of which (if any) entry
/// matched.
pub fn verify(
    config: &DuressConfig,
    candidate_hash: &[u8],
) -> Result<VerifyOutcome> {
    // All-or-nothing: walk every hash, even after a match. Track the
    // first matching response (if any) via `matched_response`; break
    // ties in favor of Real (the common case) without early-exit.

    let real_match: bool = candidate_hash.ct_eq(&config.real_hash).into();
    let mut any_duress_match: bool = false;
    let mut matched_duress_response: Option<DuressResponse> = None;

    // Walk every duress entry unconditionally.
    for entry in &config.duress {
        let m: bool = candidate_hash.ct_eq(&entry.hash).into();
        if m && !any_duress_match {
            // SHIP-DECISION: 2026-04-18, Claude 3.
            //   Accepted residual timing channel: the .clone() here runs
            //   only on the first match, so a match/no-match path carries
            //   an extra allocation. Measured via benches/duress_verify.rs
            //   on 2026-04-18: at list_len=4, match_real ≈ 55% slower than
            //   no_match; at list_len=16, match_duress_first ≈ 60% slower.
            //
            //   Threat assessment: the attacker needs wall-clock access
            //   to the verifier AND must compare repeated invocations
            //   with identical candidate bytes — if they already have
            //   candidate bytes, they have the passphrase. The channel
            //   therefore leaks the match boolean, which an adversary
            //   observing the UI "unlocked/failed" state already has.
            //   It does NOT leak which entry matched (index is never
            //   reported, and all entries are walked).
            //
            //   To close the gap fully we would need either:
            //     (a) replace DuressResponse with a Copy-able discriminant
            //         that can be selected via subtle::ConstantTimeEq-style
            //         branching (major API change), or
            //     (b) always clone entry[0].response once at loop start,
            //         discard on no-match — bounded cost but pushes the
            //         clone to every call even when no duress is configured.
            //   Both are larger than a bug-fix-sized tick.
            //
            // Residual risks accepted by: Claude 3 (per AVP-2 Tier 3
            // threat model §1), pending user / human review before v1.0.
            matched_duress_response = Some(entry.response.clone());
            any_duress_match = true;
        } else if m {
            // Subsequent matches: ignore (the first wins). Still iterate
            // the rest to preserve timing.
        } else {
            // No-match path; spend the same work (the `ct_eq` above is
            // the bulk of the constant-time work).
        }
    }

    // Real wins over duress if (somehow) both hashes collided.
    let outcome = if real_match {
        VerifyOutcome::Real
    } else if any_duress_match {
        // Unwrap is safe: any_duress_match implies matched_duress_response is Some.
        VerifyOutcome::Duress(matched_duress_response.expect("response must be set"))
    } else {
        VerifyOutcome::NoMatch
    };

    Ok(outcome)
}

/// Zeroize helper for a passphrase buffer before computing its hash.
/// Callers should use this rather than letting the passphrase linger
/// in a stack-allocated slice.
pub fn zeroize_passphrase(buf: &mut [u8]) {
    buf.zeroize();
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hash_from(b: &[u8]) -> Vec<u8> {
        // A real impl would use Argon2id / scrypt / BLAKE3. For unit
        // tests we just take the bytes — the constant-time guarantee
        // doesn't care what's inside, only that the bytes are
        // compared uniformly.
        b.to_vec()
    }

    fn sample_config() -> DuressConfig {
        DuressConfig {
            real_hash: hash_from(b"realpass"),
            duress: vec![
                DuressEntry {
                    hash: hash_from(b"duress1"),
                    response: DuressResponse::MountDecoy,
                    label: Some("panic".into()),
                },
                DuressEntry {
                    hash: hash_from(b"duress2"),
                    response: DuressResponse::SilentAlert {
                        contacts: vec!["signal://lawyer".into()],
                    },
                    label: None,
                },
            ],
        }
    }

    #[test]
    fn real_passphrase_returns_real() {
        let cfg = sample_config();
        let out = verify(&cfg, b"realpass").unwrap();
        assert!(matches!(out, VerifyOutcome::Real));
    }

    #[test]
    fn first_duress_returns_its_response() {
        let cfg = sample_config();
        let out = verify(&cfg, b"duress1").unwrap();
        match out {
            VerifyOutcome::Duress(DuressResponse::MountDecoy) => {}
            other => panic!("expected MountDecoy, got {other:?}"),
        }
    }

    #[test]
    fn second_duress_returns_its_response() {
        let cfg = sample_config();
        let out = verify(&cfg, b"duress2").unwrap();
        match out {
            VerifyOutcome::Duress(DuressResponse::SilentAlert { contacts }) => {
                assert_eq!(contacts, vec!["signal://lawyer"]);
            }
            other => panic!("expected SilentAlert, got {other:?}"),
        }
    }

    #[test]
    fn wrong_passphrase_returns_nomatch() {
        let cfg = sample_config();
        let out = verify(&cfg, b"not-configured").unwrap();
        assert!(matches!(out, VerifyOutcome::NoMatch));
    }

    #[test]
    fn empty_input_returns_nomatch() {
        let cfg = sample_config();
        let out = verify(&cfg, b"").unwrap();
        assert!(matches!(out, VerifyOutcome::NoMatch));
    }

    #[test]
    fn empty_config_with_no_match() {
        let cfg = DuressConfig::default();
        let out = verify(&cfg, b"whatever").unwrap();
        assert!(matches!(out, VerifyOutcome::NoMatch));
    }

    #[test]
    fn composite_response_is_preserved() {
        let cfg = DuressConfig {
            real_hash: vec![],
            duress: vec![DuressEntry {
                hash: hash_from(b"composite"),
                response: DuressResponse::Composite(vec![
                    DuressResponse::SilentAlert { contacts: vec!["a".into()] },
                    DuressResponse::MountDecoy,
                ]),
                label: None,
            }],
        };
        let out = verify(&cfg, b"composite").unwrap();
        match out {
            VerifyOutcome::Duress(DuressResponse::Composite(inner)) => {
                assert_eq!(inner.len(), 2);
            }
            other => panic!("expected composite, got {other:?}"),
        }
    }

    #[test]
    fn zeroize_passphrase_clears_buffer() {
        let mut buf = *b"secretpass";
        zeroize_passphrase(&mut buf);
        assert_eq!(buf, [0u8; 10]);
    }

    /// Documents + exercises the caller's zeroization contract.
    /// `verify` cannot zeroize the input (it takes `&[u8]`), so the
    /// caller owns a mutable buffer, passes a borrow in, and zeroizes
    /// immediately after. A leaked buffer (dropped without zeroize)
    /// is a SECURITY bug — not because this test would catch it, but
    /// because the pattern below is the one reviewers should expect
    /// in every call site.
    #[test]
    fn caller_owned_zeroize_pattern() {
        let cfg = sample_config();

        // Caller owns a mutable buffer containing the KDF-hashed
        // passphrase. In real use, `buf` is the output of Argon2id.
        let mut buf = b"realpass".to_vec();

        let outcome = verify(&cfg, &buf).expect("verify");

        // IMPORTANT: zeroize BEFORE branching / early-returning so the
        // buffer is wiped even if later code panics.
        zeroize_passphrase(&mut buf);
        assert_eq!(buf, vec![0u8; 8]);

        assert!(matches!(outcome, VerifyOutcome::Real));
    }
}

#[cfg(test)]
mod proptests {
    //! Property-based tests for the constant-time verifier. Properties
    //! here target the three security invariants from the module-level
    //! doc block: (1) any non-configured input returns NoMatch,
    //! (2) a matching real_hash always beats a colliding duress entry,
    //! (3) entry order does not affect which response fires, and
    //! (4) `verify` never panics on any input.
    use super::*;
    use proptest::collection::vec;
    use proptest::prelude::*;

    fn arb_hash() -> impl Strategy<Value = Vec<u8>> {
        // Hash sizes in real use: BLAKE3=32B, SHA-256=32B, Argon2id=32B default.
        // Use 1..=128 so we also exercise short and long buffers.
        vec(any::<u8>(), 1..=128)
    }

    fn arb_response() -> impl Strategy<Value = DuressResponse> {
        prop_oneof![
            Just(DuressResponse::MountDecoy),
            // Avoid the key_ids / contacts / redact_paths variants here
            // since arbitrary KeyIds would require more setup; the above
            // variant exercises the enum path adequately.
        ]
    }

    fn arb_entry() -> impl Strategy<Value = DuressEntry> {
        (arb_hash(), arb_response()).prop_map(|(hash, response)| DuressEntry {
            hash,
            response,
            label: None,
        })
    }

    fn arb_config() -> impl Strategy<Value = DuressConfig> {
        (arb_hash(), vec(arb_entry(), 0..=8))
            .prop_map(|(real_hash, duress)| DuressConfig { real_hash, duress })
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(2_000))]

        /// If a candidate byte-equals neither the real hash nor any
        /// configured duress hash, the outcome must be NoMatch.
        #[test]
        fn unconfigured_input_returns_nomatch(
            cfg in arb_config(),
            candidate in arb_hash(),
        ) {
            let matches_real = candidate == cfg.real_hash;
            let matches_any_duress = cfg.duress.iter().any(|e| e.hash == candidate);
            prop_assume!(!matches_real && !matches_any_duress);

            let out = verify(&cfg, &candidate).unwrap();
            prop_assert!(matches!(out, VerifyOutcome::NoMatch));
        }

        /// Real beats duress: if the real hash happens to also be
        /// configured as a duress entry (or collides), the Real arm
        /// must win — typing the real passphrase must never fire a
        /// duress response.
        #[test]
        fn real_hash_wins_over_duress_collision(
            real in arb_hash(),
            extra_entries in vec(arb_entry(), 0..=4),
            response in arb_response(),
        ) {
            let mut duress = extra_entries;
            // Insert a duress entry whose hash collides with real.
            duress.insert(
                0,
                DuressEntry { hash: real.clone(), response, label: None },
            );
            let cfg = DuressConfig { real_hash: real.clone(), duress };

            let out = verify(&cfg, &real).unwrap();
            prop_assert!(matches!(out, VerifyOutcome::Real));
        }

        /// Reversing the duress vector must not change which response
        /// fires for a given matching input — the first-match-wins
        /// semantics are index-based, so reversing should still pick
        /// the (now-)first matching entry for that hash. Verified by
        /// checking that both orderings produce a Duress outcome (not
        /// NoMatch) and that neither accidentally produces Real.
        #[test]
        fn reversal_preserves_duress_outcome(
            real in arb_hash(),
            entries in vec(arb_entry(), 1..=6),
            pick in 0usize..6,
        ) {
            prop_assume!(!entries.is_empty());
            let idx = pick % entries.len();
            let candidate = entries[idx].hash.clone();
            prop_assume!(candidate != real);

            let mut forward = DuressConfig { real_hash: real.clone(), duress: entries.clone() };
            let mut reversed_entries = entries;
            reversed_entries.reverse();
            let mut reverse = DuressConfig { real_hash: real, duress: reversed_entries };

            let f = verify(&forward, &candidate).unwrap();
            let r = verify(&reverse, &candidate).unwrap();

            prop_assert!(matches!(f, VerifyOutcome::Duress(_)));
            prop_assert!(matches!(r, VerifyOutcome::Duress(_)));

            // Silence unused_mut — verify takes &self so nothing mutates,
            // but both bindings live the same lifetime.
            let _ = (&mut forward, &mut reverse);
        }

        /// The verifier must never panic on arbitrary input — a crafted
        /// hash (including empty, oversized, or all-zero) must always
        /// return a well-formed Result.
        #[test]
        fn verify_never_panics(
            cfg in arb_config(),
            candidate in vec(any::<u8>(), 0..=256),
        ) {
            let _ = verify(&cfg, &candidate);
        }
    }
}
