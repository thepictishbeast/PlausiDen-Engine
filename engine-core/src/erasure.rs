//! # Cryptographic erasure primitives.
//!
//! `ErasableKey` pins its 32-byte material in RAM via `mlock` (Unix),
//! marks it `MADV_DONTDUMP` so it's excluded from core dumps, and
//! zeroizes on drop via the `Zeroize` derive. This is the minimum
//! required for `KeyStorage::Memory` to provide meaningful erasure
//! semantics per v1.2 §D.2.
//!
//! **Current status (2026-04-17):** `KeyStorage::Memory` path is
//! implemented end-to-end on Unix. Windows (`VirtualLock`),
//! `MemoryAndDisk`, `Hardware`, and `ShamirShares` storage variants
//! remain stubbed; `erase()` returns a receipt with a placeholder
//! signature (Ed25519 signing lands with the engine signing-keys work,
//! not in this module).
//!
//! SECURITY:
//! - mlock is best-effort. On systems where `RLIMIT_MEMLOCK` is too low
//!   or the process lacks `CAP_IPC_LOCK`, `new_in_memory` returns
//!   `EngineError::MlockFailed` — a hard error, not a silent fallback.
//!   Callers MUST either raise the limit or use `KeyStorage::Hardware`.
//! - Swap must be disabled on machines holding long-lived secrets. mlock
//!   protects the pages from the swap subsystem, but if the process
//!   forks and the child doesn't re-mlock, the child's copy is
//!   page-outable. Documented in OPSEC.md.
//! - `MADV_DONTDUMP` excludes the page from `ptrace`-based coredumps
//!   but NOT from live introspection. A root adversary (or exploit that
//!   gains ptrace) can still read the page. That's Tier 3 territory.

use crate::error::{EngineError, Result};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use zeroize::Zeroize;

/// Opaque key identifier. Uses a UUIDv4 internally; callers should
/// treat it as a stable-but-unpredictable handle with no routable
/// information encoded in it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct KeyId(pub Uuid);

impl KeyId {
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }
}

impl Default for KeyId {
    fn default() -> Self {
        Self::new()
    }
}

/// Where the key material for an [`ErasableKey`] is stored.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum KeyStorage {
    /// In-process memory only. `mlock` + `MADV_DONTDUMP` on Unix.
    /// `VirtualLock` on Windows (pending).
    Memory,
    /// Primary copy in memory, backup on disk (encrypted). Pending.
    MemoryAndDisk,
    /// Key held in hardware — Secure Enclave, TPM, HSM, FIDO2 key. Pending.
    Hardware,
    /// Split via Shamir's Secret Sharing (k of n shares required). Pending.
    ShamirShares { threshold: u8, total: u8 },
}

/// A cryptographic key that can be erased deterministically.
///
/// Holds 32 bytes of key material in a page pinned to RAM (on Unix;
/// Windows path pending). The bytes are zeroized on drop via the
/// `Zeroize` derive, and the page is unlocked via `munlock` also on
/// drop so we return the mlock budget to the kernel.
///
/// The material field is private — callers interact via the `expose()`
/// accessor once implemented, or (for now) treat the key as an opaque
/// handle passed to crypto functions by reference.
pub struct ErasableKey {
    /// 32 bytes of key material. Zeroized explicitly in Drop.
    material: Box<[u8; 32]>,

    /// Key identifier. Safe to log.
    pub id: KeyId,

    /// Which storage variant backs this key.
    pub storage: KeyStorage,

    /// Whether the material page is currently mlocked. Used by Drop
    /// to decide whether to call munlock. Never exposed.
    locked: bool,
}

// A manual Debug impl that redacts material. Derive-Debug would print
// the bytes — catastrophic for secret types.
impl std::fmt::Debug for ErasableKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ErasableKey")
            .field("id", &self.id)
            .field("storage", &self.storage)
            .field("locked", &self.locked)
            .field("material", &"[REDACTED 32B]")
            .finish()
    }
}

impl ErasableKey {
    /// Construct an `ErasableKey` backed by mlocked memory (Unix).
    ///
    /// On Unix: mlocks the 32-byte page, marks it `MADV_DONTDUMP`.
    /// Returns `EngineError::MlockFailed` if mlock fails (typically
    /// `RLIMIT_MEMLOCK` exhausted or missing `CAP_IPC_LOCK`).
    ///
    /// On non-Unix (including Windows for now): returns the key with
    /// `locked: false` and NO pinning. This is a TEMPORARY gap —
    /// callers on Windows should not treat `KeyStorage::Memory` as
    /// providing swap-resistance until VirtualLock lands.
    pub fn new_in_memory(material: [u8; 32]) -> Result<Self> {
        // `mut` is needed for the unix mlock path (as_mut_ptr); on wasm32
        // and other targets without that block the binding is read-only,
        // so the warning would fire. Suppress only on the no-mlock paths.
        #[cfg_attr(not(unix), allow(unused_mut))]
        let mut boxed: Box<[u8; 32]> = Box::new(material);

        #[cfg(unix)]
        let locked = {
            // SAFETY: `boxed` points to 32 aligned writable bytes owned
            // by this function. mlock merely pins the mapping in RAM —
            // it does not invalidate the pointer. MADV_DONTDUMP is best-
            // effort; we tolerate its failure because the ZeroizeOnDrop
            // + mlock pair is the primary defense.
            unsafe {
                let ptr = boxed.as_mut_ptr() as *mut libc::c_void;
                let len = std::mem::size_of::<[u8; 32]>();
                if libc::mlock(ptr, len) != 0 {
                    return Err(EngineError::MlockFailed(std::io::Error::last_os_error()));
                }
                // Best-effort MADV_DONTDUMP — some kernels / containers
                // don't implement it. We don't ERROR on failure (mlock is
                // the primary defense), but we DO surface a tracing::warn
                // so operators running under ptrace restrictions or
                // hardened containers can see the degraded state. Silent
                // failure was the previous behaviour; the module doc
                // (line 25) claims coredump exclusion as a guarantee, so
                // advertising the gap is non-optional.
                #[cfg(target_os = "linux")]
                {
                    if libc::madvise(ptr, len, libc::MADV_DONTDUMP) != 0 {
                        let os_err = std::io::Error::last_os_error();
                        tracing::warn!(
                            target: "engine_core::erasure",
                            error = %os_err,
                            "madvise(MADV_DONTDUMP) failed; key page may appear in core dumps. \
                             mlock still guards against swap-out — fallback posture holds, but a \
                             ptrace-captured coredump could now expose this key's material.",
                        );
                    }
                }
            }
            true
        };

        #[cfg(not(unix))]
        let locked = false;

        Ok(Self {
            material: boxed,
            id: KeyId::new(),
            storage: KeyStorage::Memory,
            locked,
        })
    }

    /// Borrow the key material immutably. The caller must not copy the
    /// bytes out — the whole point of ErasableKey is that the material
    /// never leaves the mlocked page uncontrolled. This accessor exists
    /// so crypto routines (chacha20poly1305, ed25519-dalek) can consume
    /// the key by reference.
    pub fn expose(&self) -> &[u8; 32] {
        &self.material
    }

    /// Erase the key material deterministically and return an
    /// [`ErasureReceipt`]. The receipt's signature is currently a
    /// placeholder — Ed25519 signing lands when the engine's signing
    /// keys are provisioned (see task #22 follow-on).
    pub fn erase(self, reason: ErasureReason) -> Result<ErasureReceipt> {
        let key_id = self.id;
        // Self drops here — ZeroizeOnDrop wipes material, the Drop impl
        // below munlocks.
        let erased_at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|e| EngineError::InvalidContext(format!("system clock before epoch: {e}")))?
            .as_secs() as i64;

        // Emit a tracing event BEFORE returning — erase is a genuine,
        // once-per-key action (not a polled decision), so logging here
        // is idempotent and high-signal for incident reconstruction.
        // Subscribers (Desktop's log_aggregator, the Browser-Ext bounded
        // ring-buffer via a JNI bridge) can correlate this with the
        // matching ErasureReceipt. KeyId is surfaced; key material is
        // never in the event (it's zeroed before we get here).
        tracing::info!(
            target: "engine_core::erasure",
            key_id = ?key_id,
            reason = ?reason,
            erased_at,
            "ErasableKey::erase",
        );

        Ok(ErasureReceipt {
            key_id,
            erased_at,
            reason,
            // Placeholder — real Ed25519 sig lands with the engine signing
            // infrastructure. Length kept at 64 bytes to match Ed25519.
            signature: vec![0u8; 64],
        })
    }
}

impl Drop for ErasableKey {
    fn drop(&mut self) {
        // Zeroize material FIRST — before munlock. munlock's kernel-side
        // accounting return is best-effort; zeroize is the actual security
        // guarantee. Order matters because if the process is being killed
        // mid-drop, we want the bytes gone before the kernel reclaims
        // pages.
        self.material.zeroize();

        #[cfg(unix)]
        if self.locked {
            // SAFETY: boxed pointer is still valid here (Drop runs before
            // the Box's own drop). munlock returns 0 on success, -1 on
            // error; we ignore the error path because we're in Drop and
            // must not panic. The worst case is a stuck mlock, which is
            // a kernel accounting issue, not a security regression.
            unsafe {
                let ptr = self.material.as_mut_ptr() as *mut libc::c_void;
                let len = std::mem::size_of::<[u8; 32]>();
                let _ = libc::munlock(ptr, len);
            }
        }
    }
}

/// Why a key was erased. Surfaced in the receipt for later audit.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum ErasureReason {
    UserInitiated,
    Deadman,
    Duress,
    Rotation,
    SwarmDestroy,
    Policy,
}

/// Proof that a key was erased at a specific point in time, signed
/// by the issuing installation's Ed25519 signing key.
///
/// Verification is via `verify_with(&verifying_key)`. Independent
/// third parties can check a receipt without trusting this runtime —
/// they need only the published public key and the canonical
/// representation of `(key_id bytes, erased_at big-endian i64,
/// reason tag byte)`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErasureReceipt {
    pub key_id: KeyId,
    /// Seconds since UNIX epoch.
    pub erased_at: i64,
    pub reason: ErasureReason,
    /// Ed25519 signature over the canonical message. Always 64 bytes.
    pub signature: Vec<u8>,
}

impl ErasureReceipt {
    /// Build the canonical signing payload.
    /// Layout: `key_id (16B) || erased_at (big-endian i64, 8B) || reason (1B)`.
    fn canonical_payload(key_id: KeyId, erased_at: i64, reason: ErasureReason) -> [u8; 25] {
        let mut buf = [0u8; 25];
        buf[0..16].copy_from_slice(key_id.0.as_bytes());
        buf[16..24].copy_from_slice(&erased_at.to_be_bytes());
        buf[24] = reason.tag_byte();
        buf
    }

    /// Construct and sign a new receipt.
    pub fn sign(
        key_id: KeyId,
        erased_at: i64,
        reason: ErasureReason,
        signing_key: &SigningKey,
    ) -> Self {
        let payload = Self::canonical_payload(key_id, erased_at, reason);
        let sig: Signature = signing_key.sign(&payload);
        Self {
            key_id,
            erased_at,
            reason,
            signature: sig.to_bytes().to_vec(),
        }
    }

    /// Verify the receipt's signature against a given public key.
    /// Returns Ok(()) on success, `EngineError::InvalidContext` on
    /// signature mismatch or malformed length.
    pub fn verify_with(&self, verifying_key: &VerifyingKey) -> Result<()> {
        if self.signature.len() != 64 {
            return Err(EngineError::InvalidContext(format!(
                "receipt signature length {} != 64",
                self.signature.len()
            )));
        }
        let sig_bytes: [u8; 64] = self
            .signature
            .as_slice()
            .try_into()
            .map_err(|_| EngineError::InvalidContext("signature conversion failed".into()))?;
        let sig = Signature::from_bytes(&sig_bytes);
        let payload = Self::canonical_payload(self.key_id, self.erased_at, self.reason);
        verifying_key
            .verify(&payload, &sig)
            .map_err(|e| EngineError::InvalidContext(format!("receipt signature invalid: {e}")))
    }
}

impl ErasureReason {
    /// Canonical 1-byte tag for the signing payload. Values fixed by
    /// this table — NEVER renumber; external verifiers depend on exact
    /// bytes for previously-issued receipts.
    fn tag_byte(self) -> u8 {
        match self {
            Self::UserInitiated => 0x01,
            Self::Deadman => 0x02,
            Self::Duress => 0x03,
            Self::Rotation => 0x04,
            Self::SwarmDestroy => 0x05,
            Self::Policy => 0x06,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_id_new_is_unique_across_calls() {
        let a = KeyId::new();
        let b = KeyId::new();
        assert_ne!(a, b);
    }

    #[test]
    fn new_in_memory_succeeds_on_unix() {
        let material = [0x42u8; 32];
        let key = ErasableKey::new_in_memory(material).expect("mlock should succeed");
        assert_eq!(key.storage, KeyStorage::Memory);
        #[cfg(unix)]
        assert!(key.locked);
    }

    #[test]
    fn expose_returns_material() {
        let material = [0x37u8; 32];
        let key = ErasableKey::new_in_memory(material).unwrap();
        assert_eq!(key.expose(), &[0x37u8; 32]);
    }

    #[test]
    fn debug_impl_redacts_material() {
        let key = ErasableKey::new_in_memory([0xaau8; 32]).unwrap();
        let dbg = format!("{key:?}");
        assert!(dbg.contains("REDACTED"));
        assert!(!dbg.contains("0xaa"));
        assert!(!dbg.contains("170"));
    }

    #[test]
    fn drop_does_not_panic() {
        let key = ErasableKey::new_in_memory([0u8; 32]).unwrap();
        drop(key);
    }

    #[test]
    fn erase_returns_receipt_with_same_key_id() {
        let key = ErasableKey::new_in_memory([1u8; 32]).unwrap();
        let id = key.id;
        let receipt = key.erase(ErasureReason::UserInitiated).unwrap();
        assert_eq!(receipt.key_id, id);
        assert_eq!(receipt.reason, ErasureReason::UserInitiated);
        assert_eq!(receipt.signature.len(), 64);
        assert!(receipt.erased_at > 1_700_000_000);
    }

    #[test]
    fn key_storage_all_variants_printable() {
        let all = [
            KeyStorage::Memory,
            KeyStorage::MemoryAndDisk,
            KeyStorage::Hardware,
            KeyStorage::ShamirShares {
                threshold: 3,
                total: 5,
            },
        ];
        for s in all {
            let _ = format!("{s:?}");
        }
    }

    #[test]
    fn erasure_receipt_roundtrips_through_serde() {
        let r = ErasureReceipt {
            key_id: KeyId::new(),
            erased_at: 1_700_000_000,
            reason: ErasureReason::Duress,
            signature: vec![0u8; 64],
        };
        let json = serde_json::to_string(&r).unwrap();
        let back: ErasureReceipt = serde_json::from_str(&json).unwrap();
        assert_eq!(back.key_id, r.key_id);
        assert_eq!(back.reason, r.reason);
    }

    // ---- Ed25519 signing (task #47) ----

    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;

    fn test_signing_key() -> SigningKey {
        SigningKey::generate(&mut OsRng)
    }

    #[test]
    fn receipt_sign_and_verify_roundtrip() {
        let sk = test_signing_key();
        let vk = sk.verifying_key();
        let receipt = ErasureReceipt::sign(
            KeyId::new(),
            1_700_000_000,
            ErasureReason::UserInitiated,
            &sk,
        );
        assert_eq!(receipt.signature.len(), 64);
        receipt
            .verify_with(&vk)
            .expect("fresh signature must verify");
    }

    #[test]
    fn tampered_receipt_fails_verification() {
        let sk = test_signing_key();
        let vk = sk.verifying_key();
        let mut receipt =
            ErasureReceipt::sign(KeyId::new(), 1_700_000_000, ErasureReason::Deadman, &sk);
        // Tamper with the timestamp.
        receipt.erased_at += 1;
        assert!(receipt.verify_with(&vk).is_err());
    }

    #[test]
    fn wrong_key_fails_verification() {
        let sk_a = test_signing_key();
        let sk_b = test_signing_key();
        let receipt =
            ErasureReceipt::sign(KeyId::new(), 1_700_000_000, ErasureReason::Rotation, &sk_a);
        // Verifying with sk_b's public key must fail.
        assert!(receipt.verify_with(&sk_b.verifying_key()).is_err());
    }

    #[test]
    fn reason_tag_bytes_are_stable() {
        // Renumbering these would invalidate every previously-issued
        // receipt — any change needs a forensic-compat note.
        assert_eq!(ErasureReason::UserInitiated.tag_byte(), 0x01);
        assert_eq!(ErasureReason::Deadman.tag_byte(), 0x02);
        assert_eq!(ErasureReason::Duress.tag_byte(), 0x03);
        assert_eq!(ErasureReason::Rotation.tag_byte(), 0x04);
        assert_eq!(ErasureReason::SwarmDestroy.tag_byte(), 0x05);
        assert_eq!(ErasureReason::Policy.tag_byte(), 0x06);
    }

    #[test]
    fn bad_signature_length_rejected() {
        let sk = test_signing_key();
        let vk = sk.verifying_key();
        let receipt = ErasureReceipt {
            key_id: KeyId::new(),
            erased_at: 0,
            reason: ErasureReason::Policy,
            signature: vec![0u8; 32], // too short
        };
        assert!(receipt.verify_with(&vk).is_err());
    }
}

#[cfg(test)]
mod proptests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use proptest::prelude::*;
    use rand::rngs::OsRng;

    fn reason_from_index(i: u8) -> ErasureReason {
        match i % 6 {
            0 => ErasureReason::UserInitiated,
            1 => ErasureReason::Deadman,
            2 => ErasureReason::Duress,
            3 => ErasureReason::Rotation,
            4 => ErasureReason::SwarmDestroy,
            _ => ErasureReason::Policy,
        }
    }

    proptest! {
        /// Sign/verify roundtrip: any (key_id, erased_at, reason)
        /// must round-trip through Ed25519 signing with a fresh key.
        #[test]
        fn sign_verify_roundtrips(
            key_id_bytes in any::<[u8; 16]>(),
            erased_at in any::<i64>(),
            reason_idx in any::<u8>(),
        ) {
            let sk = SigningKey::generate(&mut OsRng);
            let vk = sk.verifying_key();
            let key_id = KeyId(uuid::Uuid::from_bytes(key_id_bytes));
            let reason = reason_from_index(reason_idx);

            let receipt = ErasureReceipt::sign(key_id, erased_at, reason, &sk);
            prop_assert_eq!(receipt.signature.len(), 64);
            prop_assert!(receipt.verify_with(&vk).is_ok());
        }

        /// Tamper resistance: flipping any byte in the timestamp
        /// after signing must fail verification.
        #[test]
        fn tampered_timestamp_rejected(
            key_id_bytes in any::<[u8; 16]>(),
            erased_at in (i64::MIN / 2)..(i64::MAX / 2),
            delta in 1i64..1000,
            reason_idx in any::<u8>(),
        ) {
            let sk = SigningKey::generate(&mut OsRng);
            let vk = sk.verifying_key();
            let key_id = KeyId(uuid::Uuid::from_bytes(key_id_bytes));
            let reason = reason_from_index(reason_idx);

            let mut receipt = ErasureReceipt::sign(key_id, erased_at, reason, &sk);
            receipt.erased_at = erased_at.saturating_add(delta);
            prop_assert!(receipt.verify_with(&vk).is_err());
        }

        /// Independent keys never cross-verify (collision prob 2^-128).
        #[test]
        fn independent_keys_do_not_cross_verify(
            key_id_bytes in any::<[u8; 16]>(),
            erased_at in any::<i64>(),
            reason_idx in any::<u8>(),
        ) {
            let sk_a = SigningKey::generate(&mut OsRng);
            let sk_b = SigningKey::generate(&mut OsRng);
            let key_id = KeyId(uuid::Uuid::from_bytes(key_id_bytes));
            let reason = reason_from_index(reason_idx);

            let receipt = ErasureReceipt::sign(key_id, erased_at, reason, &sk_a);
            prop_assert!(receipt.verify_with(&sk_b.verifying_key()).is_err());
        }
    }
}
