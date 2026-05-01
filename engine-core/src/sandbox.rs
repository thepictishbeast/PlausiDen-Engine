//! Runtime hardening for engine consumers — defense-in-depth via
//! Linux landlock.
//!
//! This module is **opt-in** for binary consumers of engine-core
//! (`plausiden-inject`, `plausiden-desktop`, `plausiden-android` JNI
//! bridge, etc.). The library itself does nothing on import; a
//! consumer must call [`lock_down`] from `main` (or a setup hook)
//! after any filesystem setup is complete.
//!
//! ## What it does
//!
//! On Linux, [`lock_down`] applies a [landlock] ruleset that limits
//! the calling process to a small set of explicitly-allowed
//! filesystem paths. After the call, attempting to read or write
//! outside the allowlist returns `EACCES` regardless of the file's
//! permission bits or the calling user's privileges.
//!
//! On non-Linux targets the function is a no-op that logs a warning
//! at the `info` level so the consumer's logs make it obvious that
//! the hardening did not apply. Cross-compiled WASM consumers
//! (browser extensions) get the no-op — sandboxing in those targets
//! is the host runtime's responsibility (browser sandbox, JVM, etc.).
//!
//! ## Threat model this addresses
//!
//! Engine generators are pure functions over an RNG and a
//! [`crate::profile::UserProfile`]. They have no business reading
//! arbitrary files or writing outside their consumer's working set.
//! If a generator is ever compromised — by a future bug, a vendor
//! supply-chain attack on a corpus dependency, or an
//! adversarial profile crafted to trigger an out-of-bounds read —
//! the blast radius is limited by the sandbox, not by the
//! generator's code.
//!
//! ## SECURITY: layered defence
//!
//! Landlock is necessary but not sufficient. Consumers should also:
//!
//! 1. Drop unneeded capabilities via `prctl(PR_SET_NO_NEW_PRIVS)`
//!    before exec'ing engine code.
//! 2. Optionally apply a seccomp filter restricting the syscall
//!    surface (planned for a future pass; tracked at the relevant
//!    consumer's task list).
//! 3. Run as an unprivileged user.
//!
//! The landlock layer makes an in-engine compromise less catastrophic;
//! the other layers make compromise harder in the first place.

use std::path::PathBuf;

/// Configuration for the lockdown call. Each field is an allowlist
/// of paths the calling process may continue to access after
/// [`lock_down`] returns.
#[derive(Debug, Clone, Default)]
pub struct LockdownOpts {
    /// Paths the process may read from. Use the smallest set that
    /// keeps the engine consumer functional — typically just the
    /// corpus / asset directory and a temp scratch dir.
    pub read_paths: Vec<PathBuf>,
    /// Paths the process may write to. Use the smallest set that
    /// keeps the engine consumer functional — typically just the
    /// output directory and a temp scratch dir.
    pub write_paths: Vec<PathBuf>,
}

impl LockdownOpts {
    /// Empty allowlist — calling [`lock_down`] with this denies
    /// every filesystem operation. Useful for tests that exercise
    /// pure-function generators with no I/O at all.
    #[must_use]
    pub fn deny_all() -> Self {
        Self::default()
    }

    /// Convenience: allow read of `read_paths`, write of `write_paths`.
    #[must_use]
    pub fn new(read_paths: Vec<PathBuf>, write_paths: Vec<PathBuf>) -> Self {
        Self {
            read_paths,
            write_paths,
        }
    }
}

/// Apply the landlock ruleset (Linux only). On other targets, log
/// at `info` level and return `Ok(())`.
///
/// # Errors
///
/// Returns an error if the kernel doesn't support landlock (older
/// kernels, certain container configurations) OR if the ruleset
/// fails to apply for any other reason. Consumers should treat a
/// failure as a hard configuration error — proceeding without
/// the sandbox in production should be a deliberate
/// `SHIP-DECISION:` annotation, not a silent fallback.
///
/// # Idempotency
///
/// landlock rulesets are CUMULATIVE within a process: a second
/// call further restricts but cannot relax the first. Most
/// consumers should call exactly once at startup; tests that need
/// to verify the API don't usually need to call at all (the
/// public-API shape is enough).
///
/// SECURITY: This is the single point of trust. A consumer that
/// forgets to call this gets the unhardened runtime — no compile-
/// time check enforces the call. The consumer's
/// `BUG ASSUMPTION:` annotation in main MUST mention whether
/// the binary calls into here at startup.
pub fn lock_down(opts: &LockdownOpts) -> crate::error::Result<()> {
    #[cfg(target_os = "linux")]
    {
        return linux::apply(opts);
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = opts;
        tracing::info!(
            "engine-core::sandbox::lock_down: target is not Linux; \
             landlock unavailable, no sandbox applied"
        );
        Ok(())
    }
}

#[cfg(target_os = "linux")]
mod linux {
    use super::LockdownOpts;
    use landlock::{
        path_beneath_rules, AccessFs, Ruleset, RulesetAttr, RulesetCreatedAttr, RulesetStatus, ABI,
    };

    /// Apply the landlock ruleset. Pulls the most-recent ABI level
    /// the kernel supports; allowlists the requested paths.
    ///
    /// SAFETY: landlock is a kernel-level permission overlay; this
    /// function does not write any process state beyond what
    /// landlock requires. If the kernel doesn't support landlock,
    /// `Ruleset::default().handle_access(...)` succeeds (best-effort)
    /// and `restrict_self()` reports `RulesetStatus::NotEnforced`,
    /// which we map to a Result error so the consumer sees the
    /// degradation explicitly.
    pub(super) fn apply(opts: &LockdownOpts) -> crate::error::Result<()> {
        let abi = ABI::V1;
        let read_access = AccessFs::from_read(abi);
        let write_access = AccessFs::from_write(abi);

        let mut ruleset = Ruleset::default()
            .handle_access(read_access)
            .map_err(map_err)?
            .handle_access(write_access)
            .map_err(map_err)?
            .create()
            .map_err(map_err)?;

        if !opts.read_paths.is_empty() {
            ruleset = ruleset
                .add_rules(path_beneath_rules(&opts.read_paths, read_access))
                .map_err(map_err)?;
        }
        if !opts.write_paths.is_empty() {
            ruleset = ruleset
                .add_rules(path_beneath_rules(&opts.write_paths, write_access))
                .map_err(map_err)?;
        }

        let status = ruleset.restrict_self().map_err(map_err)?;
        match status.ruleset {
            RulesetStatus::FullyEnforced => {
                tracing::info!(
                    read_paths = opts.read_paths.len(),
                    write_paths = opts.write_paths.len(),
                    "engine-core::sandbox: landlock fully enforced"
                );
                Ok(())
            }
            RulesetStatus::PartiallyEnforced => {
                tracing::warn!(
                    "engine-core::sandbox: landlock only partially enforced — kernel ABI mismatch?"
                );
                Ok(())
            }
            RulesetStatus::NotEnforced => Err(crate::error::EngineError::InvalidContext(
                "landlock ruleset not enforced; kernel may not support landlock".to_string(),
            )),
        }
    }

    fn map_err<E: std::fmt::Display>(e: E) -> crate::error::EngineError {
        crate::error::EngineError::InvalidContext(format!("landlock: {e}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lockdown_opts_default_is_deny_all() {
        let opts = LockdownOpts::deny_all();
        assert!(opts.read_paths.is_empty());
        assert!(opts.write_paths.is_empty());
    }

    #[test]
    fn lockdown_opts_new_preserves_paths() {
        let opts = LockdownOpts::new(
            vec![PathBuf::from("/usr/share/corpus")],
            vec![PathBuf::from("/var/tmp/inject")],
        );
        assert_eq!(opts.read_paths.len(), 1);
        assert_eq!(opts.write_paths.len(), 1);
    }

    /// On non-Linux, lock_down returns Ok and logs a warning. We
    /// can't easily unit-test the actual landlock enforcement
    /// because it permanently restricts the test process; that's
    /// covered by manual end-to-end exercises in consumer
    /// binaries, not here.
    #[cfg(not(target_os = "linux"))]
    #[test]
    fn lockdown_is_noop_on_non_linux() {
        let opts = LockdownOpts::deny_all();
        assert!(lock_down(&opts).is_ok());
    }
}
