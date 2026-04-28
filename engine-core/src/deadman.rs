//! # Dead-man switch.
//!
//! A user configures a dead-man switch with a max-silent-time. If the
//! user doesn't [`DeadmanConfig::check_in`] within that window, the
//! configured [`TriggerAction`] fires. Use cases:
//!
//! - Activists who want key material destroyed if they are detained.
//! - Journalists who want a draft published if they go silent.
//! - Whistleblowers who want an escrowed document released at a date.
//! - Operators who want Swarm fragments destroyed if the node goes
//!   dark for too long.
//!
//! This module provides the *decision layer* — given a config and a
//! current timestamp, compute what (if anything) should fire. The
//! *execution* layer (actually erasing the key, sending the alert,
//! publishing the document) lives in the host binary, which knows
//! what "erase" or "alert" means on its platform.
//!
//! Status as of 2026-04-17 (task #24 scaffold tick): types + pure
//! `evaluate()` function + 9 unit tests. No background timer, no
//! I/O — the host drives timing by calling `evaluate()` on its own
//! schedule (e.g. a 60-second tick). A later tick adds a
//! `DeadmanWatcher` that wraps a tokio task, but the pure decision
//! function is usable now.

use crate::erasure::KeyId;
use crate::error::Result;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::time::Duration;

/// What happens when a dead-man switch fires.
///
/// Multiple actions compose via [`TriggerAction::Composite`]. Failure
/// of one composed action does not stop the others — the host's
/// dispatcher should try each independently.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum TriggerAction {
    /// Erase the specified keys via `erasure::ErasableKey::erase`.
    EraseKey { key_ids: Vec<KeyId> },

    /// Send alerts to the listed contact channels. String format is
    /// up to the host (e.g. `signal://+1...`, `email:foo@bar`,
    /// `swarm://...`). The engine doesn't send alerts itself.
    AlertContacts { channels: Vec<String> },

    /// Broadcast a "destroy this fragment" signal over the swarm so
    /// peers holding copies will also remove them. Best-effort.
    SwarmDestroy { fragment_ids: Vec<String> },

    /// Securely delete the listed filesystem paths. Uses the host's
    /// secure-delete primitive (which on Linux may be
    /// `PlausiDen-Purge`'s erasure tool, not plain `rm`).
    WipePaths { paths: Vec<PathBuf> },

    /// Invoke a host-side hook by name. The hook catalog is host-
    /// specific; the engine only passes the name. Used for
    /// integration with platform-specific behaviours (e.g.
    /// "unregister-push-token" on Android).
    CustomHook { name: String },

    /// Do multiple actions in order. Failures are isolated per sub-action.
    Composite(Vec<TriggerAction>),
}

/// Dead-man switch configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeadmanConfig {
    /// How long the user may remain silent before the trigger fires.
    /// Stored as seconds for serde simplicity; [`DeadmanConfig::duration`]
    /// returns it as a `Duration`.
    pub dead_seconds: u64,

    /// Threshold before expiry at which the host should warn the user
    /// ("your dead-man switch fires in 12 hours, check in to reset").
    /// Stored as seconds.
    pub warning_seconds: u64,

    /// The action to fire at expiry.
    pub action: TriggerAction,

    /// Unix-epoch seconds of the most recent check-in. A freshly
    /// constructed config has `last_checkin_unix == 0`, which means
    /// the timer has not started yet — the host should call
    /// [`DeadmanConfig::check_in`] once at arm time.
    pub last_checkin_unix: i64,

    /// Whether the switch is currently armed. Host flips this via
    /// [`DeadmanConfig::arm`] / [`DeadmanConfig::disarm`]. Disarmed
    /// switches do not fire regardless of elapsed time.
    pub armed: bool,
}

impl DeadmanConfig {
    /// Check-in: record the current time and reset the timer.
    pub fn check_in(&mut self, now_unix: i64) {
        self.last_checkin_unix = now_unix;
    }

    /// Arm the switch, setting the initial check-in time.
    pub fn arm(&mut self, now_unix: i64) {
        self.armed = true;
        self.last_checkin_unix = now_unix;
    }

    /// Disarm the switch. The action will not fire.
    pub fn disarm(&mut self) {
        self.armed = false;
    }

    pub fn duration(&self) -> Duration {
        Duration::from_secs(self.dead_seconds)
    }

    pub fn warning_threshold(&self) -> Duration {
        Duration::from_secs(self.warning_seconds)
    }
}

/// Evaluation result. Tells the host what (if anything) to do.
#[derive(Debug, Clone, PartialEq)]
pub enum DeadmanStatus<'a> {
    /// Switch is disarmed; do nothing.
    Disarmed,
    /// Ample time remaining; do nothing.
    Fresh,
    /// Warning threshold crossed but not yet expired. Host should
    /// prompt the user to check in.
    Warning {
        /// Seconds until the trigger fires.
        remaining: u64,
    },
    /// Expired. The host MUST execute `action`.
    Fire {
        /// How late the firing is (seconds past the dead deadline).
        late_by: u64,
        /// The action to execute.
        action: &'a TriggerAction,
    },
}

/// Pure decision function. Given a config and a current time, return
/// what should happen. Does NOT mutate state — callers that want to
/// record "fired" must update their own state outside this module.
pub fn evaluate(config: &DeadmanConfig, now_unix: i64) -> DeadmanStatus<'_> {
    if !config.armed {
        return DeadmanStatus::Disarmed;
    }

    // Why no sentinel on last_checkin_unix == 0: time 0 (1970-01-01) is a
    // valid Unix timestamp. Tests that arm at time 0 are legitimate. The
    // supported API requires calling arm() before evaluate() — direct
    // mutation of `armed` without setting last_checkin_unix is user
    // error. Conservative behavior: treat missing check-in as "last
    // check-in was at time 0" which makes an armed-but-stale switch
    // fire immediately, which is the fail-safe interpretation.

    let elapsed = now_unix.saturating_sub(config.last_checkin_unix).max(0) as u64;
    if elapsed >= config.dead_seconds {
        let late_by = elapsed - config.dead_seconds;
        return DeadmanStatus::Fire {
            late_by,
            action: &config.action,
        };
    }
    let remaining = config.dead_seconds - elapsed;
    if remaining <= config.warning_seconds {
        return DeadmanStatus::Warning { remaining };
    }
    DeadmanStatus::Fresh
}

/// Convenience: construct a minimal config — 7-day dead window, 1-day
/// warning threshold, single EraseKey action. Hosts that need more
/// structure should build `DeadmanConfig` directly.
pub fn simple_key_erase(key_ids: Vec<KeyId>) -> Result<DeadmanConfig> {
    Ok(DeadmanConfig {
        dead_seconds: 7 * 24 * 3600,
        warning_seconds: 24 * 3600,
        action: TriggerAction::EraseKey { key_ids },
        last_checkin_unix: 0,
        armed: false,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> DeadmanConfig {
        DeadmanConfig {
            dead_seconds: 86_400,   // 1 day
            warning_seconds: 3_600, // 1 hour
            action: TriggerAction::AlertContacts {
                channels: vec!["signal://lawyer".into()],
            },
            last_checkin_unix: 0,
            armed: false,
        }
    }

    #[test]
    fn disarmed_returns_disarmed() {
        let cfg = sample();
        assert_eq!(evaluate(&cfg, 1_000_000), DeadmanStatus::Disarmed);
    }

    #[test]
    fn just_checked_in_is_fresh() {
        let mut cfg = sample();
        cfg.arm(1_000_000);
        assert_eq!(evaluate(&cfg, 1_000_001), DeadmanStatus::Fresh);
    }

    #[test]
    fn inside_warning_window() {
        let mut cfg = sample();
        cfg.arm(0);
        // 23h elapsed → 1h remaining → warning
        let now = 23 * 3600;
        match evaluate(&cfg, now) {
            DeadmanStatus::Warning { remaining } => {
                assert_eq!(remaining, 3600);
            }
            other => panic!("expected Warning, got {other:?}"),
        }
    }

    #[test]
    fn expired_fires_action() {
        let mut cfg = sample();
        cfg.arm(0);
        let now = 86_400 + 60; // 1 day + 60s
        match evaluate(&cfg, now) {
            DeadmanStatus::Fire { late_by, action } => {
                assert_eq!(late_by, 60);
                assert!(matches!(action, TriggerAction::AlertContacts { .. }));
            }
            other => panic!("expected Fire, got {other:?}"),
        }
    }

    #[test]
    fn check_in_resets_timer() {
        let mut cfg = sample();
        cfg.arm(0);
        // Advance near expiry
        assert!(matches!(
            evaluate(&cfg, 86_000),
            DeadmanStatus::Warning { .. }
        ));
        // Check in
        cfg.check_in(86_000);
        // Now fresh again
        assert_eq!(evaluate(&cfg, 86_001), DeadmanStatus::Fresh);
    }

    #[test]
    fn disarm_stops_firing() {
        let mut cfg = sample();
        cfg.arm(0);
        // Past expiry, would normally fire
        assert!(matches!(
            evaluate(&cfg, 100_000),
            DeadmanStatus::Fire { .. }
        ));
        cfg.disarm();
        assert_eq!(evaluate(&cfg, 100_000), DeadmanStatus::Disarmed);
    }

    #[test]
    fn simple_key_erase_builds_a_config() {
        let keys = vec![KeyId::new(), KeyId::new()];
        let cfg = simple_key_erase(keys.clone()).unwrap();
        assert_eq!(cfg.dead_seconds, 7 * 86_400);
        assert_eq!(cfg.warning_seconds, 86_400);
        match &cfg.action {
            TriggerAction::EraseKey { key_ids } => assert_eq!(key_ids.len(), 2),
            other => panic!("expected EraseKey, got {other:?}"),
        }
    }

    #[test]
    fn negative_elapsed_clocks_are_treated_as_fresh() {
        // now < last_checkin would normally overflow u64 cast. The
        // saturating_sub(..).max(0) pattern in evaluate() must keep
        // that case at Fresh (user appears to be in the past —
        // clock skew, not expiry).
        let mut cfg = sample();
        cfg.arm(1_000_000);
        // now < last_checkin
        assert_eq!(evaluate(&cfg, 500_000), DeadmanStatus::Fresh);
    }

    #[test]
    fn extreme_past_checkin_fires_correctly() {
        // If the user armed at Unix time 0 and evaluates years
        // later, dead_seconds has definitely been exceeded.
        let mut cfg = sample();
        cfg.arm(0);
        let now_2030 = 1_900_000_000; // ~2030
        match evaluate(&cfg, now_2030) {
            DeadmanStatus::Fire { late_by, .. } => {
                // dead_seconds is 86_400 so late_by should be
                // ~1.9B minus 86_400.
                assert!(late_by > 1_000_000_000);
            }
            other => panic!("expected Fire, got {other:?}"),
        }
    }

    #[test]
    fn i64_min_checkin_does_not_overflow() {
        // An adversarially crafted last_checkin_unix at i64::MIN
        // would make now_unix - last_checkin overflow if not
        // saturating. The saturating_sub pattern must clamp.
        let mut cfg = sample();
        cfg.armed = true;
        cfg.last_checkin_unix = i64::MIN;
        // Any positive now should see elapsed = saturating to
        // u64::MAX (post-as-cast, after saturating_sub) or be
        // Fire without panicking.
        let result = std::panic::catch_unwind(|| evaluate(&cfg, 1_000_000_000));
        assert!(
            result.is_ok(),
            "evaluate must not panic on i64::MIN checkin"
        );
        // And whatever status it returns, it should not be Disarmed
        // (armed is true) nor Fresh (elapsed is huge).
        match result.unwrap() {
            DeadmanStatus::Fire { .. } | DeadmanStatus::Warning { .. } => {}
            other => panic!("expected Fire/Warning, got {other:?}"),
        }
    }

    #[test]
    fn check_in_then_immediate_eval_is_fresh() {
        let mut cfg = sample();
        cfg.arm(2_000_000_000);
        assert_eq!(evaluate(&cfg, 2_000_000_000), DeadmanStatus::Fresh);
    }

    #[test]
    fn composite_action_preserved_in_fire() {
        let mut cfg = sample();
        cfg.action = TriggerAction::Composite(vec![
            TriggerAction::AlertContacts {
                channels: vec!["a".into()],
            },
            TriggerAction::WipePaths {
                paths: vec![PathBuf::from("/tmp/evidence")],
            },
        ]);
        cfg.arm(0);
        match evaluate(&cfg, 100_000) {
            DeadmanStatus::Fire {
                action: TriggerAction::Composite(inner),
                ..
            } => {
                assert_eq!(inner.len(), 2);
            }
            other => panic!("expected composite Fire, got {other:?}"),
        }
    }
}
