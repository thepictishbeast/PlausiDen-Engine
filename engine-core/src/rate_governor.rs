//! Rate governor — throttle artifact generation to organic rhythms.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::{Duration, Instant};

/// Throttling policy for artifact generation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RatePolicy {
    /// Max artifacts per minute.
    pub per_minute: u32,
    /// Max artifacts per hour.
    pub per_hour: u32,
    /// Minimum delay between generations (milliseconds).
    pub min_gap_ms: u64,
    /// Per-category overrides.
    pub category_overrides: HashMap<String, u32>,
}

impl Default for RatePolicy {
    fn default() -> Self {
        Self {
            per_minute: 20,
            per_hour: 300,
            min_gap_ms: 500,
            category_overrides: HashMap::new(),
        }
    }
}

impl RatePolicy {
    /// Conservative rate for paranoid profiles.
    pub fn paranoid() -> Self {
        Self {
            per_minute: 5,
            per_hour: 60,
            min_gap_ms: 2000,
            category_overrides: HashMap::new(),
        }
    }

    /// Aggressive rate for bulk pollution.
    pub fn aggressive() -> Self {
        Self {
            per_minute: 60,
            per_hour: 1200,
            min_gap_ms: 100,
            category_overrides: HashMap::new(),
        }
    }
}

/// A single generation attempt event.
#[derive(Debug, Clone)]
struct GenEvent {
    category: String,
    timestamp: Instant,
}

/// Rate governor for artifact generation.
pub struct RateGovernor {
    policy: RatePolicy,
    events: Vec<GenEvent>,
    last_gen: Option<Instant>,
    /// Total artifacts throttled.
    throttled_count: u64,
    /// Total artifacts permitted.
    permitted_count: u64,
}

impl RateGovernor {
    pub fn new(policy: RatePolicy) -> Self {
        Self {
            policy,
            events: Vec::new(),
            last_gen: None,
            throttled_count: 0,
            permitted_count: 0,
        }
    }

    /// Check whether a new artifact may be generated right now.
    /// Returns Ok(()) or Err with the reason.
    pub fn check(&mut self, category: &str) -> Result<(), ThrottleReason> {
        self.prune_old();

        let now = Instant::now();

        // Min gap.
        if let Some(last) = self.last_gen {
            let elapsed = now.duration_since(last);
            if elapsed < Duration::from_millis(self.policy.min_gap_ms) {
                self.throttled_count += 1;
                return Err(ThrottleReason::MinGap);
            }
        }

        // Per-minute limit.
        //
        // BUG ASSUMPTION: early in process life, `now` may be small
        // enough that `now - Duration::from_secs(60)` would underflow
        // and panic on some platforms (notably macOS monotonic clocks
        // that start near zero). `checked_sub` returns None in that
        // case, which we treat as "no events are old enough to have
        // fallen outside the window" and count every event.
        let minute_ago = now.checked_sub(Duration::from_secs(60));
        let minute_count = match minute_ago {
            Some(t) => self.events.iter().filter(|e| e.timestamp >= t).count() as u32,
            None => self.events.len() as u32,
        };
        if minute_count >= self.policy.per_minute {
            self.throttled_count += 1;
            return Err(ThrottleReason::PerMinute);
        }

        // Per-hour limit.
        let hour_ago = now.checked_sub(Duration::from_secs(3600));
        let hour_count = match hour_ago {
            Some(t) => self.events.iter().filter(|e| e.timestamp >= t).count() as u32,
            None => self.events.len() as u32,
        };
        if hour_count >= self.policy.per_hour {
            self.throttled_count += 1;
            return Err(ThrottleReason::PerHour);
        }

        // Per-category override.
        if let Some(&limit) = self.policy.category_overrides.get(category) {
            let cat_count = match minute_ago {
                Some(t) => self
                    .events
                    .iter()
                    .filter(|e| e.category == category && e.timestamp >= t)
                    .count() as u32,
                None => self
                    .events
                    .iter()
                    .filter(|e| e.category == category)
                    .count() as u32,
            };
            if cat_count >= limit {
                self.throttled_count += 1;
                return Err(ThrottleReason::CategoryLimit);
            }
        }

        Ok(())
    }

    /// Record that a generation occurred.
    ///
    /// BUG ASSUMPTION: callers may use `record()` without calling
    /// `check()` first (for example when replaying a historical
    /// stream into the governor). In the earlier implementation the
    /// events Vec grew without bound in that case because prune_old
    /// only ran inside check(). We now prune inside record() too,
    /// so the steady-state memory footprint is bounded by the per-
    /// hour window regardless of caller discipline.
    pub fn record(&mut self, category: &str) {
        self.prune_old();
        let now = Instant::now();
        self.events.push(GenEvent {
            category: category.into(),
            timestamp: now,
        });
        self.last_gen = Some(now);
        self.permitted_count += 1;
    }

    /// Check and record atomically. Returns true if permitted.
    pub fn check_and_record(&mut self, category: &str) -> bool {
        match self.check(category) {
            Ok(()) => {
                self.record(category);
                true
            }
            Err(_) => false,
        }
    }

    fn prune_old(&mut self) {
        if let Some(cutoff) = Instant::now().checked_sub(Duration::from_secs(3600)) {
            self.events.retain(|e| e.timestamp >= cutoff);
        }
        // If the subtraction would underflow, keep everything —
        // nothing is old enough to prune yet.
    }

    /// Current per-minute usage.
    pub fn current_minute_count(&self) -> u32 {
        match Instant::now().checked_sub(Duration::from_secs(60)) {
            Some(t) => self.events.iter().filter(|e| e.timestamp >= t).count() as u32,
            None => self.events.len() as u32,
        }
    }

    /// Current per-hour usage.
    pub fn current_hour_count(&self) -> u32 {
        match Instant::now().checked_sub(Duration::from_secs(3600)) {
            Some(t) => self.events.iter().filter(|e| e.timestamp >= t).count() as u32,
            None => self.events.len() as u32,
        }
    }

    /// Approximate time until next generation is allowed, given last-gen gap.
    pub fn time_until_ok(&self) -> Duration {
        if let Some(last) = self.last_gen {
            let elapsed = Instant::now().duration_since(last);
            let min = Duration::from_millis(self.policy.min_gap_ms);
            if elapsed < min {
                return min - elapsed;
            }
        }
        Duration::from_millis(0)
    }

    pub fn throttled_count(&self) -> u64 {
        self.throttled_count
    }
    pub fn permitted_count(&self) -> u64 {
        self.permitted_count
    }
}

/// Reason a generation was throttled.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ThrottleReason {
    MinGap,
    PerMinute,
    PerHour,
    CategoryLimit,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;

    #[test]
    fn test_default_policy() {
        let p = RatePolicy::default();
        assert_eq!(p.per_minute, 20);
        assert_eq!(p.per_hour, 300);
    }

    #[test]
    fn test_paranoid_is_stricter_than_default() {
        let d = RatePolicy::default();
        let p = RatePolicy::paranoid();
        assert!(p.per_minute < d.per_minute);
        assert!(p.min_gap_ms > d.min_gap_ms);
    }

    #[test]
    fn test_first_generation_allowed() {
        let mut g = RateGovernor::new(RatePolicy::default());
        assert!(g.check("browser").is_ok());
    }

    #[test]
    fn test_min_gap_throttles() {
        let policy = RatePolicy {
            min_gap_ms: 100,
            per_minute: 100,
            per_hour: 1000,
            category_overrides: HashMap::new(),
        };
        let mut g = RateGovernor::new(policy);
        g.record("browser");
        assert_eq!(g.check("browser"), Err(ThrottleReason::MinGap));
    }

    #[test]
    fn test_per_minute_limit() {
        let policy = RatePolicy {
            per_minute: 3,
            per_hour: 100,
            min_gap_ms: 0,
            category_overrides: HashMap::new(),
        };
        let mut g = RateGovernor::new(policy);
        for _ in 0..3 {
            g.record("x");
        }
        assert_eq!(g.check("x"), Err(ThrottleReason::PerMinute));
    }

    #[test]
    fn test_category_override() {
        let mut overrides = HashMap::new();
        overrides.insert("chatty".to_string(), 2u32);
        let policy = RatePolicy {
            per_minute: 100,
            per_hour: 1000,
            min_gap_ms: 0,
            category_overrides: overrides,
        };
        let mut g = RateGovernor::new(policy);
        g.record("chatty");
        g.record("chatty");
        assert_eq!(g.check("chatty"), Err(ThrottleReason::CategoryLimit));
        // Other categories still allowed.
        assert!(g.check("other").is_ok());
    }

    #[test]
    fn test_check_and_record() {
        let policy = RatePolicy {
            per_minute: 2,
            per_hour: 100,
            min_gap_ms: 0,
            category_overrides: HashMap::new(),
        };
        let mut g = RateGovernor::new(policy);
        assert!(g.check_and_record("x"));
        assert!(g.check_and_record("x"));
        assert!(!g.check_and_record("x"));
        assert_eq!(g.permitted_count(), 2);
        assert_eq!(g.throttled_count(), 1);
    }

    #[test]
    fn test_time_until_ok() {
        let policy = RatePolicy {
            per_minute: 100,
            per_hour: 1000,
            min_gap_ms: 50,
            category_overrides: HashMap::new(),
        };
        let mut g = RateGovernor::new(policy);
        g.record("x");
        let wait = g.time_until_ok();
        assert!(wait.as_millis() <= 50);
        thread::sleep(Duration::from_millis(60));
        assert!(g.time_until_ok().as_millis() == 0);
    }

    // REGRESSION-GUARD: record() must prune the events vec. The
    // earlier implementation only pruned inside check(), so a
    // caller that drove record() directly would grow the events
    // vec without bound. We can't test "forever" but we can prove
    // record() calls prune_old because otherwise a fake event
    // placed more than an hour in the past would survive a
    // subsequent record().
    #[test]
    fn test_record_prunes_old_events() {
        let mut g = RateGovernor::new(RatePolicy::default());
        // Inject a synthetic event 2 hours in the past.
        let ancient = Instant::now()
            .checked_sub(Duration::from_secs(7200))
            .expect("instant supports 2h subtraction on test platforms");
        g.events.push(GenEvent {
            category: "x".into(),
            timestamp: ancient,
        });
        assert_eq!(g.events.len(), 1);

        // Record a fresh event. prune_old inside record() should
        // have dropped the ancient one.
        g.record("x");
        assert_eq!(
            g.events.len(),
            1,
            "record() should have pruned the 2-hour-old event",
        );
    }

    #[test]
    fn test_check_is_checked_sub_safe() {
        // Even with a completely empty governor, check() should
        // never panic — the checked_sub fix handles freshly-booted
        // Instants. This is the minimal guard against the
        // platform-specific underflow panic.
        let mut g = RateGovernor::new(RatePolicy::default());
        // Just run check a few times in a row; any panic fails.
        for _ in 0..10 {
            let _ = g.check("x");
        }
        // No assertion needed — test passes if we did not panic.
    }
}
