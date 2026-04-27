//! Profile mixer — compose user profiles by blending base archetypes.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// A named archetype profile with baseline characteristics.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Archetype {
    pub id: String,
    pub label: String,
    /// Per-category activity weights (0.0-1.0).
    pub weights: HashMap<String, f64>,
    /// Preferred generation hours (0-23).
    pub active_hours: Vec<u8>,
    /// Days of the week most active.
    pub active_days: Vec<u8>,
    /// Typical session duration in minutes.
    pub session_minutes: (u32, u32),
    /// Interests (tag list).
    pub interests: Vec<String>,
}

impl Archetype {
    /// Weekday office worker.
    pub fn office_worker() -> Self {
        let mut weights = HashMap::new();
        weights.insert("browser".into(), 0.9);
        weights.insert("email".into(), 0.85);
        weights.insert("documents".into(), 0.75);
        weights.insert("messaging".into(), 0.5);
        weights.insert("social".into(), 0.2);
        weights.insert("games".into(), 0.05);
        Self {
            id: "office".into(),
            label: "Office worker".into(),
            weights,
            active_hours: (8..=18).collect(),
            active_days: vec![1, 2, 3, 4, 5],
            session_minutes: (30, 240),
            interests: vec!["news".into(), "work".into(), "productivity".into()],
        }
    }

    /// Student.
    pub fn student() -> Self {
        let mut weights = HashMap::new();
        weights.insert("browser".into(), 0.8);
        weights.insert("email".into(), 0.4);
        weights.insert("documents".into(), 0.6);
        weights.insert("messaging".into(), 0.9);
        weights.insert("social".into(), 0.85);
        weights.insert("games".into(), 0.4);
        weights.insert("streaming".into(), 0.7);
        Self {
            id: "student".into(),
            label: "Student".into(),
            weights,
            active_hours: (9..=23).collect(),
            active_days: (0..=6).collect(),
            session_minutes: (15, 180),
            interests: vec![
                "music".into(),
                "memes".into(),
                "study".into(),
                "gaming".into(),
            ],
        }
    }

    /// Journalist.
    pub fn journalist() -> Self {
        let mut weights = HashMap::new();
        weights.insert("browser".into(), 0.95);
        weights.insert("email".into(), 0.8);
        weights.insert("documents".into(), 0.85);
        weights.insert("messaging".into(), 0.9);
        weights.insert("social".into(), 0.6);
        weights.insert("news_research".into(), 0.95);
        Self {
            id: "journalist".into(),
            label: "Journalist".into(),
            weights,
            active_hours: (0..=23).collect(),
            active_days: (0..=6).collect(),
            session_minutes: (10, 300),
            interests: vec![
                "politics".into(),
                "technology".into(),
                "current_events".into(),
            ],
        }
    }

    /// Retiree.
    pub fn retiree() -> Self {
        let mut weights = HashMap::new();
        weights.insert("browser".into(), 0.5);
        weights.insert("email".into(), 0.3);
        weights.insert("news".into(), 0.6);
        weights.insert("games".into(), 0.3);
        weights.insert("photos".into(), 0.4);
        Self {
            id: "retiree".into(),
            label: "Retiree".into(),
            weights,
            active_hours: (7..=21).collect(),
            active_days: (0..=6).collect(),
            session_minutes: (20, 90),
            interests: vec!["gardening".into(), "recipes".into(), "news".into()],
        }
    }

    /// Developer.
    pub fn developer() -> Self {
        let mut weights = HashMap::new();
        weights.insert("browser".into(), 0.85);
        weights.insert("documents".into(), 0.4);
        weights.insert("source_code".into(), 0.95);
        weights.insert("terminal".into(), 0.9);
        weights.insert("messaging".into(), 0.6);
        Self {
            id: "developer".into(),
            label: "Developer".into(),
            weights,
            active_hours: (9..=23).collect(),
            active_days: (0..=6).collect(),
            session_minutes: (30, 360),
            interests: vec!["programming".into(), "tech".into(), "open_source".into()],
        }
    }
}

/// Profile mixer.
pub struct ProfileMixer {
    archetypes: HashMap<String, Archetype>,
}

impl ProfileMixer {
    pub fn new() -> Self {
        let mut m = Self {
            archetypes: HashMap::new(),
        };
        for archetype in [
            Archetype::office_worker(),
            Archetype::student(),
            Archetype::journalist(),
            Archetype::retiree(),
            Archetype::developer(),
        ] {
            m.archetypes.insert(archetype.id.clone(), archetype);
        }
        m
    }

    /// Add a custom archetype.
    pub fn add(&mut self, archetype: Archetype) {
        self.archetypes.insert(archetype.id.clone(), archetype);
    }

    /// Get an archetype by id.
    pub fn get(&self, id: &str) -> Option<&Archetype> {
        self.archetypes.get(id)
    }

    /// Mix multiple archetypes with weights (summing to 1.0).
    ///
    /// BUG ASSUMPTION: callers may pass mixes that include unknown
    /// archetype ids (typos, stale config). The earlier
    /// implementation silently dropped unknown ids and, if EVERY id
    /// was unknown, returned `Some(Archetype)` with degenerate
    /// fields (session_minutes = (u32::MAX, 0), empty weights).
    /// That looked like success but produced an unusable profile.
    ///
    /// The fix is to recompute total_weight from the IDs that were
    /// actually found and refuse if the surviving total is zero.
    /// Returns None if the input is empty, every weight is zero, or
    /// no requested archetype id exists in the registry.
    pub fn mix(&self, mix: &[(String, f64)]) -> Option<Archetype> {
        if mix.is_empty() {
            return None;
        }

        // Total weight over the SURVIVING ids, not the requested
        // ones. An entry with an unknown id contributes zero.
        let surviving_total: f64 = mix
            .iter()
            .filter_map(|(id, w)| self.archetypes.get(id).map(|_| *w))
            .sum();
        if surviving_total <= 0.0 {
            return None;
        }

        let mut combined_weights: HashMap<String, f64> = HashMap::new();
        let mut combined_interests: std::collections::HashSet<String> =
            std::collections::HashSet::new();
        let mut combined_hours: std::collections::HashSet<u8> = std::collections::HashSet::new();
        let mut combined_days: std::collections::HashSet<u8> = std::collections::HashSet::new();
        let mut min_session: u32 = u32::MAX;
        let mut max_session: u32 = 0;
        let mut label_parts = Vec::new();
        let mut applied = 0usize;

        for (id, weight) in mix {
            let normalized = weight / surviving_total;
            if let Some(arch) = self.archetypes.get(id) {
                for (k, v) in &arch.weights {
                    *combined_weights.entry(k.clone()).or_insert(0.0) += v * normalized;
                }
                for h in &arch.active_hours {
                    combined_hours.insert(*h);
                }
                for d in &arch.active_days {
                    combined_days.insert(*d);
                }
                for i in &arch.interests {
                    combined_interests.insert(i.clone());
                }
                if arch.session_minutes.0 < min_session {
                    min_session = arch.session_minutes.0;
                }
                if arch.session_minutes.1 > max_session {
                    max_session = arch.session_minutes.1;
                }
                label_parts.push(arch.label.clone());
                applied += 1;
            }
        }

        // Defence in depth: if surviving_total > 0 but applied == 0
        // we are in an inconsistent state — refuse rather than emit
        // a corrupt Archetype with sentinel session_minutes.
        if applied == 0 {
            return None;
        }

        Some(Archetype {
            id: "mixed".into(),
            label: label_parts.join(" + "),
            weights: combined_weights,
            active_hours: {
                let mut v: Vec<u8> = combined_hours.into_iter().collect();
                v.sort();
                v
            },
            active_days: {
                let mut v: Vec<u8> = combined_days.into_iter().collect();
                v.sort();
                v
            },
            session_minutes: (min_session, max_session),
            interests: combined_interests.into_iter().collect(),
        })
    }

    /// List all archetypes.
    pub fn archetypes(&self) -> Vec<&Archetype> {
        self.archetypes.values().collect()
    }

    pub fn archetype_count(&self) -> usize {
        self.archetypes.len()
    }
}

impl Default for ProfileMixer {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_archetypes_loaded() {
        let m = ProfileMixer::new();
        assert!(m.get("office").is_some());
        assert!(m.get("student").is_some());
        assert!(m.get("journalist").is_some());
        assert!(m.get("retiree").is_some());
        assert!(m.get("developer").is_some());
    }

    #[test]
    fn test_office_worker_weights() {
        let arch = Archetype::office_worker();
        assert!(arch.weights["browser"] > 0.8);
        assert!(arch.weights["email"] > 0.8);
        assert!(arch.weights["games"] < 0.2);
    }

    #[test]
    fn test_mix_two_archetypes() {
        let m = ProfileMixer::new();
        let result = m
            .mix(&[("office".into(), 0.5), ("developer".into(), 0.5)])
            .unwrap();
        assert!(result.weights.contains_key("browser"));
        assert!(result.weights.contains_key("source_code"));
    }

    #[test]
    fn test_mix_weights_normalized() {
        let m = ProfileMixer::new();
        let result = m.mix(&[("office".into(), 2.0)]).unwrap();
        // Single archetype mix should preserve its weights approximately.
        assert!((result.weights["browser"] - 0.9).abs() < 0.01);
    }

    #[test]
    fn test_mix_empty_returns_none() {
        let m = ProfileMixer::new();
        assert!(m.mix(&[]).is_none());
    }

    #[test]
    fn test_mix_zero_weights() {
        let m = ProfileMixer::new();
        assert!(m.mix(&[("office".into(), 0.0)]).is_none());
    }

    #[test]
    fn test_add_custom_archetype() {
        let mut m = ProfileMixer::new();
        let custom = Archetype {
            id: "gamer".into(),
            label: "Gamer".into(),
            weights: HashMap::new(),
            // Gamer: 6pm-2am wraps midnight; chain the two halves so we
            // don't end up with a reversed-empty range that silently
            // produces zero hours (clippy::reversed_empty_ranges fires
            // on the naive (18..=2)).
            active_hours: (18..=23).chain(0..=2).collect(),
            active_days: (0..=6).collect(),
            session_minutes: (60, 360),
            interests: vec!["games".into()],
        };
        m.add(custom);
        assert!(m.get("gamer").is_some());
    }

    #[test]
    fn test_mix_interests_union() {
        let m = ProfileMixer::new();
        let result = m
            .mix(&[("office".into(), 0.5), ("student".into(), 0.5)])
            .unwrap();
        assert!(
            result.interests.contains(&"work".to_string())
                || result.interests.contains(&"study".to_string())
        );
    }

    #[test]
    fn test_journalist_active_all_hours() {
        let arch = Archetype::journalist();
        assert_eq!(arch.active_hours.len(), 24);
    }

    #[test]
    fn test_retiree_weekly_active() {
        let arch = Archetype::retiree();
        assert_eq!(arch.active_days.len(), 7);
    }

    #[test]
    fn test_archetype_count() {
        let m = ProfileMixer::new();
        assert_eq!(m.archetype_count(), 5);
    }

    // REGRESSION-GUARD: an earlier mix() returned Some(Archetype) for
    // a request whose every id was unknown, with degenerate
    // session_minutes = (u32::MAX, 0) and empty weights. The fix is
    // to refuse the mix when the surviving (recognised) weight is
    // zero.
    #[test]
    fn test_mix_all_unknown_ids_returns_none() {
        let m = ProfileMixer::new();
        let result = m.mix(&[("ghost".into(), 1.0), ("phantom".into(), 0.5)]);
        assert!(
            result.is_none(),
            "mix of only unknown ids must return None, got: {:?}",
            result.map(|a| a.session_minutes),
        );
    }

    #[test]
    fn test_mix_partial_unknown_ids_uses_surviving_only() {
        // One known + one unknown — surviving-only should still
        // produce a valid result whose weights match the known one
        // exactly (after re-normalising over the surviving total).
        let m = ProfileMixer::new();
        let result = m
            .mix(&[("office".into(), 0.5), ("ghost".into(), 0.5)])
            .expect("should still produce a result with one known id");
        // session_minutes should NOT be the sentinel pair.
        assert!(result.session_minutes.0 < result.session_minutes.1);
        // Weights should match the office archetype (within
        // floating tolerance).
        let office = Archetype::office_worker();
        for (k, v) in &office.weights {
            let mixed = result
                .weights
                .get(k)
                .copied()
                .expect("office weight key missing from mix");
            assert!(
                (mixed - v).abs() < 1e-9,
                "weight {k} drifted: mix={mixed}, office={v}",
            );
        }
    }

    #[test]
    fn test_mix_session_minutes_never_sentinel_after_fix() {
        // Defence-in-depth check: after the fix, no successful mix
        // should report session_minutes.0 == u32::MAX or .1 == 0.
        let m = ProfileMixer::new();
        let result = m
            .mix(&[("office".into(), 1.0)])
            .expect("known id must succeed");
        assert!(result.session_minutes.0 < u32::MAX);
        assert!(result.session_minutes.1 > 0);
    }
}
