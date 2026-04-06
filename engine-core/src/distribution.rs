//! Distribution sampler — weighted random selection for realistic behavior.

use rand::Rng;
use rand::seq::SliceRandom;
use rand::rngs::StdRng;
use rand::SeedableRng;
use serde::{Deserialize, Serialize};

/// A weighted item.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WeightedItem<T> {
    pub value: T,
    pub weight: f64,
}

impl<T: Clone> WeightedItem<T> {
    pub fn new(value: T, weight: f64) -> Self {
        Self { value, weight }
    }
}

/// Weighted distribution sampler.
pub struct Distribution<T: Clone> {
    items: Vec<WeightedItem<T>>,
    total_weight: f64,
    rng: StdRng,
}

impl<T: Clone> Distribution<T> {
    pub fn new(seed: u64) -> Self {
        Self {
            items: Vec::new(),
            total_weight: 0.0,
            rng: StdRng::seed_from_u64(seed),
        }
    }

    pub fn from_entropy() -> Self {
        Self {
            items: Vec::new(),
            total_weight: 0.0,
            rng: StdRng::from_entropy(),
        }
    }

    /// Add a weighted item.
    pub fn add(&mut self, value: T, weight: f64) {
        if weight <= 0.0 { return; }
        self.total_weight += weight;
        self.items.push(WeightedItem { value, weight });
    }

    /// Sample a single item.
    pub fn sample(&mut self) -> Option<&T> {
        if self.items.is_empty() || self.total_weight == 0.0 {
            return None;
        }
        let mut target: f64 = self.rng.r#gen::<f64>() * self.total_weight;
        for item in &self.items {
            target -= item.weight;
            if target <= 0.0 {
                return Some(&item.value);
            }
        }
        self.items.last().map(|i| &i.value)
    }

    /// Sample without replacement.
    pub fn sample_many(&mut self, n: usize) -> Vec<&T> {
        let mut results = Vec::new();
        let mut remaining: Vec<(f64, usize)> = self.items.iter().enumerate()
            .map(|(i, item)| (item.weight, i)).collect();
        let mut total = self.total_weight;
        for _ in 0..n.min(self.items.len()) {
            if total <= 0.0 { break; }
            let mut target: f64 = self.rng.r#gen::<f64>() * total;
            let mut chosen = None;
            for (idx, (w, orig_idx)) in remaining.iter().enumerate() {
                target -= w;
                if target <= 0.0 {
                    chosen = Some((idx, *orig_idx));
                    break;
                }
            }
            if let Some((idx, orig_idx)) = chosen {
                results.push(&self.items[orig_idx].value);
                total -= remaining[idx].0;
                remaining.swap_remove(idx);
            }
        }
        results
    }

    /// Uniform random pick (ignoring weights).
    pub fn sample_uniform(&mut self) -> Option<&T> {
        self.items.choose(&mut self.rng).map(|i| &i.value)
    }

    /// Number of items.
    pub fn len(&self) -> usize {
        self.items.len()
    }

    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }

    /// Total weight.
    pub fn total_weight(&self) -> f64 {
        self.total_weight
    }

    /// Clear all items.
    pub fn clear(&mut self) {
        self.items.clear();
        self.total_weight = 0.0;
    }

    /// Normalize weights so they sum to 1.0.
    pub fn normalize(&mut self) {
        if self.total_weight == 0.0 { return; }
        for item in &mut self.items {
            item.weight /= self.total_weight;
        }
        self.total_weight = 1.0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[test]
    fn test_add_and_count() {
        let mut d = Distribution::new(42);
        d.add("a", 1.0);
        d.add("b", 2.0);
        assert_eq!(d.len(), 2);
    }

    #[test]
    fn test_zero_weight_ignored() {
        let mut d = Distribution::new(42);
        d.add("a", 0.0);
        assert_eq!(d.len(), 0);
    }

    #[test]
    fn test_sample() {
        let mut d = Distribution::new(42);
        d.add("a", 1.0);
        d.add("b", 1.0);
        assert!(d.sample().is_some());
    }

    #[test]
    fn test_sample_frequency() {
        let mut d = Distribution::new(42);
        d.add("common", 9.0);
        d.add("rare", 1.0);
        let mut counts = HashMap::new();
        for _ in 0..1000 {
            let s = d.sample().unwrap();
            *counts.entry(*s).or_insert(0) += 1;
        }
        // Common should dominate roughly 9:1.
        assert!(counts["common"] > counts["rare"] * 2);
    }

    #[test]
    fn test_sample_many_no_dup() {
        let mut d = Distribution::new(42);
        d.add("a", 1.0);
        d.add("b", 1.0);
        d.add("c", 1.0);
        let samples = d.sample_many(3);
        assert_eq!(samples.len(), 3);
        // All distinct.
        let set: std::collections::HashSet<_> = samples.into_iter().collect();
        assert_eq!(set.len(), 3);
    }

    #[test]
    fn test_empty_sample() {
        let mut d: Distribution<i32> = Distribution::new(42);
        assert!(d.sample().is_none());
    }

    #[test]
    fn test_uniform_sample() {
        let mut d = Distribution::new(42);
        d.add("a", 100.0);
        d.add("b", 1.0);
        assert!(d.sample_uniform().is_some());
    }

    #[test]
    fn test_total_weight() {
        let mut d = Distribution::new(42);
        d.add("a", 1.0);
        d.add("b", 2.0);
        d.add("c", 3.0);
        assert_eq!(d.total_weight(), 6.0);
    }

    #[test]
    fn test_normalize() {
        let mut d = Distribution::new(42);
        d.add("a", 2.0);
        d.add("b", 8.0);
        d.normalize();
        assert!((d.total_weight - 1.0).abs() < 0.01);
    }

    #[test]
    fn test_clear() {
        let mut d = Distribution::new(42);
        d.add("a", 1.0);
        d.clear();
        assert!(d.is_empty());
    }

    #[test]
    fn test_deterministic_with_same_seed() {
        let mut a = Distribution::new(42);
        a.add("x", 1.0);
        a.add("y", 1.0);
        let mut b = Distribution::new(42);
        b.add("x", 1.0);
        b.add("y", 1.0);
        assert_eq!(a.sample(), b.sample());
    }
}
