//! Seed chain — deterministic reproducible RNG streams for test and replay.

use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// A labeled seed in the chain.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Seed {
    pub label: String,
    pub seed: u64,
    pub parent: Option<String>,
    pub depth: u32,
}

/// Hierarchical seed chain for deterministic RNG derivation.
pub struct SeedChain {
    seeds: HashMap<String, Seed>,
    root: u64,
}

impl SeedChain {
    pub fn new(root: u64) -> Self {
        let mut chain = Self {
            seeds: HashMap::new(),
            root,
        };
        chain.seeds.insert("root".into(), Seed {
            label: "root".into(),
            seed: root,
            parent: None,
            depth: 0,
        });
        chain
    }

    /// Derive a child seed from a parent label.
    pub fn derive(&mut self, parent_label: &str, child_label: &str) -> Option<u64> {
        let parent = self.seeds.get(parent_label)?.clone();
        let child_seed = mix_seed(parent.seed, child_label);
        self.seeds.insert(child_label.into(), Seed {
            label: child_label.into(),
            seed: child_seed,
            parent: Some(parent_label.into()),
            depth: parent.depth + 1,
        });
        Some(child_seed)
    }

    /// Get a seed by label.
    pub fn get_seed(&self, label: &str) -> Option<u64> {
        self.seeds.get(label).map(|s| s.seed)
    }

    /// Create a ChaCha20 RNG from a labeled seed.
    pub fn rng_for(&self, label: &str) -> Option<ChaCha20Rng> {
        let seed = self.get_seed(label)?;
        Some(ChaCha20Rng::seed_from_u64(seed))
    }

    /// Number of seeds in the chain.
    pub fn len(&self) -> usize {
        self.seeds.len()
    }

    pub fn is_empty(&self) -> bool { self.seeds.is_empty() }

    /// Root seed value.
    pub fn root(&self) -> u64 {
        self.root
    }

    /// All labels in the chain.
    pub fn labels(&self) -> Vec<&String> {
        self.seeds.keys().collect()
    }

    /// Children of a given seed.
    pub fn children_of(&self, parent_label: &str) -> Vec<&Seed> {
        self.seeds.values()
            .filter(|s| s.parent.as_deref() == Some(parent_label))
            .collect()
    }

    /// Remove a seed and its descendants.
    pub fn remove_subtree(&mut self, label: &str) -> usize {
        let mut to_remove: Vec<String> = vec![label.into()];
        let mut i = 0;
        while i < to_remove.len() {
            let current = to_remove[i].clone();
            let children: Vec<String> = self.seeds.values()
                .filter(|s| s.parent.as_deref() == Some(&current))
                .map(|s| s.label.clone())
                .collect();
            to_remove.extend(children);
            i += 1;
        }
        let count = to_remove.len();
        for label in to_remove {
            self.seeds.remove(&label);
        }
        count
    }

    /// Seeds at a specific depth.
    pub fn at_depth(&self, depth: u32) -> Vec<&Seed> {
        self.seeds.values().filter(|s| s.depth == depth).collect()
    }

    /// Max depth in the chain.
    pub fn max_depth(&self) -> u32 {
        self.seeds.values().map(|s| s.depth).max().unwrap_or(0)
    }
}

/// Mix a seed with a label deterministically.
fn mix_seed(parent: u64, label: &str) -> u64 {
    use std::hash::{Hasher};
    let mut h = std::collections::hash_map::DefaultHasher::new();
    h.write_u64(parent);
    h.write(label.as_bytes());
    h.finish()
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::RngCore;

    #[test]
    fn test_root_exists() {
        let chain = SeedChain::new(42);
        assert_eq!(chain.get_seed("root"), Some(42));
    }

    #[test]
    fn test_derive_child() {
        let mut chain = SeedChain::new(42);
        let child = chain.derive("root", "browser").unwrap();
        assert_ne!(child, 42);
    }

    #[test]
    fn test_deterministic_derivation() {
        let mut a = SeedChain::new(42);
        let mut b = SeedChain::new(42);
        let ca = a.derive("root", "browser").unwrap();
        let cb = b.derive("root", "browser").unwrap();
        assert_eq!(ca, cb);
    }

    #[test]
    fn test_different_labels_different_seeds() {
        let mut chain = SeedChain::new(42);
        let a = chain.derive("root", "browser").unwrap();
        let b = chain.derive("root", "filesystem").unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn test_rng_for_label() {
        let mut chain = SeedChain::new(42);
        chain.derive("root", "test").unwrap();
        let mut rng = chain.rng_for("test").unwrap();
        let _: u64 = rng.next_u64();
    }

    #[test]
    fn test_rng_reproducibility() {
        let mut chain = SeedChain::new(42);
        chain.derive("root", "browser").unwrap();
        let mut rng1 = chain.rng_for("browser").unwrap();
        let mut rng2 = chain.rng_for("browser").unwrap();
        assert_eq!(rng1.next_u64(), rng2.next_u64());
    }

    #[test]
    fn test_derive_unknown_parent() {
        let mut chain = SeedChain::new(42);
        assert!(chain.derive("missing", "child").is_none());
    }

    #[test]
    fn test_depth_tracking() {
        let mut chain = SeedChain::new(42);
        chain.derive("root", "a").unwrap();
        chain.derive("a", "b").unwrap();
        chain.derive("b", "c").unwrap();
        assert_eq!(chain.max_depth(), 3);
    }

    #[test]
    fn test_children_of() {
        let mut chain = SeedChain::new(42);
        chain.derive("root", "a").unwrap();
        chain.derive("root", "b").unwrap();
        chain.derive("a", "c").unwrap();
        assert_eq!(chain.children_of("root").len(), 2);
    }

    #[test]
    fn test_remove_subtree() {
        let mut chain = SeedChain::new(42);
        chain.derive("root", "a").unwrap();
        chain.derive("a", "b").unwrap();
        chain.derive("a", "c").unwrap();
        let removed = chain.remove_subtree("a");
        assert_eq!(removed, 3);
        assert!(chain.get_seed("a").is_none());
        assert!(chain.get_seed("root").is_some());
    }

    #[test]
    fn test_at_depth() {
        let mut chain = SeedChain::new(42);
        chain.derive("root", "a").unwrap();
        chain.derive("root", "b").unwrap();
        assert_eq!(chain.at_depth(1).len(), 2);
    }
}
