//! Engine configuration — intensity levels, active generators, resource limits.

use crate::profile::RiskLevel;
use crate::traits::DataCategory;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

/// Top-level engine configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EngineConfig {
    /// Which data categories are enabled for generation.
    pub active_categories: HashSet<DataCategory>,
    /// Overall risk/intensity level.
    pub risk_level: RiskLevel,
    /// Resource limits to prevent excessive usage.
    pub resource_limits: ResourceLimits,
    /// Whether to validate plausibility before emitting artifacts.
    pub validate_plausibility: bool,
}

impl Default for EngineConfig {
    fn default() -> Self {
        let mut categories = HashSet::new();
        categories.insert(DataCategory::BrowserActivity);
        categories.insert(DataCategory::FileSystem);

        Self {
            active_categories: categories,
            risk_level: RiskLevel::Medium,
            resource_limits: ResourceLimits::default(),
            validate_plausibility: true,
        }
    }
}

impl EngineConfig {
    /// Check if a data category is enabled.
    pub fn is_category_enabled(&self, category: DataCategory) -> bool {
        self.active_categories.contains(&category)
    }

    /// Enable all data categories.
    ///
    /// REGRESSION-GUARD: this used to manually enumerate every
    /// variant of `DataCategory`. Adding a new variant would have
    /// silently failed to enable it — no compiler warning. Now
    /// driven by `DataCategory::ALL`, which carries an
    /// `_all_variants_covered_check` that does fail to compile if
    /// a new variant is added without updating the slice.
    pub fn enable_all_categories(&mut self) {
        for category in DataCategory::ALL.iter().copied() {
            self.active_categories.insert(category);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_enable_all_categories_covers_every_variant() {
        let mut cfg = EngineConfig::default();
        cfg.active_categories.clear();
        cfg.enable_all_categories();
        // The set must contain every variant of DataCategory.
        // If a future PR adds a new variant without updating
        // DataCategory::ALL, this test fails because the count
        // mismatch is detected here AND the compile-time check
        // in traits.rs fires.
        assert_eq!(cfg.active_categories.len(), DataCategory::ALL.len());
        for cat in DataCategory::ALL {
            assert!(
                cfg.active_categories.contains(cat),
                "enable_all_categories missed variant: {cat:?}",
            );
        }
    }

    #[test]
    fn test_default_config_has_minimal_categories() {
        let cfg = EngineConfig::default();
        // The default is intentionally NOT all categories — only
        // browser and filesystem. This is the conservative shipping
        // default; tests that depend on a richer set must call
        // enable_all_categories explicitly.
        assert!(cfg.is_category_enabled(DataCategory::BrowserActivity));
        assert!(cfg.is_category_enabled(DataCategory::FileSystem));
        assert!(!cfg.is_category_enabled(DataCategory::Network));
    }

    #[test]
    fn test_resource_limits_default_is_conservative() {
        let limits = ResourceLimits::default();
        assert!(limits.max_cpu_percent <= 10);
        assert!(limits.max_disk_bytes_per_hour <= 1024 * 1024 * 1024);
        assert!(limits.max_memory_bytes <= 1024 * 1024 * 1024);
    }
}

/// Resource limits to prevent the engine from consuming excessive system resources.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceLimits {
    /// Maximum disk bytes to write per hour.
    pub max_disk_bytes_per_hour: u64,
    /// Maximum CPU percentage to use (0-100).
    pub max_cpu_percent: u8,
    /// Maximum number of artifacts to generate per hour.
    pub max_artifacts_per_hour: u64,
    /// Maximum memory usage in bytes.
    pub max_memory_bytes: u64,
}

impl Default for ResourceLimits {
    fn default() -> Self {
        Self {
            max_disk_bytes_per_hour: 100 * 1024 * 1024, // 100 MiB
            max_cpu_percent: 5,
            max_artifacts_per_hour: 500,
            max_memory_bytes: 256 * 1024 * 1024, // 256 MiB
        }
    }
}
