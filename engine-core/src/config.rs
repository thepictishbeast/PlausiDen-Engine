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
    pub fn enable_all_categories(&mut self) {
        self.active_categories.insert(DataCategory::BrowserActivity);
        self.active_categories.insert(DataCategory::FileSystem);
        self.active_categories.insert(DataCategory::Communications);
        self.active_categories.insert(DataCategory::Location);
        self.active_categories.insert(DataCategory::Network);
        self.active_categories.insert(DataCategory::Input);
        self.active_categories.insert(DataCategory::System);
        self.active_categories.insert(DataCategory::Social);
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
