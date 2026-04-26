//! Artifact validator — verify generated artifacts meet plausibility rules.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// A validation rule for an artifact field.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Rule {
    /// Field must be non-empty.
    NotEmpty,
    /// Field must match one of the allowed values.
    AllowedValues(Vec<String>),
    /// Field length must be in [min, max], measured in BYTES, not
    /// in `char`s. For ASCII-only fields the two are the same; for
    /// multibyte text (UTF-8 emoji, CJK, accented Latin) a 5-char
    /// emoji string has byte length ≈ 20 and would fail
    /// `LengthRange(5, 10)`. Callers that want char-length semantics
    /// should multiply their bounds by 4 (the maximum UTF-8 char
    /// width) or pre-validate the field separately.
    LengthRange(usize, usize),
    /// Field must be parseable as a u64.
    IsInteger,
    /// Field must be parseable as an ISO 8601 datetime.
    IsTimestamp,
    /// Field must match one of these regex-like prefixes.
    StartsWithAny(Vec<String>),
    /// Field must be unique within the artifact batch.
    Unique,
    /// Field value must not match any denylist pattern.
    DenyPatterns(Vec<String>),
}

/// A validation issue.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValidationIssue {
    pub field: String,
    pub rule: String,
    pub message: String,
    pub severity: Severity,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Severity {
    Info,
    Warn,
    Error,
}

/// Artifact validator.
pub struct ArtifactValidator {
    rules: HashMap<String, Vec<Rule>>, // field → rules
}

impl ArtifactValidator {
    pub fn new() -> Self {
        Self {
            rules: HashMap::new(),
        }
    }

    /// Add a rule for a field.
    pub fn add_rule(&mut self, field: &str, rule: Rule) {
        self.rules.entry(field.into()).or_default().push(rule);
    }

    /// Validate a single artifact (field → value).
    pub fn validate(&self, artifact: &HashMap<String, String>) -> Vec<ValidationIssue> {
        let mut issues = Vec::new();
        for (field, rules) in &self.rules {
            let value = artifact.get(field).cloned().unwrap_or_default();
            for rule in rules {
                if let Some(issue) = self.check_rule(field, &value, rule) {
                    issues.push(issue);
                }
            }
        }
        issues
    }

    /// Validate a batch. Enforces Unique rules across the batch.
    pub fn validate_batch(&self, batch: &[HashMap<String, String>]) -> Vec<Vec<ValidationIssue>> {
        let mut results: Vec<Vec<ValidationIssue>> =
            batch.iter().map(|a| self.validate(a)).collect();

        // Unique fields across batch.
        for (field, rules) in &self.rules {
            if rules.iter().any(|r| matches!(r, Rule::Unique)) {
                let mut seen: HashMap<String, Vec<usize>> = HashMap::new();
                for (idx, artifact) in batch.iter().enumerate() {
                    if let Some(v) = artifact.get(field) {
                        seen.entry(v.clone()).or_default().push(idx);
                    }
                }
                for (_, indices) in seen {
                    if indices.len() > 1 {
                        for idx in indices.iter().skip(1) {
                            results[*idx].push(ValidationIssue {
                                field: field.clone(),
                                rule: "Unique".into(),
                                message: "duplicate value within batch".to_string(),
                                severity: Severity::Error,
                            });
                        }
                    }
                }
            }
        }
        results
    }

    fn check_rule(&self, field: &str, value: &str, rule: &Rule) -> Option<ValidationIssue> {
        match rule {
            Rule::NotEmpty => {
                if value.is_empty() {
                    Some(ValidationIssue {
                        field: field.into(),
                        rule: "NotEmpty".into(),
                        message: "field is empty".into(),
                        severity: Severity::Error,
                    })
                } else {
                    None
                }
            }
            Rule::AllowedValues(values) => {
                if !values.contains(&value.to_string()) {
                    Some(ValidationIssue {
                        field: field.into(),
                        rule: "AllowedValues".into(),
                        message: format!("'{}' not in allowlist", value),
                        severity: Severity::Error,
                    })
                } else {
                    None
                }
            }
            Rule::LengthRange(min, max) => {
                if value.len() < *min || value.len() > *max {
                    Some(ValidationIssue {
                        field: field.into(),
                        rule: "LengthRange".into(),
                        message: format!("length {} outside [{}, {}]", value.len(), min, max),
                        severity: Severity::Warn,
                    })
                } else {
                    None
                }
            }
            Rule::IsInteger => {
                if value.parse::<u64>().is_err() {
                    Some(ValidationIssue {
                        field: field.into(),
                        rule: "IsInteger".into(),
                        message: format!("'{}' not a valid integer", value),
                        severity: Severity::Error,
                    })
                } else {
                    None
                }
            }
            Rule::IsTimestamp => {
                if chrono::DateTime::parse_from_rfc3339(value).is_err() {
                    Some(ValidationIssue {
                        field: field.into(),
                        rule: "IsTimestamp".into(),
                        message: format!("'{}' not a valid ISO 8601 timestamp", value),
                        severity: Severity::Error,
                    })
                } else {
                    None
                }
            }
            Rule::StartsWithAny(prefixes) => {
                if !prefixes.iter().any(|p| value.starts_with(p)) {
                    Some(ValidationIssue {
                        field: field.into(),
                        rule: "StartsWithAny".into(),
                        message: format!("'{}' doesn't match any prefix", value),
                        severity: Severity::Warn,
                    })
                } else {
                    None
                }
            }
            Rule::DenyPatterns(patterns) => {
                for p in patterns {
                    if value.contains(p) {
                        return Some(ValidationIssue {
                            field: field.into(),
                            rule: "DenyPatterns".into(),
                            message: format!("value contains forbidden pattern '{}'", p),
                            severity: Severity::Error,
                        });
                    }
                }
                None
            }
            Rule::Unique => None, // handled at batch level
        }
    }

    pub fn rule_count(&self) -> usize {
        self.rules.values().map(|r| r.len()).sum()
    }
}

impl Default for ArtifactValidator {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn artifact(pairs: &[(&str, &str)]) -> HashMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    #[test]
    fn test_not_empty() {
        let mut v = ArtifactValidator::new();
        v.add_rule("url", Rule::NotEmpty);
        let issues = v.validate(&artifact(&[("url", "")]));
        assert_eq!(issues.len(), 1);
    }

    #[test]
    fn test_not_empty_ok() {
        let mut v = ArtifactValidator::new();
        v.add_rule("url", Rule::NotEmpty);
        let issues = v.validate(&artifact(&[("url", "http://example.com")]));
        assert!(issues.is_empty());
    }

    #[test]
    fn test_allowed_values() {
        let mut v = ArtifactValidator::new();
        v.add_rule(
            "method",
            Rule::AllowedValues(vec!["GET".into(), "POST".into()]),
        );
        let issues = v.validate(&artifact(&[("method", "DELETE")]));
        assert_eq!(issues.len(), 1);
    }

    // REGRESSION-GUARD: the previous version of this test was a
    // no-op — `!v.validate(...).is_empty() == false` simplifies to
    // `is_empty() == true`, which passes vacuously and never
    // exercised the failure path. Replaced with explicit positive
    // and negative cases for both ends of the range.
    #[test]
    fn test_length_range() {
        let mut v = ArtifactValidator::new();
        v.add_rule("title", Rule::LengthRange(5, 100));
        // In-range value should produce no issues.
        assert!(
            v.validate(&artifact(&[("title", "valid title")]))
                .is_empty(),
            "an 11-char title in [5, 100] should produce no issues",
        );
        // Too-short value should produce a LengthRange issue.
        let short_issues = v.validate(&artifact(&[("title", "hi")]));
        assert_eq!(short_issues.len(), 1);
        assert_eq!(short_issues[0].rule, "LengthRange");
        // Too-long value should also produce a LengthRange issue.
        let long_value = "x".repeat(200);
        let long_issues = v.validate(&artifact(&[("title", long_value.as_str())]));
        assert_eq!(long_issues.len(), 1);
        assert_eq!(long_issues[0].rule, "LengthRange");
    }

    #[test]
    fn test_length_range_byte_semantics_documented() {
        // Document the byte-vs-char gotcha: a 1-emoji string is
        // bytes_len = 4 (in UTF-8), so LengthRange(1, 3) rejects it
        // even though it's "1 character".
        let mut v = ArtifactValidator::new();
        v.add_rule("emoji", Rule::LengthRange(1, 3));
        let issues = v.validate(&artifact(&[("emoji", "\u{1F600}")])); // grinning face
        assert!(
            !issues.is_empty(),
            "1-emoji UTF-8 string is 4 bytes, must trip LengthRange(1, 3)",
        );
    }

    #[test]
    fn test_is_integer() {
        let mut v = ArtifactValidator::new();
        v.add_rule("id", Rule::IsInteger);
        assert!(v.validate(&artifact(&[("id", "42")])).is_empty());
        assert!(!v.validate(&artifact(&[("id", "abc")])).is_empty());
    }

    #[test]
    fn test_is_timestamp() {
        let mut v = ArtifactValidator::new();
        v.add_rule("ts", Rule::IsTimestamp);
        assert!(
            v.validate(&artifact(&[("ts", "2025-01-01T00:00:00Z")]))
                .is_empty()
        );
        assert!(!v.validate(&artifact(&[("ts", "invalid")])).is_empty());
    }

    #[test]
    fn test_starts_with_any() {
        let mut v = ArtifactValidator::new();
        v.add_rule(
            "url",
            Rule::StartsWithAny(vec!["http://".into(), "https://".into()]),
        );
        assert!(
            v.validate(&artifact(&[("url", "https://example.com")]))
                .is_empty()
        );
        assert!(
            !v.validate(&artifact(&[("url", "ftp://example.com")]))
                .is_empty()
        );
    }

    #[test]
    fn test_deny_patterns() {
        let mut v = ArtifactValidator::new();
        v.add_rule(
            "content",
            Rule::DenyPatterns(vec!["PROD".into(), "SECRET".into()]),
        );
        assert!(
            !v.validate(&artifact(&[("content", "this has PROD in it")]))
                .is_empty()
        );
    }

    #[test]
    fn test_unique_batch() {
        let mut v = ArtifactValidator::new();
        v.add_rule("id", Rule::Unique);
        let batch = vec![
            artifact(&[("id", "1")]),
            artifact(&[("id", "2")]),
            artifact(&[("id", "1")]),
        ];
        let results = v.validate_batch(&batch);
        assert!(!results[2].is_empty());
    }

    #[test]
    fn test_multiple_rules_on_field() {
        let mut v = ArtifactValidator::new();
        v.add_rule("id", Rule::NotEmpty);
        v.add_rule("id", Rule::IsInteger);
        assert_eq!(v.rule_count(), 2);
        assert_eq!(v.validate(&artifact(&[("id", "")])).len(), 2);
    }
}
