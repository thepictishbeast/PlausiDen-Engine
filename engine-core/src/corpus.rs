//! Corpus loader — manage reference corpora for synthetic data generators.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// A corpus entry (a single template/sample).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CorpusEntry {
    pub id: String,
    pub category: String,
    pub locale: String,
    pub text: String,
    pub weight: f64,
    pub tags: Vec<String>,
}

/// A loaded corpus.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Corpus {
    pub name: String,
    pub locale: String,
    pub version: String,
    pub entries: Vec<CorpusEntry>,
    pub total_weight: f64,
}

impl Corpus {
    pub fn new(name: &str, locale: &str, version: &str) -> Self {
        Self {
            name: name.into(),
            locale: locale.into(),
            version: version.into(),
            entries: Vec::new(),
            total_weight: 0.0,
        }
    }

    pub fn add(&mut self, entry: CorpusEntry) {
        self.total_weight += entry.weight;
        self.entries.push(entry);
    }

    pub fn entries_by_category(&self, category: &str) -> Vec<&CorpusEntry> {
        self.entries.iter().filter(|e| e.category == category).collect()
    }

    pub fn entries_by_tag(&self, tag: &str) -> Vec<&CorpusEntry> {
        self.entries.iter().filter(|e| e.tags.iter().any(|t| t == tag)).collect()
    }

    pub fn categories(&self) -> Vec<String> {
        let mut cats: std::collections::HashSet<String> = std::collections::HashSet::new();
        for e in &self.entries {
            cats.insert(e.category.clone());
        }
        let mut out: Vec<String> = cats.into_iter().collect();
        out.sort();
        out
    }

    pub fn entry_count(&self) -> usize {
        self.entries.len()
    }
}

/// Corpus loader.
pub struct CorpusRegistry {
    corpora: HashMap<String, Corpus>,
}

impl CorpusRegistry {
    pub fn new() -> Self {
        Self { corpora: HashMap::new() }
    }

    /// Register a corpus.
    pub fn register(&mut self, corpus: Corpus) {
        self.corpora.insert(corpus.name.clone(), corpus);
    }

    /// Get a corpus by name.
    pub fn get(&self, name: &str) -> Option<&Corpus> {
        self.corpora.get(name)
    }

    /// Get a corpus mutably.
    pub fn get_mut(&mut self, name: &str) -> Option<&mut Corpus> {
        self.corpora.get_mut(name)
    }

    /// Remove a corpus.
    pub fn remove(&mut self, name: &str) -> bool {
        self.corpora.remove(name).is_some()
    }

    /// All corpora for a locale.
    pub fn for_locale(&self, locale: &str) -> Vec<&Corpus> {
        self.corpora.values().filter(|c| c.locale == locale).collect()
    }

    /// Total entries across all corpora.
    pub fn total_entries(&self) -> usize {
        self.corpora.values().map(|c| c.entry_count()).sum()
    }

    pub fn corpus_count(&self) -> usize {
        self.corpora.len()
    }
}

impl Default for CorpusRegistry {
    fn default() -> Self { Self::new() }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(id: &str, category: &str, text: &str) -> CorpusEntry {
        CorpusEntry {
            id: id.into(),
            category: category.into(),
            locale: "en-US".into(),
            text: text.into(),
            weight: 1.0,
            tags: Vec::new(),
        }
    }

    #[test]
    fn test_register_and_get() {
        let mut r = CorpusRegistry::new();
        r.register(Corpus::new("english_news", "en-US", "1.0"));
        assert!(r.get("english_news").is_some());
    }

    #[test]
    fn test_add_entry() {
        let mut c = Corpus::new("test", "en-US", "1.0");
        c.add(entry("e1", "headline", "Breaking news"));
        assert_eq!(c.entry_count(), 1);
    }

    #[test]
    fn test_total_weight() {
        let mut c = Corpus::new("test", "en-US", "1.0");
        let mut e1 = entry("a", "x", "text1");
        e1.weight = 2.0;
        let mut e2 = entry("b", "x", "text2");
        e2.weight = 3.0;
        c.add(e1);
        c.add(e2);
        assert_eq!(c.total_weight, 5.0);
    }

    #[test]
    fn test_entries_by_category() {
        let mut c = Corpus::new("test", "en-US", "1.0");
        c.add(entry("a", "headline", "x"));
        c.add(entry("b", "headline", "y"));
        c.add(entry("c", "body", "z"));
        assert_eq!(c.entries_by_category("headline").len(), 2);
    }

    #[test]
    fn test_entries_by_tag() {
        let mut c = Corpus::new("test", "en-US", "1.0");
        let mut e = entry("a", "x", "text");
        e.tags = vec!["sports".into()];
        c.add(e);
        c.add(entry("b", "x", "text"));
        assert_eq!(c.entries_by_tag("sports").len(), 1);
    }

    #[test]
    fn test_categories() {
        let mut c = Corpus::new("test", "en-US", "1.0");
        c.add(entry("a", "headline", "x"));
        c.add(entry("b", "body", "y"));
        let cats = c.categories();
        assert_eq!(cats.len(), 2);
    }

    #[test]
    fn test_for_locale() {
        let mut r = CorpusRegistry::new();
        r.register(Corpus::new("a", "en-US", "1.0"));
        r.register(Corpus::new("b", "fr-FR", "1.0"));
        r.register(Corpus::new("c", "en-US", "1.0"));
        assert_eq!(r.for_locale("en-US").len(), 2);
    }

    #[test]
    fn test_remove_corpus() {
        let mut r = CorpusRegistry::new();
        r.register(Corpus::new("test", "en-US", "1.0"));
        assert!(r.remove("test"));
        assert_eq!(r.corpus_count(), 0);
    }

    #[test]
    fn test_total_entries() {
        let mut r = CorpusRegistry::new();
        let mut a = Corpus::new("a", "en-US", "1.0");
        a.add(entry("e1", "x", "y"));
        a.add(entry("e2", "x", "y"));
        r.register(a);
        assert_eq!(r.total_entries(), 2);
    }
}
