//! Realistic browsing pattern models.
//!
//! Inspired by research on human browsing behavior and FOSS noise generators:
//! - TrackMeNot: search query generation patterns
//! - AdNauseam: click behavior simulation
//! - Chaff: browsing noise generation
//!
//! Real browsing follows specific patterns that distinguish humans from bots:
//! - Power-law distribution of URL visits (few sites visited often, long tail of one-offs)
//! - Temporal autocorrelation (topics cluster in sessions)
//! - Referrer graphs (search → results → subpages → related sites)
//! - Dwell time variation (scan headlines vs read articles)

use chrono::Duration;
use rand::distributions::{Distribution, Uniform};
use rand::{CryptoRng, RngCore};

/// Models a browsing session — a burst of related activity.
#[derive(Debug, Clone)]
pub struct BrowsingSession {
    /// Primary topic of this session.
    pub topic: SessionTopic,
    /// Number of page visits in this session.
    pub visit_count: u32,
    /// Total session duration.
    pub duration: Duration,
    /// Individual page dwell times in seconds.
    pub dwell_times: Vec<u32>,
}

/// Topic categories that drive session behavior.
#[derive(Debug, Clone)]
pub enum SessionTopic {
    /// Quick check — weather, news headlines, email
    QuickCheck,
    /// Deep reading — articles, research, documentation
    DeepReading,
    /// Shopping — product comparison, reviews, checkout
    Shopping,
    /// Social browsing — feed scrolling, messaging
    Social,
    /// Search research — query, scan results, visit several
    SearchResearch,
    /// Entertainment — streaming, gaming, YouTube
    Entertainment,
    /// Work/productivity — docs, tools, dashboards
    Work,
}

impl SessionTopic {
    /// Typical session length for this topic.
    pub fn typical_visit_count(&self, rng: &mut (impl RngCore + CryptoRng)) -> u32 {
        let (min, max) = match self {
            Self::QuickCheck => (1, 5),
            Self::DeepReading => (3, 15),
            Self::Shopping => (5, 30),
            Self::Social => (10, 50),
            Self::SearchResearch => (5, 20),
            Self::Entertainment => (2, 10),
            Self::Work => (5, 25),
        };
        Uniform::new_inclusive(min, max).sample(rng)
    }

    /// Typical dwell time per page in seconds.
    pub fn typical_dwell_secs(&self, rng: &mut (impl RngCore + CryptoRng)) -> u32 {
        let (min, max) = match self {
            Self::QuickCheck => (3, 15),
            Self::DeepReading => (30, 300), // 30s to 5min
            Self::Shopping => (10, 120),
            Self::Social => (5, 60),
            Self::SearchResearch => (5, 45),
            Self::Entertainment => (60, 1800), // 1min to 30min
            Self::Work => (15, 180),
        };
        Uniform::new_inclusive(min, max).sample(rng)
    }
}

/// Generate a realistic browsing session.
pub fn generate_session(
    topic: SessionTopic,
    rng: &mut (impl RngCore + CryptoRng),
) -> BrowsingSession {
    let visit_count = topic.typical_visit_count(rng);
    let mut dwell_times = Vec::with_capacity(visit_count as usize);
    let mut total_secs = 0u64;

    for _ in 0..visit_count {
        let dwell = topic.typical_dwell_secs(rng);
        dwell_times.push(dwell);
        total_secs += dwell as u64;

        // Add inter-page navigation time (1-5 seconds)
        total_secs += Uniform::new_inclusive(1u64, 5).sample(rng);
    }

    BrowsingSession {
        topic,
        visit_count,
        duration: Duration::seconds(total_secs as i64),
        dwell_times,
    }
}

/// Power-law (Zipf) distribution for URL visit frequency.
///
/// Models the real-world pattern where a few sites are visited very often
/// (google, facebook, youtube) and most sites are visited once.
pub fn zipf_rank_probability(rank: u32, total_items: u32) -> f64 {
    if rank == 0 || total_items == 0 {
        return 0.0;
    }

    // Zipf's law: P(rank) = 1/rank^s / H(N,s) where s ≈ 1.0
    let s = 1.0;
    let numerator = 1.0 / (rank as f64).powf(s);

    // Harmonic number H(N,s)
    let harmonic: f64 = (1..=total_items).map(|k| 1.0 / (k as f64).powf(s)).sum();

    numerator / harmonic
}

/// Select an item from a collection using Zipf distribution.
///
/// Item at index 0 is most likely to be selected.
pub fn zipf_select<'a, T>(items: &'a [T], rng: &mut (impl RngCore + CryptoRng)) -> Option<&'a T> {
    if items.is_empty() {
        return None;
    }

    let roll: f64 = Uniform::new(0.0f64, 1.0).sample(rng);
    let mut cumulative = 0.0;

    for (i, item) in items.iter().enumerate() {
        cumulative += zipf_rank_probability((i + 1) as u32, items.len() as u32);
        if roll < cumulative {
            return Some(item);
        }
    }

    // Fallback to last item (rounding)
    items.last()
}

/// Models inter-session gaps (time between browsing sessions).
///
/// Real users have irregular gaps: short during the day, long overnight,
/// with occasional multi-hour stretches of no activity.
pub fn inter_session_gap_secs(hour_of_day: u8, rng: &mut (impl RngCore + CryptoRng)) -> u64 {
    // During active hours: 5-60 minute gaps
    // During evening: 30-120 minute gaps
    // During sleep: 4-8 hour gaps
    let (min, max) = if !(7..=23).contains(&hour_of_day) {
        (4 * 3600, 8 * 3600) // Sleep: 4-8 hours
    } else if hour_of_day > 20 {
        (30 * 60, 120 * 60) // Evening: 30-120 min
    } else {
        (5 * 60, 60 * 60) // Day: 5-60 min
    };

    Uniform::new_inclusive(min, max).sample(rng)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    #[test]
    fn test_zipf_distribution_favors_top_items() {
        let items: Vec<u32> = (0..100).collect();
        let mut rng = ChaCha20Rng::seed_from_u64(42);
        let mut counts = vec![0u32; 100];

        for _ in 0..10000 {
            if let Some(&idx) = zipf_select(&items, &mut rng) {
                counts[idx as usize] += 1;
            }
        }

        // Top item should be selected much more than bottom items
        assert!(
            counts[0] > counts[99] * 5,
            "top item ({}) should be 5x+ more frequent than bottom ({})",
            counts[0],
            counts[99]
        );

        // Top 10 items should account for >50% of selections
        let top10: u32 = counts[..10].iter().sum();
        assert!(
            top10 > 5000,
            "top 10 items should be >50% of selections, got {}",
            top10
        );
    }

    #[test]
    fn test_session_has_realistic_length() {
        let mut rng = ChaCha20Rng::seed_from_u64(42);

        for _ in 0..100 {
            let session = generate_session(SessionTopic::Shopping, &mut rng);
            assert!(session.visit_count >= 5 && session.visit_count <= 30);
            assert_eq!(session.dwell_times.len(), session.visit_count as usize);
        }
    }

    #[test]
    fn test_deep_reading_has_longer_dwell() {
        let mut rng = ChaCha20Rng::seed_from_u64(42);

        let mut quick_dwells = Vec::new();
        let mut deep_dwells = Vec::new();

        for _ in 0..100 {
            quick_dwells.push(SessionTopic::QuickCheck.typical_dwell_secs(&mut rng));
            deep_dwells.push(SessionTopic::DeepReading.typical_dwell_secs(&mut rng));
        }

        let quick_avg: f64 = quick_dwells.iter().map(|&d| d as f64).sum::<f64>() / 100.0;
        let deep_avg: f64 = deep_dwells.iter().map(|&d| d as f64).sum::<f64>() / 100.0;

        assert!(
            deep_avg > quick_avg * 3.0,
            "deep reading avg ({deep_avg}s) should be 3x+ quick check ({quick_avg}s)"
        );
    }

    #[test]
    fn test_inter_session_gap_respects_time_of_day() {
        let mut rng = ChaCha20Rng::seed_from_u64(42);

        let mut day_gaps = Vec::new();
        let mut night_gaps = Vec::new();

        for _ in 0..100 {
            day_gaps.push(inter_session_gap_secs(14, &mut rng)); // 2pm
            night_gaps.push(inter_session_gap_secs(3, &mut rng)); // 3am
        }

        let day_avg: f64 = day_gaps.iter().map(|&g| g as f64).sum::<f64>() / 100.0;
        let night_avg: f64 = night_gaps.iter().map(|&g| g as f64).sum::<f64>() / 100.0;

        assert!(
            night_avg > day_avg * 3.0,
            "night gaps ({night_avg}s) should be 3x+ day gaps ({day_avg}s)"
        );
    }

    #[test]
    fn test_zipf_probabilities_sum_to_one() {
        let total = 100;
        let sum: f64 = (1..=total).map(|r| zipf_rank_probability(r, total)).sum();
        assert!(
            (sum - 1.0).abs() < 0.001,
            "Zipf probabilities should sum to ~1.0, got {sum}"
        );
    }
}
