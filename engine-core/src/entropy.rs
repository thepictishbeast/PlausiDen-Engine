//! Entropy sources and seeded RNG for reproducible generation.
//!
//! All randomness in PlausiDen flows through cryptographically secure RNGs.
//! Seeded RNGs enable deterministic generation for testing and reproducibility.

use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;

/// Create a cryptographically secure RNG seeded from OS entropy.
pub fn secure_rng() -> ChaCha20Rng {
    ChaCha20Rng::from_entropy()
}

/// Create a deterministic RNG from a seed.
///
/// Used for testing and reproducible generation. Two calls with the same
/// seed produce identical artifact sequences.
pub fn seeded_rng(seed: u64) -> ChaCha20Rng {
    ChaCha20Rng::seed_from_u64(seed)
}

/// Create a deterministic RNG from a 32-byte seed.
pub fn seeded_rng_bytes(seed: [u8; 32]) -> ChaCha20Rng {
    ChaCha20Rng::from_seed(seed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::RngCore;

    #[test]
    fn test_rng_seed_produces_deterministic_output() {
        let mut rng1 = seeded_rng(12345);
        let mut rng2 = seeded_rng(12345);

        let mut buf1 = [0u8; 32];
        let mut buf2 = [0u8; 32];

        rng1.fill_bytes(&mut buf1);
        rng2.fill_bytes(&mut buf2);

        assert_eq!(buf1, buf2, "same seed must produce identical output");
    }

    #[test]
    fn test_different_seeds_produce_different_output() {
        let mut rng1 = seeded_rng(12345);
        let mut rng2 = seeded_rng(54321);

        let mut buf1 = [0u8; 32];
        let mut buf2 = [0u8; 32];

        rng1.fill_bytes(&mut buf1);
        rng2.fill_bytes(&mut buf2);

        assert_ne!(buf1, buf2, "different seeds must produce different output");
    }
}
