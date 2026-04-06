//! Network packet metadata generation — flow records, not full packets.
//!
//! Generates NetFlow/IPFIX-style flow records representing network connections.
//! These are what forensic analysts see in network logs.

use chrono::{DateTime, Duration, Utc};
use engine_core::error::{EngineError, Result};
use engine_core::profile::UserProfile;
use engine_core::traits::{
    Artifact, ArtifactMetadata, DataCategory, DataGenerator, GenerationContext,
};
use rand::distributions::{Distribution, Uniform};
use rand::seq::SliceRandom;
use rand::{CryptoRng, RngCore};
use serde::Serialize;

#[derive(Debug, Clone, Serialize, serde::Deserialize)]
pub struct FlowEntry {
    pub meta: ArtifactMetadata,
    pub src_ip: String,
    pub src_port: u16,
    pub dst_ip: String,
    pub dst_port: u16,
    pub protocol: String,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub packets_sent: u32,
    pub packets_received: u32,
    pub duration_ms: u64,
    pub start_time: DateTime<Utc>,
    pub end_time: DateTime<Utc>,
}

impl Artifact for FlowEntry {
    fn metadata(&self) -> &ArtifactMetadata { &self.meta }
    fn validate_plausibility(&self) -> Result<()> {
        self.meta.validate_timestamps()?;
        if self.bytes_sent == 0 && self.bytes_received == 0 {
            return Err(EngineError::ImplausibleArtifact { reason: "zero-byte flow".into() });
        }
        Ok(())
    }
    fn to_bytes(&self) -> Result<Vec<u8>> { serde_json::to_vec(self).map_err(EngineError::Serialization) }
}

const COMMON_PORTS: &[(u16, &str)] = &[
    (80, "http"), (443, "https"), (53, "dns"), (22, "ssh"),
    (25, "smtp"), (993, "imaps"), (8080, "http-alt"), (8443, "https-alt"),
    (3306, "mysql"), (5432, "postgresql"), (6379, "redis"),
];

pub struct FlowGenerator;
impl FlowGenerator { pub fn new() -> Self { Self } }
impl Default for FlowGenerator { fn default() -> Self { Self::new() } }

impl DataGenerator for FlowGenerator {
    fn generate(&self, _profile: &UserProfile, context: &GenerationContext, rng: &mut (impl RngCore + CryptoRng)) -> Result<Box<dyn Artifact>> {
        // SAFETY: COMMON_PORTS is a non-empty const slice.
        let (port, proto) = COMMON_PORTS
            .choose(rng)
            .expect("COMMON_PORTS is a non-empty const slice");

        let src_port = Uniform::new_inclusive(32768u16, 65535).sample(rng);
        let dst_ip = format!("{}.{}.{}.{}",
            Uniform::new_inclusive(1u8, 223).sample(rng),
            Uniform::new_inclusive(0u8, 255).sample(rng),
            Uniform::new_inclusive(0u8, 255).sample(rng),
            Uniform::new_inclusive(1u8, 254).sample(rng),
        );

        let duration_ms = Uniform::new_inclusive(10u64, 30000).sample(rng);
        let bytes_sent = Uniform::new_inclusive(100u64, 50000).sample(rng);
        let bytes_received = Uniform::new_inclusive(500u64, 500000).sample(rng);
        let packets_sent = (bytes_sent / 1400 + 1) as u32;
        let packets_received = (bytes_received / 1400 + 1) as u32;

        let jitter = Uniform::new_inclusive(0i64, 3600).sample(rng);
        let start_time = context.now - Duration::seconds(jitter);
        let end_time = start_time + Duration::milliseconds(duration_ms as i64);

        let meta = ArtifactMetadata::new(DataCategory::Network, start_time, end_time, 256)?;

        let entry = FlowEntry {
            meta, src_ip: "192.168.1.100".into(), src_port, dst_ip, dst_port: *port,
            protocol: proto.to_string(), bytes_sent, bytes_received,
            packets_sent, packets_received, duration_ms, start_time, end_time,
        };
        entry.validate_plausibility()?;
        Ok(Box::new(entry))
    }

    fn category(&self) -> DataCategory { DataCategory::Network }
    fn forensic_weight(&self) -> u32 { 65 }
}

#[cfg(test)]
mod tests {
    use super::*;
    use engine_core::entropy::seeded_rng;

    #[test]
    fn test_generate_flow() {
        let g = FlowGenerator::new();
        let p = UserProfile::default();
        let c = GenerationContext::new();
        let mut r = seeded_rng(42);
        let a = g.generate(&p, &c, &mut r).unwrap();
        a.validate_plausibility().unwrap();
    }

    #[test]
    fn test_500_flows_valid() {
        let g = FlowGenerator::new();
        let p = UserProfile::default();
        let c = GenerationContext::new();
        for s in 0..500 { let mut r = seeded_rng(s); g.generate(&p, &c, &mut r).unwrap().validate_plausibility().unwrap(); }
    }

    #[test]
    fn test_flow_has_traffic() {
        let g = FlowGenerator::new();
        let p = UserProfile::default();
        let c = GenerationContext::new();
        let mut r = seeded_rng(42);
        let a = g.generate(&p, &c, &mut r).unwrap();
        let b = a.to_bytes().unwrap();
        let e: FlowEntry = serde_json::from_slice(&b).unwrap();
        assert!(e.bytes_sent > 0);
        assert!(e.bytes_received > 0);
        assert!(e.end_time >= e.start_time);
    }
}
