//! TLS fingerprint generation -- realistic Client Hello fingerprints.
//!
//! Real TLS traffic reveals a lot about the client software: each browser
//! implementation has a distinctive cipher suite ordering, extension set,
//! and supported groups list. Forensic analysts use JA3 and JA4 hashes
//! to classify traffic and identify anomalous clients (e.g., curl/wget
//! where a browser is expected). This generator produces TLS handshake
//! metadata indistinguishable from genuine browser traffic.

use chrono::{DateTime, Duration, Utc};
use engine_core::error::{EngineError, Result};
use engine_core::profile::UserProfile;
use engine_core::traits::{
    Artifact, ArtifactMetadata, DataCategory, DataGenerator, GenerationContext,
};
use md5::{Digest, Md5};
use rand::distributions::{Distribution, Uniform};
use rand::seq::SliceRandom;
use rand::{CryptoRng, RngCore};
use serde::Serialize;

// ---------------------------------------------------------------------------
// TLS constants -- realistic browser fingerprint components
// ---------------------------------------------------------------------------

/// TLS version identifiers as they appear on the wire.
#[derive(Debug, Clone, Copy, Serialize, serde::Deserialize, PartialEq, Eq)]
pub enum TlsVersion {
    /// TLS 1.2 (0x0303) -- still common, especially for compatibility.
    Tls12,
    /// TLS 1.3 (0x0304) -- preferred by modern browsers.
    Tls13,
}

impl TlsVersion {
    /// Wire-format hex string used in JA3/JA4.
    fn wire_value(self) -> &'static str {
        match self {
            Self::Tls12 => "771",
            Self::Tls13 => "772",
        }
    }

    /// Short tag for JA4.
    fn ja4_tag(self) -> &'static str {
        match self {
            Self::Tls12 => "12",
            Self::Tls13 => "13",
        }
    }
}

impl std::fmt::Display for TlsVersion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Tls12 => write!(f, "TLS 1.2"),
            Self::Tls13 => write!(f, "TLS 1.3"),
        }
    }
}

/// A browser fingerprint profile used to construct Client Hello parameters.
#[derive(Debug, Clone)]
struct BrowserProfile {
    /// Human-readable name (e.g., "Chrome 120"). Used in test diagnostics.
    #[cfg_attr(not(test), allow(dead_code))]
    name: &'static str,
    /// Preferred TLS version.
    tls_version: TlsVersion,
    /// Cipher suites in Client Hello order (IANA numeric values).
    cipher_suites: &'static [u16],
    /// TLS extensions present (IANA numeric values).
    extensions: &'static [u16],
    /// Supported elliptic curve groups.
    supported_groups: &'static [u16],
    /// Known JA3 hash for this profile. Used in test verification.
    #[allow(dead_code)]
    known_ja3: &'static str,
}

// Cipher suite constants (IANA values).
const TLS_AES_128_GCM_SHA256: u16 = 0x1301;
const TLS_AES_256_GCM_SHA384: u16 = 0x1302;
const TLS_CHACHA20_POLY1305_SHA256: u16 = 0x1303;
const TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256: u16 = 0xc02b;
const TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256: u16 = 0xc02f;
const TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384: u16 = 0xc02c;
const TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384: u16 = 0xc030;
const TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256: u16 = 0xcca9;
const TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256: u16 = 0xcca8;
const TLS_RSA_WITH_AES_128_GCM_SHA256: u16 = 0x009c;
const TLS_RSA_WITH_AES_256_GCM_SHA384: u16 = 0x009d;
const TLS_RSA_WITH_AES_128_CBC_SHA: u16 = 0x002f;

// Extension constants (IANA values).
const EXT_SNI: u16 = 0;
const EXT_STATUS_REQUEST: u16 = 5;
const EXT_SUPPORTED_GROUPS: u16 = 10;
const EXT_EC_POINT_FORMATS: u16 = 11;
const EXT_SIGNATURE_ALGORITHMS: u16 = 13;
const EXT_ALPN: u16 = 16;
const EXT_ENCRYPT_THEN_MAC: u16 = 22;
const EXT_EXTENDED_MASTER_SECRET: u16 = 23;
const EXT_COMPRESS_CERTIFICATE: u16 = 27;
const EXT_SESSION_TICKET: u16 = 35;
const EXT_SUPPORTED_VERSIONS: u16 = 43;
const EXT_PSK_KEY_EXCHANGE_MODES: u16 = 45;
const EXT_KEY_SHARE: u16 = 51;
const EXT_RENEGOTIATION_INFO: u16 = 0xff01;

// Supported group constants (IANA values).
const GROUP_X25519: u16 = 0x001d;
const GROUP_SECP256R1: u16 = 0x0017;
const GROUP_SECP384R1: u16 = 0x0018;
const GROUP_SECP521R1: u16 = 0x0019;
const GROUP_FFDHE2048: u16 = 0x0100;

/// Chrome 120 -- TLS 1.3 preferred, GREASE values stripped for JA3.
const CHROME_120: BrowserProfile = BrowserProfile {
    name: "Chrome 120",
    tls_version: TlsVersion::Tls13,
    cipher_suites: &[
        TLS_AES_128_GCM_SHA256,
        TLS_AES_256_GCM_SHA384,
        TLS_CHACHA20_POLY1305_SHA256,
        TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
        TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
        TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
        TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
        TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
        TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
        TLS_RSA_WITH_AES_128_GCM_SHA256,
        TLS_RSA_WITH_AES_256_GCM_SHA384,
    ],
    extensions: &[
        EXT_SNI,
        EXT_EXTENDED_MASTER_SECRET,
        EXT_RENEGOTIATION_INFO,
        EXT_SUPPORTED_GROUPS,
        EXT_EC_POINT_FORMATS,
        EXT_SESSION_TICKET,
        EXT_ALPN,
        EXT_STATUS_REQUEST,
        EXT_SIGNATURE_ALGORITHMS,
        EXT_SUPPORTED_VERSIONS,
        EXT_PSK_KEY_EXCHANGE_MODES,
        EXT_KEY_SHARE,
        EXT_COMPRESS_CERTIFICATE,
    ],
    supported_groups: &[GROUP_X25519, GROUP_SECP256R1, GROUP_SECP384R1],
    known_ja3: "4d22a293361aa1cdf5c647ef58acac28",
};

/// Firefox 121 -- TLS 1.3, different cipher ordering from Chrome.
const FIREFOX_121: BrowserProfile = BrowserProfile {
    name: "Firefox 121",
    tls_version: TlsVersion::Tls13,
    cipher_suites: &[
        TLS_AES_128_GCM_SHA256,
        TLS_CHACHA20_POLY1305_SHA256,
        TLS_AES_256_GCM_SHA384,
        TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
        TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
        TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
        TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
        TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
        TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
        TLS_RSA_WITH_AES_128_GCM_SHA256,
        TLS_RSA_WITH_AES_256_GCM_SHA384,
    ],
    extensions: &[
        EXT_SNI,
        EXT_EXTENDED_MASTER_SECRET,
        EXT_RENEGOTIATION_INFO,
        EXT_SUPPORTED_GROUPS,
        EXT_EC_POINT_FORMATS,
        EXT_SESSION_TICKET,
        EXT_ALPN,
        EXT_STATUS_REQUEST,
        EXT_SIGNATURE_ALGORITHMS,
        EXT_SUPPORTED_VERSIONS,
        EXT_PSK_KEY_EXCHANGE_MODES,
        EXT_KEY_SHARE,
        EXT_ENCRYPT_THEN_MAC,
    ],
    supported_groups: &[
        GROUP_X25519,
        GROUP_SECP256R1,
        GROUP_SECP384R1,
        GROUP_SECP521R1,
        GROUP_FFDHE2048,
    ],
    known_ja3: "898193f581225e974d88853e05bddd0e",
};

/// Safari 17 -- TLS 1.3, Apple's distinct ordering.
const SAFARI_17: BrowserProfile = BrowserProfile {
    name: "Safari 17",
    tls_version: TlsVersion::Tls13,
    cipher_suites: &[
        TLS_AES_128_GCM_SHA256,
        TLS_AES_256_GCM_SHA384,
        TLS_CHACHA20_POLY1305_SHA256,
        TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
        TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
        TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
        TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
        TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
        TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
        TLS_RSA_WITH_AES_256_GCM_SHA384,
        TLS_RSA_WITH_AES_128_GCM_SHA256,
        TLS_RSA_WITH_AES_128_CBC_SHA,
    ],
    extensions: &[
        EXT_SNI,
        EXT_EXTENDED_MASTER_SECRET,
        EXT_RENEGOTIATION_INFO,
        EXT_SUPPORTED_GROUPS,
        EXT_EC_POINT_FORMATS,
        EXT_ALPN,
        EXT_STATUS_REQUEST,
        EXT_SIGNATURE_ALGORITHMS,
        EXT_SUPPORTED_VERSIONS,
        EXT_PSK_KEY_EXCHANGE_MODES,
        EXT_KEY_SHARE,
    ],
    supported_groups: &[GROUP_X25519, GROUP_SECP256R1, GROUP_SECP384R1, GROUP_SECP521R1],
    known_ja3: "d311137c12fe9c937d49ff590818b827",
};

/// curl/wget -- TLS 1.2 (OpenSSL default), suspicious in browser-expected contexts.
const CURL_WGET: BrowserProfile = BrowserProfile {
    name: "curl/wget",
    tls_version: TlsVersion::Tls12,
    cipher_suites: &[
        TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
        TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
        TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
        TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
        TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
        TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
        TLS_RSA_WITH_AES_256_GCM_SHA384,
        TLS_RSA_WITH_AES_128_GCM_SHA256,
    ],
    extensions: &[
        EXT_SNI,
        EXT_SUPPORTED_GROUPS,
        EXT_EC_POINT_FORMATS,
        EXT_SIGNATURE_ALGORITHMS,
        EXT_ALPN,
        EXT_EXTENDED_MASTER_SECRET,
        EXT_RENEGOTIATION_INFO,
    ],
    supported_groups: &[GROUP_X25519, GROUP_SECP256R1, GROUP_SECP384R1],
    known_ja3: "4c1b561655a13323b13810037d032c81",
};

/// Known JA3 hashes for each browser family.
pub const KNOWN_JA3_CHROME_120: &str = "4d22a293361aa1cdf5c647ef58acac28";
/// Known JA3 hash for Firefox 121.
pub const KNOWN_JA3_FIREFOX_121: &str = "898193f581225e974d88853e05bddd0e";
/// Known JA3 hash for Safari 17.
pub const KNOWN_JA3_SAFARI_17: &str = "d311137c12fe9c937d49ff590818b827";
/// Known JA3 hash for curl/wget (OpenSSL). Suspicious in browser-expected contexts.
pub const KNOWN_JA3_CURL_WGET: &str = "4c1b561655a13323b13810037d032c81";

/// Common SNI targets -- domains that appear in TLS logs.
const SNI_DOMAINS: &[&str] = &[
    "www.google.com",
    "www.youtube.com",
    "www.reddit.com",
    "www.wikipedia.org",
    "www.amazon.com",
    "www.github.com",
    "www.stackoverflow.com",
    "news.ycombinator.com",
    "www.nytimes.com",
    "www.bbc.com",
    "www.cnn.com",
    "www.twitter.com",
    "www.facebook.com",
    "www.instagram.com",
    "www.linkedin.com",
    "www.netflix.com",
    "www.twitch.tv",
    "mail.google.com",
    "outlook.live.com",
    "web.whatsapp.com",
    "cdn.jsdelivr.net",
    "fonts.googleapis.com",
    "ajax.googleapis.com",
    "api.github.com",
    "accounts.google.com",
    "login.microsoftonline.com",
];

// ---------------------------------------------------------------------------
// JA3 / JA4 computation
// ---------------------------------------------------------------------------

/// Compute the JA3 hash from Client Hello parameters.
///
/// JA3 format: `TLSVersion,Ciphers,Extensions,EllipticCurves,EllipticCurvePointFormats`
/// Each field is a dash-separated list of decimal values, fields separated by commas.
/// The result is the MD5 hash of this string.
fn compute_ja3(profile: &BrowserProfile) -> String {
    let version = profile.tls_version.wire_value();

    let ciphers: String = profile
        .cipher_suites
        .iter()
        .map(|c| c.to_string())
        .collect::<Vec<_>>()
        .join("-");

    let extensions: String = profile
        .extensions
        .iter()
        .map(|e| e.to_string())
        .collect::<Vec<_>>()
        .join("-");

    let groups: String = profile
        .supported_groups
        .iter()
        .map(|g| g.to_string())
        .collect::<Vec<_>>()
        .join("-");

    // EC point formats -- 0 = uncompressed (universal default).
    let point_formats = "0";

    let ja3_string = format!("{version},{ciphers},{extensions},{groups},{point_formats}");

    let mut hasher = Md5::new();
    hasher.update(ja3_string.as_bytes());
    let result = hasher.finalize();
    result.iter().map(|b| format!("{b:02x}")).collect()
}

/// Compute a JA4 fingerprint from Client Hello parameters.
///
/// JA4 is a newer fingerprinting format: `{proto}{version}{sni}{ciphers_count}{ext_count}_{cipher_hash}_{ext_hash}`
/// This is a simplified but structurally accurate implementation.
fn compute_ja4(profile: &BrowserProfile, sni: &str) -> String {
    let proto = "t"; // TCP (as opposed to QUIC 'q')
    let version = profile.tls_version.ja4_tag();
    let sni_flag = if sni.is_empty() { "i" } else { "d" }; // 'd' = domain present
    let cipher_count = format!("{:02}", profile.cipher_suites.len().min(99));
    let ext_count = format!("{:02}", profile.extensions.len().min(99));

    // Sorted cipher suites for hash stability.
    let mut sorted_ciphers: Vec<u16> = profile.cipher_suites.to_vec();
    sorted_ciphers.sort();
    let cipher_str: String = sorted_ciphers
        .iter()
        .map(|c| format!("{c:04x}"))
        .collect::<Vec<_>>()
        .join(",");

    let mut hasher = Md5::new();
    hasher.update(cipher_str.as_bytes());
    let cipher_hash: String = hasher.finalize().iter().map(|b| format!("{b:02x}")).collect();
    let cipher_hash_trunc = &cipher_hash[..12];

    // Sorted extensions for hash stability.
    let mut sorted_exts: Vec<u16> = profile.extensions.to_vec();
    sorted_exts.sort();
    let ext_str: String = sorted_exts
        .iter()
        .map(|e| format!("{e:04x}"))
        .collect::<Vec<_>>()
        .join(",");

    let mut hasher = Md5::new();
    hasher.update(ext_str.as_bytes());
    let ext_hash: String = hasher.finalize().iter().map(|b| format!("{b:02x}")).collect();
    let ext_hash_trunc = &ext_hash[..12];

    format!("{proto}{version}{sni_flag}{cipher_count}{ext_count}_{cipher_hash_trunc}_{ext_hash_trunc}")
}

// ---------------------------------------------------------------------------
// TLS entry and artifact
// ---------------------------------------------------------------------------

/// A generated TLS handshake fingerprint entry.
///
/// Represents metadata captured during a TLS Client Hello, as would appear
/// in network monitoring logs, proxy intercepts, or forensic PCAP analysis.
#[derive(Debug, Clone, Serialize, serde::Deserialize)]
pub struct TlsEntry {
    /// Artifact metadata.
    pub meta: ArtifactMetadata,
    /// Server Name Indication (SNI) -- the domain the client requested.
    pub server_name: String,
    /// Negotiated TLS version.
    pub tls_version: String,
    /// Selected cipher suite (human-readable name).
    pub cipher_suite: String,
    /// JA3 hash (MD5 of Client Hello parameters).
    pub ja3_hash: String,
    /// JA4 fingerprint (newer format with structured fields).
    pub ja4_fingerprint: String,
    /// TLS handshake duration in milliseconds.
    pub handshake_time_ms: u32,
    /// Handshake timestamp.
    pub timestamp: DateTime<Utc>,
}

impl Artifact for TlsEntry {
    fn metadata(&self) -> &ArtifactMetadata {
        &self.meta
    }

    fn validate_plausibility(&self) -> Result<()> {
        self.meta.validate_timestamps()?;
        if self.server_name.is_empty() {
            return Err(EngineError::ImplausibleArtifact {
                reason: "empty TLS server name (SNI)".into(),
            });
        }
        if self.ja3_hash.len() != 32 {
            return Err(EngineError::ImplausibleArtifact {
                reason: format!(
                    "JA3 hash must be 32 hex chars, got {}",
                    self.ja3_hash.len()
                ),
            });
        }
        if self.handshake_time_ms > 10_000 {
            return Err(EngineError::ImplausibleArtifact {
                reason: "TLS handshake >10s is implausible".into(),
            });
        }
        if self.cipher_suite.is_empty() {
            return Err(EngineError::ImplausibleArtifact {
                reason: "empty cipher suite".into(),
            });
        }
        Ok(())
    }

    fn to_bytes(&self) -> Result<Vec<u8>> {
        serde_json::to_vec(self).map_err(EngineError::Serialization)
    }
}

/// Human-readable cipher suite name for a given IANA value.
fn cipher_suite_name(id: u16) -> &'static str {
    match id {
        0x1301 => "TLS_AES_128_GCM_SHA256",
        0x1302 => "TLS_AES_256_GCM_SHA384",
        0x1303 => "TLS_CHACHA20_POLY1305_SHA256",
        0xc02b => "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
        0xc02f => "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
        0xc02c => "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
        0xc030 => "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
        0xcca9 => "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
        0xcca8 => "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
        0x009c => "TLS_RSA_WITH_AES_128_GCM_SHA256",
        0x009d => "TLS_RSA_WITH_AES_256_GCM_SHA384",
        0x002f => "TLS_RSA_WITH_AES_128_CBC_SHA",
        _ => "UNKNOWN",
    }
}

// ---------------------------------------------------------------------------
// Generator
// ---------------------------------------------------------------------------

/// Generates realistic TLS Client Hello fingerprint artifacts.
///
/// Produces handshake metadata matching real browser fingerprint distributions:
/// Chrome dominates (~65%), followed by Firefox (~20%), Safari (~10%),
/// with a small fraction of curl/wget (~5%) traffic.
pub struct TlsGenerator;

impl TlsGenerator {
    /// Create a new TLS fingerprint generator.
    pub fn new() -> Self {
        Self
    }

    /// Select a browser profile using a weighted distribution matching real
    /// internet traffic shares.
    fn pick_profile(rng: &mut (impl RngCore + CryptoRng)) -> &'static BrowserProfile {
        let roll = Uniform::new_inclusive(0u32, 99).sample(rng);
        match roll {
            0..=64 => &CHROME_120,
            65..=84 => &FIREFOX_121,
            85..=94 => &SAFARI_17,
            _ => &CURL_WGET,
        }
    }
}

impl Default for TlsGenerator {
    fn default() -> Self {
        Self::new()
    }
}

impl DataGenerator for TlsGenerator {
    fn generate(
        &self,
        _profile: &UserProfile,
        context: &GenerationContext,
        rng: &mut (impl RngCore + CryptoRng),
    ) -> Result<Box<dyn Artifact>> {
        let browser = Self::pick_profile(rng);

        // Pick an SNI domain.
        // SAFETY/FALLBACK: SNI_DOMAINS is a non-empty const slice, so
        // .choose() returning None would only mean a future refactor
        // has emptied it. We fall back to a literal placeholder rather
        // than unwrap so a doctrine-violating empty slice cannot
        // panic the generator at runtime.
        let server_name = SNI_DOMAINS
            .choose(rng)
            .copied()
            .unwrap_or("example.com")
            .to_string();

        // Compute fingerprints.
        let ja3_hash = compute_ja3(browser);
        let ja4_fingerprint = compute_ja4(browser, &server_name);

        // Select the first cipher suite as the "negotiated" one (server usually
        // picks the first mutually-supported suite).
        let selected_cipher = browser.cipher_suites[0];
        let cipher_suite = cipher_suite_name(selected_cipher).to_string();

        let tls_version = browser.tls_version.to_string();

        // Handshake time: TLS 1.3 is faster (1-RTT) than TLS 1.2 (2-RTT).
        let handshake_time_ms = match browser.tls_version {
            TlsVersion::Tls13 => Uniform::new_inclusive(8u32, 60).sample(rng),
            TlsVersion::Tls12 => Uniform::new_inclusive(15u32, 120).sample(rng),
        };

        let jitter = Uniform::new_inclusive(0i64, 300).sample(rng);
        let timestamp = context.now - Duration::seconds(jitter);

        let estimated_size = server_name.len() as u64 + ja3_hash.len() as u64 + 256;
        let meta = ArtifactMetadata::new(
            DataCategory::Network,
            timestamp,
            timestamp,
            estimated_size,
        )?;

        let entry = TlsEntry {
            meta,
            server_name,
            tls_version,
            cipher_suite,
            ja3_hash,
            ja4_fingerprint,
            handshake_time_ms,
            timestamp,
        };
        entry.validate_plausibility()?;
        Ok(Box::new(entry))
    }

    fn category(&self) -> DataCategory {
        DataCategory::Network
    }

    fn forensic_weight(&self) -> u32 {
        72
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use engine_core::entropy::seeded_rng;

    #[test]
    fn test_generate_tls_entry() {
        let tls_gen = TlsGenerator::new();
        let profile = UserProfile::default();
        let ctx = GenerationContext::new();
        let mut rng = seeded_rng(42);
        let artifact = tls_gen.generate(&profile, &ctx, &mut rng).unwrap();
        artifact.validate_plausibility().unwrap();
        let bytes = artifact.to_bytes().unwrap();
        let entry: TlsEntry = serde_json::from_slice(&bytes).unwrap();
        assert!(!entry.server_name.is_empty());
        assert!(!entry.cipher_suite.is_empty());
        assert_eq!(entry.ja3_hash.len(), 32, "JA3 must be 32 hex chars");
        assert!(
            entry.ja4_fingerprint.contains('_'),
            "JA4 must contain underscore separators"
        );
        assert!(entry.handshake_time_ms <= 10_000);
    }

    #[test]
    fn test_1000_tls_entries_valid() {
        let tls_gen = TlsGenerator::new();
        let profile = UserProfile::default();
        let ctx = GenerationContext::new();
        for seed in 0..1000 {
            let mut rng = seeded_rng(seed);
            tls_gen
                .generate(&profile, &ctx, &mut rng)
                .unwrap()
                .validate_plausibility()
                .unwrap();
        }
    }

    #[test]
    fn test_ja3_hashes_match_known_browsers() {
        // Each browser profile should produce its declared known JA3 hash.
        let profiles: &[(&BrowserProfile, &str)] = &[
            (&CHROME_120, KNOWN_JA3_CHROME_120),
            (&FIREFOX_121, KNOWN_JA3_FIREFOX_121),
            (&SAFARI_17, KNOWN_JA3_SAFARI_17),
            (&CURL_WGET, KNOWN_JA3_CURL_WGET),
        ];
        for (bp, expected) in profiles {
            let computed = compute_ja3(bp);
            assert_eq!(
                computed, *expected,
                "JA3 mismatch for {}: computed={computed}, expected={expected}",
                bp.name
            );
        }
    }

    #[test]
    fn test_browser_profile_distribution() {
        let tls_gen = TlsGenerator::new();
        let profile = UserProfile::default();
        let ctx = GenerationContext::new();
        let n = 5_000u32;
        let mut chrome_count = 0u32;
        let mut firefox_count = 0u32;
        let mut safari_count = 0u32;
        let mut curl_count = 0u32;

        let chrome_ja3 = compute_ja3(&CHROME_120);
        let firefox_ja3 = compute_ja3(&FIREFOX_121);
        let safari_ja3 = compute_ja3(&SAFARI_17);
        let curl_ja3 = compute_ja3(&CURL_WGET);

        for seed in 0..n {
            let mut rng = seeded_rng(u64::from(seed));
            let artifact = tls_gen.generate(&profile, &ctx, &mut rng).unwrap();
            let bytes = artifact.to_bytes().unwrap();
            let entry: TlsEntry = serde_json::from_slice(&bytes).unwrap();
            if entry.ja3_hash == chrome_ja3 {
                chrome_count += 1;
            } else if entry.ja3_hash == firefox_ja3 {
                firefox_count += 1;
            } else if entry.ja3_hash == safari_ja3 {
                safari_count += 1;
            } else if entry.ja3_hash == curl_ja3 {
                curl_count += 1;
            }
        }

        let pct = |c: u32| (c as f64 / n as f64) * 100.0;
        assert!(
            pct(chrome_count) > 45.0 && pct(chrome_count) < 85.0,
            "Chrome should be ~65%, got {:.1}%",
            pct(chrome_count)
        );
        assert!(
            pct(firefox_count) > 10.0 && pct(firefox_count) < 35.0,
            "Firefox should be ~20%, got {:.1}%",
            pct(firefox_count)
        );
        assert!(
            pct(safari_count) > 3.0 && pct(safari_count) < 20.0,
            "Safari should be ~10%, got {:.1}%",
            pct(safari_count)
        );
        assert!(
            pct(curl_count) > 1.0 && pct(curl_count) < 12.0,
            "curl/wget should be ~5%, got {:.1}%",
            pct(curl_count)
        );
    }

    #[test]
    fn test_ja4_format_structure() {
        let ja4 = compute_ja4(&CHROME_120, "www.google.com");
        // Format: t{version}{sni}{cipher_count}{ext_count}_{12 hex}_{12 hex}
        assert!(ja4.starts_with('t'), "JA4 should start with 't' for TCP");
        let parts: Vec<&str> = ja4.split('_').collect();
        assert_eq!(parts.len(), 3, "JA4 must have 3 underscore-separated parts");
        assert_eq!(parts[1].len(), 12, "cipher hash truncated to 12 chars");
        assert_eq!(parts[2].len(), 12, "extension hash truncated to 12 chars");
    }

    #[test]
    fn test_tls13_handshake_faster_than_tls12() {
        let tls_gen = TlsGenerator::new();
        let profile = UserProfile::default();
        let ctx = GenerationContext::new();
        let mut tls13_total: u64 = 0;
        let mut tls13_count: u64 = 0;
        let mut tls12_total: u64 = 0;
        let mut tls12_count: u64 = 0;

        for seed in 0..5000 {
            let mut rng = seeded_rng(seed);
            let artifact = tls_gen.generate(&profile, &ctx, &mut rng).unwrap();
            let bytes = artifact.to_bytes().unwrap();
            let entry: TlsEntry = serde_json::from_slice(&bytes).unwrap();
            if entry.tls_version == "TLS 1.3" {
                tls13_total += u64::from(entry.handshake_time_ms);
                tls13_count += 1;
            } else {
                tls12_total += u64::from(entry.handshake_time_ms);
                tls12_count += 1;
            }
        }

        // Ensure we got both versions.
        assert!(tls13_count > 0, "should generate TLS 1.3 entries");
        assert!(tls12_count > 0, "should generate TLS 1.2 entries");

        let avg_13 = tls13_total as f64 / tls13_count as f64;
        let avg_12 = tls12_total as f64 / tls12_count as f64;
        assert!(
            avg_13 < avg_12,
            "TLS 1.3 avg ({avg_13:.1}ms) should be faster than TLS 1.2 avg ({avg_12:.1}ms)"
        );
    }
}
