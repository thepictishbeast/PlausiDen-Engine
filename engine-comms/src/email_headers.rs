//! Email header generation -- forensically plausible RFC 2822 header sets.
//!
//! Generates realistic email header artifacts: From, To, Subject, Date,
//! Message-ID, and MIME-Version fields. No body content is produced -- headers
//! only, matching patterns seen in real mailbox forensic extractions.

use chrono::{DateTime, Duration, Utc};
use engine_core::error::{EngineError, Result};
use engine_core::profile::UserProfile;
use engine_core::traits::{
    Artifact, ArtifactMetadata, DataCategory, DataGenerator, GenerationContext, ResourceCost,
};
use rand::distributions::{Distribution, Uniform};
use rand::seq::SliceRandom;
use rand::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};

// ---- Name and domain pools ----

const FIRST_NAMES: &[&str] = &[
    "James",
    "Mary",
    "Robert",
    "Patricia",
    "John",
    "Jennifer",
    "Michael",
    "Linda",
    "David",
    "Elizabeth",
    "William",
    "Barbara",
    "Richard",
    "Susan",
    "Joseph",
    "Jessica",
    "Thomas",
    "Sarah",
    "Charles",
    "Karen",
    "Daniel",
    "Nancy",
    "Matthew",
    "Betty",
    "Anthony",
    "Margaret",
    "Mark",
    "Sandra",
    "Paul",
    "Emily",
    "Joshua",
    "Donna",
    "Kevin",
    "Michelle",
    "Brian",
    "Amanda",
    "George",
    "Melissa",
    "Timothy",
    "Deborah",
    "Jason",
    "Laura",
    "Ryan",
    "Cynthia",
    "Jacob",
    "Amy",
    "Nicholas",
    "Angela",
];

const LAST_NAMES: &[&str] = &[
    "Smith",
    "Johnson",
    "Williams",
    "Brown",
    "Jones",
    "Garcia",
    "Miller",
    "Davis",
    "Rodriguez",
    "Martinez",
    "Hernandez",
    "Lopez",
    "Wilson",
    "Anderson",
    "Thomas",
    "Taylor",
    "Moore",
    "Jackson",
    "Martin",
    "Lee",
    "Thompson",
    "White",
    "Harris",
    "Clark",
    "Lewis",
    "Robinson",
    "Walker",
    "Young",
    "Allen",
    "King",
    "Wright",
    "Scott",
    "Nguyen",
    "Hill",
    "Green",
    "Adams",
    "Nelson",
    "Baker",
    "Hall",
    "Rivera",
    "Campbell",
    "Mitchell",
    "Carter",
    "Roberts",
    "Phillips",
    "Evans",
    "Turner",
];

const EMAIL_DOMAINS: &[&str] = &[
    "gmail.com",
    "yahoo.com",
    "outlook.com",
    "hotmail.com",
    "icloud.com",
    "protonmail.com",
    "aol.com",
    "mail.com",
    "zoho.com",
    "fastmail.com",
    "live.com",
    "msn.com",
    "ymail.com",
    "inbox.com",
    "pm.me",
];

const MAIL_SERVER_DOMAINS: &[&str] = &[
    "mail.google.com",
    "mx.outlook.com",
    "smtp.yahoo.com",
    "mail.icloud.com",
    "smtp.fastmail.com",
    "mail.protonmail.ch",
    "mx.zoho.com",
    "smtp.aol.com",
    "mail.gmx.com",
    "mx.mail.com",
];

const SUBJECT_TEMPLATES: &[&str] = &[
    // Work
    "Meeting tomorrow at {time}",
    "Re: Project update",
    "Quick question about the report",
    "Reminder: deadline Friday",
    "FYI: schedule change",
    "Action required: review needed",
    "Re: Re: Budget proposal",
    "Follow up from our call",
    "Weekly status update",
    "New policy announcement",
    // Personal
    "Dinner plans this weekend?",
    "Photos from last week",
    "Happy birthday!",
    "Re: Vacation plans",
    "Invitation: BBQ on Saturday",
    "Check this out",
    "Long time no see!",
    "Re: Recipe you asked about",
    // Transactional
    "Your order has shipped",
    "Payment confirmation",
    "Your receipt from Store",
    "Appointment reminder",
    "Your subscription renewal",
    "Account security alert",
    "Password reset request",
    "Welcome to our service",
    // Newsletters
    "This week in tech",
    "Your daily digest",
    "Monthly newsletter",
    "Special offer inside",
];

const MIME_TYPES: &[&str] = &[
    "text/plain; charset=UTF-8",
    "text/html; charset=UTF-8",
    "multipart/alternative",
    "multipart/mixed",
];

/// A set of email headers for a single message.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmailHeaderEntry {
    /// Artifact metadata (timestamps, category, size).
    pub meta: ArtifactMetadata,
    /// From header: sender address with optional display name.
    pub from: String,
    /// To header: recipient address with optional display name.
    pub to: String,
    /// Subject line.
    pub subject: String,
    /// Date header in RFC 2822 format.
    pub date: String,
    /// Unique Message-ID.
    pub message_id: String,
    /// MIME-Version (always "1.0").
    pub mime_version: String,
    /// Content-Type header.
    pub content_type: String,
    /// When the email was sent (parsed datetime for forensic correlation).
    pub sent_at: DateTime<Utc>,
}

impl Artifact for EmailHeaderEntry {
    fn metadata(&self) -> &ArtifactMetadata {
        &self.meta
    }

    fn validate_plausibility(&self) -> Result<()> {
        self.meta.validate_timestamps()?;

        if self.from.is_empty() {
            return Err(EngineError::ImplausibleArtifact {
                reason: "From header is empty".to_string(),
            });
        }

        if !self.from.contains('@') {
            return Err(EngineError::ImplausibleArtifact {
                reason: format!("From header missing '@': {}", self.from),
            });
        }

        if self.to.is_empty() {
            return Err(EngineError::ImplausibleArtifact {
                reason: "To header is empty".to_string(),
            });
        }

        if !self.to.contains('@') {
            return Err(EngineError::ImplausibleArtifact {
                reason: format!("To header missing '@': {}", self.to),
            });
        }

        // Defence-in-depth: From and To must not be identical. The
        // generator now retries on collision (see generate()), but a
        // serialized artifact loaded from disk could still have the
        // bug, so the validator catches it too.
        if self.from == self.to {
            return Err(EngineError::ImplausibleArtifact {
                reason: format!("From and To are identical: {}", self.from),
            });
        }

        if self.subject.is_empty() {
            return Err(EngineError::ImplausibleArtifact {
                reason: "Subject header is empty".to_string(),
            });
        }

        if self.message_id.is_empty() || !self.message_id.contains('@') {
            return Err(EngineError::ImplausibleArtifact {
                reason: format!("invalid Message-ID: {}", self.message_id),
            });
        }

        if self.mime_version != "1.0" {
            return Err(EngineError::ImplausibleArtifact {
                reason: format!("unexpected MIME-Version: {}", self.mime_version),
            });
        }

        if self.date.is_empty() {
            return Err(EngineError::ImplausibleArtifact {
                reason: "Date header is empty".to_string(),
            });
        }

        Ok(())
    }

    fn to_bytes(&self) -> Result<Vec<u8>> {
        serde_json::to_vec(self).map_err(EngineError::Serialization)
    }
}

/// Generates realistic email header sets.
pub struct EmailHeaderGenerator;

impl EmailHeaderGenerator {
    /// Create a new email header generator.
    pub fn new() -> Self {
        Self
    }

    /// Generate a display name and email address pair: "First Last <first.last@domain>".
    fn generate_address(
        rng: &mut (impl RngCore + CryptoRng),
    ) -> core::result::Result<String, EngineError> {
        let first = FIRST_NAMES
            .choose(rng)
            .ok_or_else(|| EngineError::InvalidContext("empty first name pool".to_string()))?;
        let last = LAST_NAMES
            .choose(rng)
            .ok_or_else(|| EngineError::InvalidContext("empty last name pool".to_string()))?;
        let domain = EMAIL_DOMAINS
            .choose(rng)
            .ok_or_else(|| EngineError::InvalidContext("empty domain pool".to_string()))?;

        let local_part = match Uniform::new_inclusive(0u32, 3).sample(rng) {
            0 => format!("{}.{}", first.to_lowercase(), last.to_lowercase()),
            1 => format!("{}{}", first.to_lowercase(), last.to_lowercase()),
            2 => {
                let digits = Uniform::new_inclusive(1u32, 99).sample(rng);
                format!("{}.{}{}", first.to_lowercase(), last.to_lowercase(), digits)
            }
            _ => {
                let first_initial = &first.to_lowercase()[..1];
                format!("{}{}", first_initial, last.to_lowercase())
            }
        };

        Ok(format!("{first} {last} <{local_part}@{domain}>"))
    }

    /// Generate a subject line, filling in any template placeholders.
    fn generate_subject(
        rng: &mut (impl RngCore + CryptoRng),
    ) -> core::result::Result<String, EngineError> {
        let template = SUBJECT_TEMPLATES.choose(rng).ok_or_else(|| {
            EngineError::InvalidContext("empty subject template pool".to_string())
        })?;

        // Fill in {time} placeholder if present.
        let subject = if template.contains("{time}") {
            let hour = Uniform::new_inclusive(8u32, 17).sample(rng);
            let minute = if Uniform::new_inclusive(0u32, 1).sample(rng) == 0 {
                "00"
            } else {
                "30"
            };
            let period = if hour < 12 { "AM" } else { "PM" };
            let display_hour = if hour > 12 { hour - 12 } else { hour };
            template.replace("{time}", &format!("{display_hour}:{minute} {period}"))
        } else {
            template.to_string()
        };

        Ok(subject)
    }

    /// Generate an RFC 2822 compliant Message-ID.
    fn generate_message_id(
        sent_at: &DateTime<Utc>,
        rng: &mut (impl RngCore + CryptoRng),
    ) -> core::result::Result<String, EngineError> {
        let server = MAIL_SERVER_DOMAINS
            .choose(rng)
            .ok_or_else(|| EngineError::InvalidContext("empty server domain pool".to_string()))?;

        let random_part = Uniform::new_inclusive(100_000u64, 999_999).sample(rng);
        let ts = sent_at.timestamp();

        Ok(format!("<{ts}.{random_part}@{server}>"))
    }

    /// Generate an email timestamp within the last 90 days. The
    /// hour-of-day is sampled from the user's circadian profile via
    /// `engine_core::schedule::pick_active_timestamp`, replacing the
    /// previous hand-rolled 75%-in-8am-8pm heuristic which assumed
    /// every user worked business hours.
    fn generate_sent_at(
        profile: &UserProfile,
        context: &GenerationContext,
        rng: &mut (impl RngCore + CryptoRng),
    ) -> DateTime<Utc> {
        let day_offset = Uniform::new_inclusive(0i64, 89).sample(rng);
        let target = context.now - Duration::days(day_offset);
        engine_core::schedule::pick_active_timestamp(profile, target, rng)
            .unwrap_or(target)
    }
}

impl Default for EmailHeaderGenerator {
    fn default() -> Self {
        Self::new()
    }
}

impl DataGenerator for EmailHeaderGenerator {
    fn generate(
        &self,
        profile: &UserProfile,
        context: &GenerationContext,
        rng: &mut (impl RngCore + CryptoRng),
    ) -> Result<Box<dyn Artifact>> {
        let from = Self::generate_address(rng)?;
        // BUG ASSUMPTION: generate_address draws independently from
        // small const pools (FIRST_NAMES, LAST_NAMES, EMAIL_DOMAINS).
        // Two consecutive calls can collide — birthday-paradox math
        // says ~1 in N collisions for N entries, which becomes
        // visible at scale. The validator now refuses From == To, so
        // a colliding generation would propagate as an error rather
        // than a forensically implausible artifact. We retry up to
        // 10 times before giving up; in practice the very first
        // retry succeeds.
        let mut to = Self::generate_address(rng)?;
        for _ in 0..10 {
            if to != from {
                break;
            }
            to = Self::generate_address(rng)?;
        }
        let subject = Self::generate_subject(rng)?;
        let sent_at = Self::generate_sent_at(profile, context, rng);
        let date = sent_at.format("%a, %d %b %Y %H:%M:%S +0000").to_string();
        let message_id = Self::generate_message_id(&sent_at, rng)?;
        let mime_version = "1.0".to_string();
        let content_type = MIME_TYPES
            .choose(rng)
            .unwrap_or(&"text/plain; charset=UTF-8")
            .to_string();

        let size_estimate = from.len() as u64
            + to.len() as u64
            + subject.len() as u64
            + date.len() as u64
            + message_id.len() as u64
            + content_type.len() as u64
            + 128;

        let meta = ArtifactMetadata::new(
            DataCategory::Communications,
            sent_at,
            sent_at,
            size_estimate,
        )?;

        let entry = EmailHeaderEntry {
            meta,
            from,
            to,
            subject,
            date,
            message_id,
            mime_version,
            content_type,
            sent_at,
        };

        entry.validate_plausibility()?;
        Ok(Box::new(entry))
    }

    fn category(&self) -> DataCategory {
        DataCategory::Communications
    }

    fn forensic_weight(&self) -> u32 {
        85 // Email metadata is significant forensic evidence.
    }

    fn resource_cost(&self) -> ResourceCost {
        ResourceCost {
            cpu_us: 25,
            disk_bytes: 512,
            network_bytes: 0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use engine_core::entropy::seeded_rng;

    fn test_profile() -> UserProfile {
        UserProfile::default()
    }

    #[test]
    fn test_basic_email_header_generation() {
        let g = EmailHeaderGenerator::new();
        let p = test_profile();
        let c = GenerationContext::new();
        let mut r = seeded_rng(42);

        let a = g.generate(&p, &c, &mut r).unwrap();
        a.validate_plausibility().unwrap();

        let b = a.to_bytes().unwrap();
        let e: EmailHeaderEntry = serde_json::from_slice(&b).unwrap();

        assert!(e.from.contains('@'), "From must contain @");
        assert!(e.to.contains('@'), "To must contain @");
        assert!(!e.subject.is_empty(), "Subject must not be empty");
        assert!(e.message_id.contains('@'), "Message-ID must contain @");
        assert_eq!(e.mime_version, "1.0");
        assert!(!e.date.is_empty());
    }

    #[test]
    fn test_500_email_headers_valid() {
        let g = EmailHeaderGenerator::new();
        let p = test_profile();
        let c = GenerationContext::new();
        for s in 0..500 {
            let mut r = seeded_rng(s);
            g.generate(&p, &c, &mut r)
                .unwrap()
                .validate_plausibility()
                .unwrap_or_else(|err| panic!("entry {s} failed: {err}"));
        }
    }

    // REGRESSION-GUARD: generate_address draws independently from
    // small const pools (FIRST_NAMES, LAST_NAMES, EMAIL_DOMAINS), so
    // two consecutive calls can collide and produce From == To. The
    // fix is a retry loop in generate() and a defence-in-depth
    // check in validate_plausibility(). This test sweeps 2000 seeds
    // and asserts no entry has From == To.
    #[test]
    fn test_from_to_never_identical() {
        let g = EmailHeaderGenerator::new();
        let p = test_profile();
        let c = GenerationContext::new();
        for s in 0..2000 {
            let mut r = seeded_rng(s);
            let a = g.generate(&p, &c, &mut r).unwrap();
            let b = a.to_bytes().unwrap();
            let e: EmailHeaderEntry = serde_json::from_slice(&b).unwrap();
            assert_ne!(
                e.from, e.to,
                "seed {s}: From == To collision was not retried",
            );
        }
    }

    #[test]
    fn test_message_id_uniqueness() {
        let g = EmailHeaderGenerator::new();
        let p = test_profile();
        let c = GenerationContext::new();
        let mut ids = std::collections::HashSet::new();
        for s in 0..200 {
            let mut r = seeded_rng(s);
            let a = g.generate(&p, &c, &mut r).unwrap();
            let b = a.to_bytes().unwrap();
            let e: EmailHeaderEntry = serde_json::from_slice(&b).unwrap();
            assert!(
                ids.insert(e.message_id.clone()),
                "duplicate Message-ID: {}",
                e.message_id
            );
        }
    }

    #[test]
    fn test_subject_variety() {
        let g = EmailHeaderGenerator::new();
        let p = test_profile();
        let c = GenerationContext::new();
        let mut subjects = std::collections::HashSet::new();
        for s in 0..200 {
            let mut r = seeded_rng(s);
            let a = g.generate(&p, &c, &mut r).unwrap();
            let b = a.to_bytes().unwrap();
            let e: EmailHeaderEntry = serde_json::from_slice(&b).unwrap();
            subjects.insert(e.subject);
        }
        // Should see many distinct subjects.
        assert!(
            subjects.len() > 10,
            "expected diverse subjects, got only {}",
            subjects.len()
        );
    }

    #[test]
    fn test_from_and_to_have_display_names() {
        let g = EmailHeaderGenerator::new();
        let p = test_profile();
        let c = GenerationContext::new();
        let mut r = seeded_rng(42);

        let a = g.generate(&p, &c, &mut r).unwrap();
        let b = a.to_bytes().unwrap();
        let e: EmailHeaderEntry = serde_json::from_slice(&b).unwrap();

        // Format: "First Last <local@domain>"
        assert!(e.from.contains('<'), "From should contain '<': {}", e.from);
        assert!(e.from.contains('>'), "From should contain '>': {}", e.from);
        assert!(e.to.contains('<'), "To should contain '<': {}", e.to);
        assert!(e.to.contains('>'), "To should contain '>': {}", e.to);
    }
}
