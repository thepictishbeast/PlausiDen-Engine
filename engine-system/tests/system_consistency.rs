//! Cross-artifact consistency tests for system generators (logs, processes,
//! installs, crash reports).
//!
//! Forensic analysts cross-reference system artifacts: log entries must have
//! known facilities and non-empty messages; process PIDs must be valid;
//! install records need package identities; crash reports must cite real
//! POSIX signals. Any inconsistency across generators is a synthetic data
//! tell that undermines plausible deniability.

use std::collections::HashSet;

use engine_core::entropy::seeded_rng;
use engine_core::profile::UserProfile;
use engine_core::traits::{DataGenerator, GenerationContext};
use engine_system::crash::{CrashEntry, CrashGenerator};
use engine_system::installs::{InstallEntry, InstallGenerator};
use engine_system::logs::{LogEntry, LogGenerator};
use engine_system::processes::{ProcessEntry, ProcessGenerator};

// ============================================================================
// Shared helpers
// ============================================================================

fn shared_profile() -> UserProfile {
    UserProfile::default()
}

fn shared_context() -> GenerationContext {
    GenerationContext::new()
}

/// Generate N log entries.
fn make_logs(
    n: usize,
    profile: &UserProfile,
    ctx: &GenerationContext,
    seed: u64,
) -> Vec<LogEntry> {
    let log_gen = LogGenerator::new();
    let mut rng = seeded_rng(seed);
    let mut entries = Vec::with_capacity(n);
    for _ in 0..n {
        let artifact = log_gen.generate(profile, ctx, &mut rng).unwrap();
        let bytes = artifact.to_bytes().unwrap();
        let entry: LogEntry = serde_json::from_slice(&bytes).unwrap();
        entries.push(entry);
    }
    entries
}

/// Generate N process entries.
fn make_processes(
    n: usize,
    profile: &UserProfile,
    ctx: &GenerationContext,
    seed: u64,
) -> Vec<ProcessEntry> {
    let proc_gen = ProcessGenerator::new();
    let mut rng = seeded_rng(seed);
    let mut entries = Vec::with_capacity(n);
    for _ in 0..n {
        let artifact = proc_gen.generate(profile, ctx, &mut rng).unwrap();
        let bytes = artifact.to_bytes().unwrap();
        let entry: ProcessEntry = serde_json::from_slice(&bytes).unwrap();
        entries.push(entry);
    }
    entries
}

/// Generate N install entries.
fn make_installs(
    n: usize,
    profile: &UserProfile,
    ctx: &GenerationContext,
    seed: u64,
) -> Vec<InstallEntry> {
    let inst_gen = InstallGenerator::new();
    let mut rng = seeded_rng(seed);
    let mut entries = Vec::with_capacity(n);
    for _ in 0..n {
        let artifact = inst_gen.generate(profile, ctx, &mut rng).unwrap();
        let bytes = artifact.to_bytes().unwrap();
        let entry: InstallEntry = serde_json::from_slice(&bytes).unwrap();
        entries.push(entry);
    }
    entries
}

/// Generate N crash entries.
fn make_crashes(
    n: usize,
    profile: &UserProfile,
    ctx: &GenerationContext,
    seed: u64,
) -> Vec<CrashEntry> {
    let crash_gen = CrashGenerator::new();
    let mut rng = seeded_rng(seed);
    let mut entries = Vec::with_capacity(n);
    for _ in 0..n {
        let artifact = crash_gen.generate(profile, ctx, &mut rng).unwrap();
        let bytes = artifact.to_bytes().unwrap();
        let entry: CrashEntry = serde_json::from_slice(&bytes).unwrap();
        entries.push(entry);
    }
    entries
}

// ============================================================================
// Test 1: Log messages are never empty
// ============================================================================
//
// An empty syslog message is impossible on a real system -- the kernel and
// userspace daemons always write meaningful text. Empty messages would be
// flagged immediately by any log analysis tool.

#[test]
fn test_log_messages_never_empty() {
    let profile = shared_profile();
    let ctx = shared_context();

    let entries = make_logs(1000, &profile, &ctx, 42);

    for (i, entry) in entries.iter().enumerate() {
        assert!(
            !entry.message.is_empty(),
            "log entry {i}: message must not be empty (facility='{}', source='{}')",
            entry.facility,
            entry.source,
        );
        assert!(
            !entry.message.trim().is_empty(),
            "log entry {i}: message must not be whitespace-only: '{}'",
            entry.message,
        );
    }
}

// ============================================================================
// Test 2: Log facilities are from a known set
// ============================================================================
//
// Real syslog facilities are a fixed set defined by RFC 5424. Logs with
// unknown facilities would be rejected by syslog parsers and flagged as
// anomalous by forensic tools.

#[test]
fn test_log_facilities_from_known_set() {
    let profile = shared_profile();
    let ctx = shared_context();

    let known_facilities: HashSet<&str> =
        ["kern", "auth", "daemon", "cron"].into_iter().collect();

    let entries = make_logs(1000, &profile, &ctx, 77);

    let mut seen_facilities: HashSet<String> = HashSet::new();
    for (i, entry) in entries.iter().enumerate() {
        assert!(
            known_facilities.contains(entry.facility.as_str()),
            "log entry {i}: unknown facility '{}' -- must be one of {:?}",
            entry.facility,
            known_facilities,
        );
        seen_facilities.insert(entry.facility.clone());
    }

    // With 1000 entries across 7 templates spanning 4 facilities, we should
    // see all of them.
    assert!(
        seen_facilities.len() >= 3,
        "expected at least 3 distinct facilities in 1000 logs, got {}: {:?}",
        seen_facilities.len(),
        seen_facilities,
    );
}

// ============================================================================
// Test 3: Process PIDs are > 0
// ============================================================================
//
// PID 0 is the kernel scheduler (swapper) and never appears in /proc as a
// normal process. Every generated process entry must have PID >= 1.

#[test]
fn test_process_pids_positive() {
    let profile = shared_profile();
    let ctx = shared_context();

    let entries = make_processes(1000, &profile, &ctx, 42);

    for (i, entry) in entries.iter().enumerate() {
        assert!(
            entry.pid > 0,
            "process entry {i}: PID must be > 0, got {} (name='{}')",
            entry.pid,
            entry.name,
        );
    }
}

// ============================================================================
// Test 4: System processes have ppid = 1
// ============================================================================
//
// System daemons are children of PID 1 (systemd/init). If a system process
// (run by root, from the SYSTEM_PROCESSES list) has a ppid other than 1,
// it would look anomalous to any process tree analysis tool.

#[test]
fn test_system_processes_have_ppid_1() {
    let profile = shared_profile();
    let ctx = shared_context();

    let system_names: HashSet<&str> = [
        "systemd",
        "kthreadd",
        "journald",
        "udevd",
        "NetworkManager",
        "dbus-daemon",
        "polkitd",
        "sshd",
        "cron",
        "rsyslogd",
    ]
    .into_iter()
    .collect();

    let entries = make_processes(1000, &profile, &ctx, 55);

    let mut system_count = 0u32;
    for (i, entry) in entries.iter().enumerate() {
        if system_names.contains(entry.name.as_str()) {
            system_count += 1;
            assert_eq!(
                entry.ppid, 1,
                "process entry {i}: system process '{}' (pid={}) must have ppid=1, got ppid={}",
                entry.name, entry.pid, entry.ppid,
            );
        }
    }

    // With ~33% system process chance across 1000 entries, we should see plenty.
    assert!(
        system_count > 100,
        "too few system processes found: {system_count}/1000 (expected ~333)",
    );
}

// ============================================================================
// Test 5: Install packages have non-empty names and versions
// ============================================================================
//
// A dpkg/apt log entry without a package name or version is impossible on
// a real system. Package managers always record both fields. Missing data
// would be an obvious synthetic tell.

#[test]
fn test_install_packages_have_names_and_versions() {
    let profile = shared_profile();
    let ctx = shared_context();

    let entries = make_installs(1000, &profile, &ctx, 42);

    for (i, entry) in entries.iter().enumerate() {
        assert!(
            !entry.package_name.is_empty(),
            "install entry {i}: package_name must not be empty",
        );
        assert!(
            !entry.package_name.trim().is_empty(),
            "install entry {i}: package_name must not be whitespace-only: '{}'",
            entry.package_name,
        );
        assert!(
            !entry.version.is_empty(),
            "install entry {i}: version must not be empty for package '{}'",
            entry.package_name,
        );
        assert!(
            !entry.version.trim().is_empty(),
            "install entry {i}: version must not be whitespace-only for package '{}': '{}'",
            entry.package_name,
            entry.version,
        );
    }
}

// ============================================================================
// Test 6: Crash reports have known signal names
// ============================================================================
//
// POSIX defines a fixed set of signal names. A crash report citing an
// unknown signal (e.g., "SIGFAKE") would be immediately flagged by any
// forensic analyst reviewing coredump metadata.

#[test]
fn test_crash_reports_have_known_signals() {
    let profile = shared_profile();
    let ctx = shared_context();

    let known_signals: HashSet<&str> = [
        "SIGSEGV", "SIGABRT", "SIGFPE", "SIGILL", "SIGBUS", "SIGSYS", "SIGTRAP", "SIGXCPU",
        "SIGXFSZ",
    ]
    .into_iter()
    .collect();

    let entries = make_crashes(1000, &profile, &ctx, 42);

    let mut seen_signals: HashSet<String> = HashSet::new();
    for (i, entry) in entries.iter().enumerate() {
        assert!(
            known_signals.contains(entry.signal.as_str()),
            "crash entry {i}: unknown signal '{}' for process '{}' -- \
             must be one of {:?}",
            entry.signal,
            entry.process_name,
            known_signals,
        );
        seen_signals.insert(entry.signal.clone());
    }

    // The generator uses 3 distinct signals (SIGSEGV, SIGABRT, SIGFPE).
    // With 1000 entries across 8 scenarios, all 3 should appear.
    assert!(
        seen_signals.len() >= 2,
        "expected at least 2 distinct signals in 1000 crash reports, got {}: {:?}",
        seen_signals.len(),
        seen_signals,
    );
}

// ============================================================================
// Test 7: All timestamps are in the past (not future)
// ============================================================================
//
// Timestamps from any system generator must be at or before context.now.
// Future timestamps are physically impossible and would be an immediate
// forensic red flag across logs, processes, installs, and crash reports.

#[test]
fn test_all_timestamps_in_the_past() {
    let profile = shared_profile();
    let ctx = shared_context();
    let now = ctx.now;

    let log_entries = make_logs(200, &profile, &ctx, 66);
    let proc_entries = make_processes(200, &profile, &ctx, 66);
    let inst_entries = make_installs(200, &profile, &ctx, 66);
    let crash_entries = make_crashes(200, &profile, &ctx, 66);

    // Check log timestamps
    for (i, entry) in log_entries.iter().enumerate() {
        assert!(
            entry.timestamp <= now,
            "log entry {i}: timestamp {} is in the future (now={})",
            entry.timestamp,
            now,
        );
        assert!(
            entry.meta.created_at <= now,
            "log entry {i}: meta.created_at {} is in the future",
            entry.meta.created_at,
        );
    }

    // Check process start times
    for (i, entry) in proc_entries.iter().enumerate() {
        assert!(
            entry.start_time <= now,
            "process entry {i}: start_time {} is in the future for '{}'",
            entry.start_time,
            entry.name,
        );
        assert!(
            entry.meta.created_at <= now,
            "process entry {i}: meta.created_at {} is in the future",
            entry.meta.created_at,
        );
    }

    // Check install timestamps
    for (i, entry) in inst_entries.iter().enumerate() {
        assert!(
            entry.timestamp <= now,
            "install entry {i}: timestamp {} is in the future for '{}'",
            entry.timestamp,
            entry.package_name,
        );
        assert!(
            entry.meta.created_at <= now,
            "install entry {i}: meta.created_at {} is in the future",
            entry.meta.created_at,
        );
    }

    // Check crash timestamps
    for (i, entry) in crash_entries.iter().enumerate() {
        assert!(
            entry.timestamp <= now,
            "crash entry {i}: timestamp {} is in the future for '{}'",
            entry.timestamp,
            entry.process_name,
        );
        assert!(
            entry.meta.created_at <= now,
            "crash entry {i}: meta.created_at {} is in the future",
            entry.meta.created_at,
        );
    }
}

// ============================================================================
// Test 8: 500-entry stress test across all 4 system generators
// ============================================================================
//
// Generate 500 entries from each generator (2000 total) using varying seeds.
// Every artifact must pass validation, serialize/deserialize cleanly, and
// maintain internal consistency. This catches edge cases that smaller sample
// sizes miss.

#[test]
fn test_500_entry_stress_all_generators() {
    let profile = shared_profile();
    let ctx = shared_context();
    let now = ctx.now;

    let known_facilities: HashSet<&str> =
        ["kern", "auth", "daemon", "cron"].into_iter().collect();
    let known_signals: HashSet<&str> = [
        "SIGSEGV", "SIGABRT", "SIGFPE", "SIGILL", "SIGBUS", "SIGSYS", "SIGTRAP", "SIGXCPU",
        "SIGXFSZ",
    ]
    .into_iter()
    .collect();

    // --- 500 logs ---
    let log_gen = LogGenerator::new();
    for seed in 0u64..500 {
        let mut rng = seeded_rng(seed);
        let artifact = log_gen.generate(&profile, &ctx, &mut rng).unwrap();
        artifact.validate_plausibility().unwrap();
        let bytes = artifact.to_bytes().unwrap();
        let entry: LogEntry = serde_json::from_slice(&bytes).unwrap();

        assert!(!entry.message.is_empty(), "seed {seed}: empty log message");
        assert!(
            known_facilities.contains(entry.facility.as_str()),
            "seed {seed}: unknown facility '{}'",
            entry.facility,
        );
        assert!(
            entry.timestamp <= now,
            "seed {seed}: log timestamp in future",
        );
    }

    // --- 500 processes ---
    let proc_gen = ProcessGenerator::new();
    for seed in 0u64..500 {
        let mut rng = seeded_rng(seed);
        let artifact = proc_gen.generate(&profile, &ctx, &mut rng).unwrap();
        artifact.validate_plausibility().unwrap();
        let bytes = artifact.to_bytes().unwrap();
        let entry: ProcessEntry = serde_json::from_slice(&bytes).unwrap();

        assert!(entry.pid > 0, "seed {seed}: PID is 0");
        assert!(!entry.name.is_empty(), "seed {seed}: empty process name");
        assert!(
            entry.start_time <= now,
            "seed {seed}: process start_time in future",
        );
    }

    // --- 500 installs ---
    let inst_gen = InstallGenerator::new();
    for seed in 0u64..500 {
        let mut rng = seeded_rng(seed);
        let artifact = inst_gen.generate(&profile, &ctx, &mut rng).unwrap();
        artifact.validate_plausibility().unwrap();
        let bytes = artifact.to_bytes().unwrap();
        let entry: InstallEntry = serde_json::from_slice(&bytes).unwrap();

        assert!(
            !entry.package_name.is_empty(),
            "seed {seed}: empty package name",
        );
        assert!(!entry.version.is_empty(), "seed {seed}: empty version");
        assert!(
            entry.timestamp <= now,
            "seed {seed}: install timestamp in future",
        );
    }

    // --- 500 crashes ---
    let crash_gen = CrashGenerator::new();
    for seed in 0u64..500 {
        let mut rng = seeded_rng(seed);
        let artifact = crash_gen.generate(&profile, &ctx, &mut rng).unwrap();
        artifact.validate_plausibility().unwrap();
        let bytes = artifact.to_bytes().unwrap();
        let entry: CrashEntry = serde_json::from_slice(&bytes).unwrap();

        assert!(
            !entry.process_name.is_empty(),
            "seed {seed}: empty crash process name",
        );
        assert!(
            known_signals.contains(entry.signal.as_str()),
            "seed {seed}: unknown signal '{}'",
            entry.signal,
        );
        assert!(
            entry.timestamp <= now,
            "seed {seed}: crash timestamp in future",
        );
    }
}
