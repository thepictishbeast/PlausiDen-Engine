# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/).

## [Unreleased]

### Added — runtime hardening (2026-05-01)

**Sandbox facility for binary consumers (task #48)**
- New `engine_core::sandbox` module exposes `lock_down(opts) ->
  Result<()>` and `LockdownOpts { read_paths, write_paths }`.
- On Linux, applies a landlock V1 ruleset that limits the calling
  process's filesystem access to the supplied allowlist. After the
  call, attempting to read/write outside the allowlist returns
  EACCES regardless of file permissions or caller privileges.
- On non-Linux, logs an `info` line and returns Ok(()) — sandbox
  is the host runtime's responsibility (browser sandbox, JVM).
- SECURITY: defends against an in-engine compromise (corpus supply-
  chain attack, future bug, adversarial profile) — the blast
  radius is bounded by the sandbox, not by the generator code.
- Layered defence per the module docs: consumers should also drop
  capabilities (PR_SET_NO_NEW_PRIVS), optionally apply a seccomp
  filter, and run as an unprivileged user.
- 2 unit tests pin the LockdownOpts API shape; actual landlock
  enforcement is exercised in consumer binaries (cannot unit-test
  because the call permanently restricts the test process).

### Added — forensic plausibility cycle (2026-05-01)

**Cross-artifact correlation (task #40)**
- New `engine_core::schedule::pick_active_timestamp(profile,
  target_date, rng)` — public helper that samples a hour-of-day
  weighted by the user's `OrganicScheduler::activity_factor()`,
  with random minute and second. Replaces every uniform-random
  hour pattern across the browser/comms generators.
- `OrganicScheduler::activity_factor()` newly public so external
  generators can read the circadian weighting without holding a
  full scheduler instance.
- DownloadGenerator, BookmarkGenerator, AutofillGenerator
  (engine-browser) and SmsGenerator, EmailHeaderGenerator
  (engine-comms) all snap their `created_at`/`added_at`/
  `started_at`/`timestamp` fields to circadian-active hours via
  the new helper. Removes a forensic-detectable signal where
  synthetic 3am downloads/SMS/emails would have been flagged
  against a user's known wake/sleep pattern.
- SECURITY: night-owl profiles (wake=22, sleep=6) now correctly
  produce midnight artifacts instead of implausibly clustering
  at 8am — the previous hand-rolled per-generator distributions
  hard-coded business-hours assumptions.
- Per-template anchor invariant: every domain in
  `downloads::DOWNLOAD_TEMPLATES` must have at least one URL in
  `url_corpus` that "covers" it (same registered domain or
  sibling subdomain). Adding a new template without a matching
  corpus anchor now fails CI. New helpers
  `url_corpus::registered_domain` and
  `url_corpus::download_covered_by` (with their own unit tests).
- Software-vendor landing pages (mozilla.org/firefox/,
  google.com/chrome/, libreoffice.org, documentfoundation.org,
  ubuntu.com/download, zoom.us, rust-lang.org, pypi.org,
  pythonhosted.org, unsplash.com) added to the Technology
  category so each download template's parent vendor is
  visitable as history.
- `cdn.mozilla.net` template renamed to `download.mozilla.org`
  (the modern Firefox download endpoint, shares the mozilla.org
  eTLD+1 with the corpus anchor).
- End-to-end correlation regression: `engine-pipeline::
  test_downloads_are_always_anchored_in_history` runs a 500-
  artifact session and asserts every emitted download URL has
  a history URL on a covered domain. Three layers of defence
  for the property; a future regression fails at the layer it
  hits first.
- `engine_browser::url_corpus` promoted from private to public
  module so external tests can use the shared correlation
  helpers.

**Test stabilization**
- `engine-pipeline::test_session_walks_through_past_time`: 600s
  → 6000s window so the assertion stays green at every UTC hour
  (deep-sleep adjusted_interval up to 2400s).
- `engine-location::gps::tests::test_trace_1000_points_all_valid`:
  context anchored 4 days in the past so the 1000-point trace
  ends comfortably before the 24h-future cutoff under all RNG
  outcomes.

**Tests**: 638 → 646 across the workspace (+8 net).

### Added — security + testing cycle (2026-04-18)
- **duress.rs proptests.** 4 new property tests × 2k cases each (8k
  total): `unconfigured_input_returns_nomatch`,
  `real_hash_wins_over_duress_collision`,
  `reversal_preserves_duress_outcome`, `verify_never_panics`.
- **duress.rs constant-time SHIP-DECISION.** Formal AVP-2
  `SHIP-DECISION:` annotation documents the accepted residual
  timing channel where the matched-duress response `.clone()`
  makes match paths ~55-60% slower than no-match (measured via
  the bench below). Threat assessment shows the channel leaks
  the match boolean only, not the matched index. Two close-the-
  gap options (API refactor vs always-clone entry[0]) sketched
  for future work.
- **duress.rs criterion benchmark.** New
  `engine-core/benches/duress_verify.rs` parameterized over
  `list_len ∈ {1, 4, 16}` × 3 match conditions. Added
  `[[bench]] harness = false` to `engine-core/Cargo.toml`.
- **duress.rs ZEROIZATION CONTRACT fix.** Module doc previously
  implied `verify()` zeroized the caller's buffer — impossible
  with `&[u8]`. Rewrote the contract: caller owns the buffer,
  calls `verify`, then `zeroize_passphrase(&mut buf)` BEFORE
  branching on the outcome. New test `caller_owned_zeroize_pattern`
  exercises the sequence. 13 duress tests total.
- **`engine-core/examples/journalist_deadman.rs`.** Runnable
  `cargo run --example journalist_deadman -p engine-core` demo
  composing erasure + duress + deadman end-to-end: ErasableKey
  → DuressConfig with `SilentErase` response → DeadmanConfig
  with `Composite(EraseKey + AlertContacts)` → Ed25519-signed
  `ErasureReceipt` with `verify_with`. 170 lines; narrates each
  step on stdout.
- **CONTRIBUTING.md: AVP-2 annotation table.** 10-row grep-friendly
  vocabulary (`BUG ASSUMPTION` / `SAFETY` / `SECURITY` /
  `REGRESSION-GUARD` / `SHIP-DECISION` / `FOSS-ABSORBED` /
  `AVP-PASS-N` / `UX-DEBT` / `CROSSFIX` / `DEBUG-REMOVE`) with
  when-to-use + an annotated `ct_eq` example. File grew 57 → 102
  lines.
- **design/tokens.rs: status-`-on` variants.** Added
  `STATUS_{OK,WARN,ERR,INFO}_ON` constants mirroring CSS
  foreground-on-status tokens. Light: warn-on = black, others =
  white. Dark: all four = black.
  `dark_mode_has_same_token_set_as_light` test extended.
- **scripts/design/check-tokens-parity.sh.** Cross-file awk
  parity checker for `design/tokens.css` ↔ `design/tokens.rs`.
  44 color tokens match. Colors-only today; spacing / text /
  radius / motion is follow-on.

### Added — Ed25519 receipt signing cycle (2026-04-17)
- **Ed25519-dalek signing on `ErasureReceipt`** (task #47 advance).
  Added `ed25519-dalek = "2"` to workspace + engine-core deps.
  `ErasureReceipt::sign(key_id, erased_at, reason, &signing_key)`
  and `::verify_with(&verifying_key)` — third parties can verify
  a receipt without trusting this runtime given the published
  public key.
- **Canonical signing payload**: `key_id (16B) || erased_at (BE
  i64, 8B) || reason (1B)` — exactly 25 bytes. Documented so
  external verifiers can reconstruct without access to the Rust
  source.
- **`ErasureReason::tag_byte()`** — fixed 1-byte mapping
  `UserInitiated=0x01 / Deadman=0x02 / Duress=0x03 / Rotation=0x04
  / SwarmDestroy=0x05 / Policy=0x06`. A forensic-compat pin:
  NEVER renumber without invalidating every previously-issued
  receipt.
- **5 new unit tests + 3 proptest properties** for receipt
  signing: sign/verify roundtrip, tampered-timestamp rejection,
  wrong-key rejection, tag-byte stability (forensic-compat pin),
  bad-signature-length rejection, plus 768-case proptest coverage.
- **Cargo.toml**: `libc 0.2` (Unix) for mlock; `zeroize 1` with
  derive; `subtle 2` for constant-time compares; `ed25519-dalek 2`
  (std + rand_core features, no_std-ready default-features-off).

### Added — engine-comms::notifications (task #25 advance)
- **`engine-comms::notifications`** — v1.2 §D.3 / v1.1 §4.1
  synthetic-notification generator targeting the Prairie Land
  forensic pathway. `NotificationEntry`, 8-variant
  `NotificationCategory` (MessagingSecure / MessagingSms /
  MessagingTeam / Email / Social / Financial / Broadcast /
  System), `NotificationGenerator` impl `DataGenerator` with
  `forensic_weight() = 900` (highest in the suite).
- **APP_CATALOG**: 20+ real bundle IDs — Signal
  (`org.whispersystems.signal`) is present per v1.1 §4.1 mandate.
  Regression test pins it.
- **`CategoryProfile` struct**: consolidates title / body /
  median-latency / interaction-probability for each category into
  one lookup table (was four separate `match` blocks).
- **Bounded fields**: `validate_plausibility` enforces
  `MAX_TITLE_LEN=100 / MAX_BODY_LEN=500 / MAX_BUNDLE_LEN=128`.
  Unbounded strings are a fingerprint (no real Android app pushes
  a 4 KB title).
- **9 unit tests + 3 proptests**: Signal-in-catalog, per-category
  pools non-empty, forensic-weight = 900, artifact serde
  roundtrip, interacted ↔ latency invariant over 50 seeds, bundle
  IDs have reverse-DNS syntax, oversize field rejection (title /
  body / bundle), plus proptest coverage (any-seed validate,
  catalog integrity, posted-time-in-past).

### Changed
- Engine OPSEC.md (220 lines) — swap-disable mandate,
  `RLIMIT_MEMLOCK` tuning, `MADV_DONTDUMP` best-effort note,
  Windows-VirtualLock gap, duress KDF responsibility, response-
  timing side-channel discussion, known failure modes.
- Engine ARCHITECTURE.md — new "Security primitives
  (engine-core)" section documenting erasure / duress / deadman
  composition pattern.
- `engine-network/src/tls.rs` CROSSFIX (task #43 CLOSED):
  `.unwrap_or("example.com")` runtime fallback replaced with
  `.expect(...)` + `const _: () = assert!(!SNI_DOMAINS.is_empty())`
  compile-time assertion. An emptied slice now fails `cargo
  check` instead of leaking a synthetic TLD in generated TLS
  handshakes.
- `deny.toml` — audited and annotated with rationale;
  `multiple-versions = warn` pending rand-migration (task #21).

### Added
- `engine-core::erasure` — v1.2 §D.2 cryptographic erasure primitives.
  - `ErasableKey` with 32-byte mlocked material, `MADV_DONTDUMP` on
    Linux (best-effort), manual `Zeroize` on `Drop`, `munlock` on
    `Drop`. Unix path is fully functional; Windows `VirtualLock`
    pending (see task #22).
  - `KeyId` (UUIDv4), `KeyStorage` (Memory / MemoryAndDisk /
    Hardware / ShamirShares), `ErasureReason` (6 variants),
    `ErasureReceipt` (Ed25519 signature currently placeholder — real
    signing lands when engine signing keys are provisioned).
  - `Debug` impl redacts material as `[REDACTED 32B]`.
- `engine-core::duress` — v1.2 §D.2 constant-time passphrase
  verification.
  - `DuressConfig`, `DuressEntry`, `DuressResponse` (MountDecoy,
    SilentErase, SilentAlert, SanitizedMount, Composite),
    `VerifyOutcome` (Real / Duress(response) / NoMatch).
  - `verify()` uses `subtle::ConstantTimeEq` with all-or-nothing
    iteration (no short-circuit; no response-timing side channel
    leaking which entry matched).
- `engine-core::deadman` — v1.2 §D.2 dead-man switch decision layer.
  - `DeadmanConfig` with arm / disarm / check_in. `TriggerAction`
    (EraseKey / AlertContacts / SwarmDestroy / WipePaths /
    CustomHook / Composite). `DeadmanStatus`
    (Disarmed / Fresh / Warning / Fire). Pure `evaluate()` function —
    callers drive the timer. `simple_key_erase()` helper for the
    common case.
- `engine-core` deps: `zeroize` (derive), `subtle`, `libc` (Unix-only).
- Project-root `OPSEC.md` — 220-line operational-security doc
  covering the swap-disable mandate, `RLIMIT_MEMLOCK` tuning,
  `MADV_DONTDUMP` caveats, Windows pending gap, duress KDF
  responsibility, response-timing side channel, and failure modes.
- `deny.toml` audited, annotated with rationale, and extended with
  a `[bans]` section (multiple-versions = warn pending rand 0.9
  migration, task #21).

### Fixed
- **`engine-network/tls.rs` SNI fallback leak (CROSSFIX from
  PlausiDen-Browser-Ext leak audit, task #43).** Replaced
  `.unwrap_or("example.com")` runtime fallback with `.expect()` plus
  a `const _: () = assert!(!SNI_DOMAINS.is_empty())` compile-time
  assertion. The `.example` / `example.com` literal can no longer
  ship in generated TLS handshakes even under a future refactor
  that empties the slice.
- `engine-comms/calendar.rs` FIXME and `engine-browser/tests/
  cross_artifact.rs` TODO converted to annotated tasks #41 and #40
  respectively (REGRESSION-GUARD comments reference the task IDs).

### Known regressions
- `rand` 0.8 → 0.9 migration attempted workspace-wide during an
  autonomous-loop tick; bump produced ≥8 compile errors in
  `engine-core` alone (`rand::distributions` renamed,
  `StdRng::from_entropy` removed, `ChaCha20Rng` SeedableRng API
  moved). Reverted cleanly. Task #21 rescoped into 7 sub-steps
  21a-g; `rand = "0.8"` / `rand_chacha = "0.3"` remain pinned in
  the workspace until the sub-tasks land.

## [0.1.0] - 2026-04-04

### Added
- `engine-core`: Core traits (`DataGenerator`, `Artifact`), `UserProfile` builder, `OrganicScheduler`, `EngineConfig`, entropy management
- `engine-browser`: `HistoryGenerator` with referrer chains, `CookieGenerator` matching visited domains, `SearchGenerator` with interest-based queries
- Scaffold crates: `engine-fs`, `engine-comms`, `engine-location`, `engine-input`, `engine-network`, `engine-social`, `engine-system`
- WASM compilation support for `engine-browser`
- CI pipeline with format check, clippy, tests, WASM verification, and security audit
- Project documentation: README, ARCHITECTURE, CONTRIBUTING, SECURITY, CLAUDE.md
