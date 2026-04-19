# Architecture — PlausiDen Engine

## System Diagram

```
┌─────────────────────────────────────────────────────────┐
│                    UserProfile                          │
│  (demographic, device, interests, schedule, risk_level) │
└──────────────────────┬──────────────────────────────────┘
                       │
                       ▼
┌──────────────────────────────────────────────────────────┐
│                  OrganicScheduler                        │
│  (circadian rhythm, burst patterns, session modeling)    │
└──────────────────────┬───────────────────────────────────┘
                       │ timestamps
                       ▼
┌──────────────────────────────────────────────────────────┐
│              DataGenerator (trait)                       │
│                                                         │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐   │
│  │ Browser  │ │   FS     │ │  Comms   │ │ Location │   │
│  │ history  │ │ files    │ │ contacts │ │ GPS/WiFi │   │
│  │ cookies  │ │ metadata │ │ calls    │ │ cell     │   │
│  │ searches │ │ thumbs   │ │ calendar │ │ EXIF     │   │
│  └────┬─────┘ └────┬─────┘ └────┬─────┘ └────┬─────┘   │
│       │             │            │             │         │
│  ┌────┴─────┐ ┌────┴─────┐ ┌───┴──────┐ ┌───┴──────┐  │
│  │ Network  │ │  Input   │ │  Social  │ │  System  │   │
│  │ DNS/HTTP │ │ keys/    │ │ activity │ │ logs/    │   │
│  │ TLS/pkts │ │ touch    │ │ engage   │ │ procs    │   │
│  └──────────┘ └──────────┘ └──────────┘ └──────────┘   │
└──────────────────────┬───────────────────────────────────┘
                       │ Box<dyn Artifact>
                       ▼
┌──────────────────────────────────────────────────────────┐
│              Artifact (trait)                            │
│  - metadata (timestamps, category, size)                │
│  - validate_plausibility()                              │
│  - to_bytes() → serialized for injection/transmission   │
└──────────────────────┬───────────────────────────────────┘
                       │
              ┌────────┼────────┐
              ▼        ▼        ▼
         plausiden  plausiden  plausiden
         -inject   -swarm    -browser-ext
```

## Data Flow

1. **Profile** → A `UserProfile` defines who the synthetic person is: age range, interests, device, activity schedule, risk level.
2. **Scheduling** → `OrganicScheduler` generates timestamps following circadian rhythms — more active during waking hours, burst patterns, session-based browsing clusters.
3. **Generation** → Each `DataGenerator` produces artifacts matching the profile. A `HistoryGenerator` creates browser history with referrer chains. A `CookieGenerator` creates cookies matching visited domains. Generators are independent but share the profile for consistency.
4. **Validation** → Every artifact passes `validate_plausibility()` before emission. This catches impossible timestamps (modification before creation), empty URLs, zero visit counts, and other red flags.
5. **Output** → Artifacts are serialized via `to_bytes()` and consumed by downstream systems: `plausiden-inject` writes them to OS data stores, `plausiden-swarm` fragments and distributes them, `plausiden-browser-ext` uses them via WASM.

## Threat Model

### What We Defend Against
- **Forensic timeline construction**: Analysts build timelines from MAC timestamps, browser history, and communication metadata. Synthetic artifacts with consistent, organic-looking timestamps destroy timeline reliability.
- **Pattern-of-life analysis**: Analysts infer behavior from data patterns. Generated data follows real human patterns (circadian rhythm, interest clustering, session bursts) so it cannot be separated from organic data by pattern.
- **Known-file elimination (NSRL)**: Forensic tools hash files against known databases. Generated files have unique content that won't appear in NSRL, making them indistinguishable from real user-created files.
- **Cross-artifact correlation**: Analysts cross-reference cookies with history, downloads with files, GPS with photos. The engine generates correlated artifacts — cookies match visited domains, EXIF matches GPS traces — so cross-reference analysis finds no inconsistencies.

### What We Do NOT Defend Against
- **Real-time surveillance**: If an adversary is observing the device in real-time, they can see the engine running.
- **Network-level monitoring**: The engine generates artifacts locally. It does not generate network traffic (that's `plausiden-swarm`'s job). Tier 0 (browser extension) only covers the history/cookie surface, not network-level artifacts.
- **Hardware forensics**: Wear-leveling, flash translation layers, and hardware-level analysis are beyond the engine's scope (`plausiden-purge` and `plausiden-pdfs` address these).

## Key Design Decisions

### Why Rust
- Memory safety without garbage collection — critical for a security tool.
- Compiles to WASM for the browser extension (Tier 0).
- Compiles to native for desktop and Android (via JNI).
- `no_std` support enables embedded targets (USB device, PlausiDenOS).
- No runtime — small binaries, predictable performance.

### Why `Box<dyn Artifact>` Instead of Associated Types
The `DataGenerator` trait returns `Box<dyn Artifact>` (type-erased) rather than an associated type. This allows heterogeneous collections of generators — the engine orchestrator can hold `Vec<Box<dyn DataGenerator>>` and iterate over all generators regardless of their output types. The cost is one heap allocation per artifact, which is negligible compared to the I/O cost of injection.

### Why No `Serialize` Supertrait on `Artifact`
The `Artifact` trait uses `to_bytes()` for serialization instead of requiring `serde::Serialize` as a supertrait. This keeps serde out of the public API, which matters for WASM targets where binary size is critical. Concrete artifact types can still derive `Serialize` for convenience in tests and downstream consumers.

### Why `RngCore + CryptoRng` Bound
`CryptoRng` alone is a marker trait with no methods. The `RngCore` trait provides the actual `next_u32()`, `fill_bytes()`, etc. Both bounds are required.

## Forensic Analysis Resistance

### Timestamp Consistency
- Creation time is always ≤ modification time.
- Timestamps respect filesystem granularity: NTFS (100ns), ext4 (1ns), HFS+ (1s).
- Timestamps follow circadian rhythm — no browsing at 3am unless the profile says the user is a night owl.
- Within-session timestamps have short intervals (2-30s); between-session gaps are longer.

### Referrer Chain Integrity
- History entries include referrer URLs linking to previous visits.
- Transition types (typed, link, search result, bookmark) have realistic distributions.
- Search results link to the search engine URL, not orphaned.

### Cookie-History Correlation
- Cookies are generated for domains that appear in history.
- Cookie expiry distributions match what real servers set (session, daily, monthly, annual, 2-year).
- Cookie names come from real-world common cookies (_ga, _gid, JSESSIONID, etc.).

### Statistical Indistinguishability (Planned)
- **Adversarial test suite**: A statistical classifier will attempt to distinguish synthetic datasets from real browsing corpora. The pass criterion is that the classifier cannot do better than chance (AUC ≤ 0.55).
- **Distribution matching**: Inter-visit intervals, URL category distributions, cookie expiry distributions, and search query patterns will be calibrated against real-world datasets.
- This is the difference between "looks plausible on manual inspection" and "is mathematically indistinguishable."

## Security primitives (engine-core)

Three modules under `engine-core` handle key lifecycle and dead-hand
scenarios. They are shared across every tier — Desktop, Android, USB,
and the Swarm — so correctness matters disproportionately.

### `engine-core::erasure`

Cryptographic key erasure with pinned-RAM storage.

- `ErasableKey` holds 32 bytes of key material in a page `mlock`'d
  on Unix (`MADV_DONTDUMP` on Linux, best-effort), zeroized on
  `Drop`, `munlock`'d on `Drop`. Windows `VirtualLock` support is
  pending.
- `KeyStorage` variants: `Memory` (implemented), `MemoryAndDisk`,
  `Hardware` (TPM / Secure Enclave / FIDO2), `ShamirShares` (via
  `PlausiDen-Shard`). Only `Memory` is implemented today.
- `ErasureReceipt` with Ed25519 signature (signature currently a
  64-byte zero placeholder until the engine signing keys are
  provisioned).
- `Debug` impl redacts material as `[REDACTED 32B]`.

The `OPSEC.md` in this repo covers the swap-disable mandate,
`RLIMIT_MEMLOCK` tuning, and the Windows gap.

### `engine-core::duress`

Constant-time passphrase verification.

- `DuressConfig` holds a real-passphrase hash plus an ordered list
  of `DuressEntry` (each a hash + `DuressResponse`).
- `verify(cfg, candidate_hash) -> VerifyOutcome` uses
  `subtle::ConstantTimeEq` against every entry (all-or-nothing
  iteration; no short-circuit). Returns `Real`,
  `Duress(response)`, or `NoMatch` — the caller cannot tell from
  timing which entry matched.
- `DuressResponse` variants: `MountDecoy`, `SilentErase`,
  `SilentAlert`, `SanitizedMount`, `Composite`.
- Caller responsibility: KDF the typed passphrase (Argon2id
  recommended) before passing. See `OPSEC.md` §5.1.

### `engine-core::deadman`

Dead-man switch decision layer (pure — timing is the caller's).

- `DeadmanConfig` with `arm`, `disarm`, `check_in`, `evaluate`
  (pure function taking current Unix time).
- `TriggerAction` variants: `EraseKey`, `AlertContacts`,
  `SwarmDestroy`, `WipePaths`, `CustomHook`, `Composite`.
- `DeadmanStatus` variants: `Disarmed`, `Fresh`, `Warning`, `Fire`.
- Intentionally no background timer in this module — hosts drive
  the cadence (a Tokio wrapper lands with task #24 follow-on).
- `simple_key_erase()` convenience for the most common config.

### Interaction

The three primitives compose: a `DeadmanConfig` whose
`TriggerAction` is `EraseKey { key_ids }` lets an `ErasableKey`
auto-wipe if the user goes silent. A `DuressConfig` whose
`DuressResponse` is `SilentErase { key_ids }` wipes the same keys
if a duress passphrase fires. The caller wires these.

## Future Directions

### Adversarial Testing (Priority)
Add `tests/adversarial/` with statistical distinguishers as benchmarks. If the distinguisher can tell synthetic from organic data, the generator is broken.

### Engine Orchestrator
A top-level `Engine` struct that manages multiple generators, respects resource limits, and produces correlated artifact streams (e.g., history + matching cookies + matching DNS queries).

### LFI Integration
The Localized Forensic Intelligence (neurosymbolic AI) will drive the engine, making generation decisions based on the current threat environment rather than static profiles.

### WASM Optimization
Minimize binary size for the browser extension. Tree-shake unused generators. Profile and optimize hot paths.

---

## Out of Scope

Per v1.2 §G.3. The Engine is a pure data-generation library — it
produces `Box<dyn Artifact>` items plus the security primitives
(`erasure`, `duress`, `deadman`). It does NOT:

- **Write to the host filesystem or browser stores.** That is
  `plausiden-inject`'s job. Engine crates return artifacts;
  consumers decide where (and whether) to materialize them. A
  plaintext-file adapter, a `places.sqlite` adapter, or a
  "discard" consumer are all valid wirings.
- **Open network sockets, resolve DNS, or otherwise touch the
  network.** `engine-network` generates network-shaped
  *artifacts* (DNS query records, HTTP log lines) but does not
  emit real packets. Anything that would produce observable
  network traffic belongs in a separate `plausiden-net-emit`
  layer if and when it is ever scoped.
- **Manage user credentials, vaults, or OS keyrings.**
  `engine-core::erasure::ErasableKey` is a memory-lifetime
  primitive only — it mlocks and zeroizes a 32-byte buffer. Any
  on-disk key material, including the Ed25519 signing key used
  by `ErasureReceipt::sign`, must be provisioned by the caller
  (Desktop via Tauri secure storage; Android via Keystore).
- **Schedule work over wall-clock time.** Engine's
  `engine-core::schedule` computes *delays* from a circadian +
  burst + jitter model; hosts (Browser-Ext's `alarms`, Desktop's
  Tokio runtime) turn those delays into timer firings.
  `engine-core::deadman::evaluate` is likewise a pure decision
  function — the caller holds the clock.
- **Enforce OS-level sandboxing.** seccomp, landlock, pledge,
  capability-dropping, AppArmor, SELinux profiles — all belong
  in the host. Engine is a library and inherits whatever
  confinement the host process is running under. See `OPSEC.md`
  for the per-host expected sandbox posture.
- **Provide a binary / CLI / daemon.** Engine ships as workspace
  crates only. Consumers (`plausiden-browser-ext` → WASM,
  `plausiden-desktop` → Tauri, `plausiden-android` → JNI) wrap
  the library.
- **Implement anti-forensic detection or evasion of running
  security tools.** Engine is an *artifact* generator; whether
  those artifacts land in a filesystem a forensic tool will scan
  is a consumer concern (handled by `plausiden-inject` and by
  Desktop's `stealth.rs` detection layer).

Scope creep beyond this boundary lands downstream; keeping the
library pure is what makes the AVP-2 Tier 3 threat model
tractable.
