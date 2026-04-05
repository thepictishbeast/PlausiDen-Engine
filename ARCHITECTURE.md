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

## Future Directions

### Adversarial Testing (Priority)
Add `tests/adversarial/` with statistical distinguishers as benchmarks. If the distinguisher can tell synthetic from organic data, the generator is broken.

### Engine Orchestrator
A top-level `Engine` struct that manages multiple generators, respects resource limits, and produces correlated artifact streams (e.g., history + matching cookies + matching DNS queries).

### LFI Integration
The Localized Forensic Intelligence (neurosymbolic AI) will drive the engine, making generation decisions based on the current threat environment rather than static profiles.

### WASM Optimization
Minimize binary size for the browser extension. Tree-shake unused generators. Profile and optimize hot paths.
