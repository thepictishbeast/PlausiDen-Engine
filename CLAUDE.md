# CLAUDE.md — Instructions for Claude Code

## IMPORTANT: If this is the first message in a session or context was recently compacted, read this entire file before doing anything else. Do not rely on conversation history.

## Project: plausiden-engine
Core data pollution library for the PlausiDen ecosystem. Generates forensically indistinguishable synthetic artifacts — files, browser history, contacts, keystrokes, GPS traces, network traffic, and more.

## Part of the PlausiDen Ecosystem
This repo is part of PlausiDen (PLAUSIbly DENiable) protection suite — AI-powered tools that generate forensically indistinguishable synthetic data, defeating surveillance and forensic overreach. All repos share the same standards.

## Architecture
This is a Cargo workspace with 9 crates:
- `engine-core` — traits, UserProfile, scheduling, config, entropy (FULLY IMPLEMENTED)
- `engine-browser` — history, cookies, searches, bookmarks, downloads, autofill, localStorage (CORE IMPLEMENTED, some modules scaffold)
- `engine-fs` — filesystem artifacts (SCAFFOLD)
- `engine-comms` — contacts, calls, SMS, calendar, email (SCAFFOLD)
- `engine-location` — GPS, WiFi, cell towers, EXIF (SCAFFOLD)
- `engine-input` — keystrokes, touch, mouse, gestures (SCAFFOLD)
- `engine-network` — DNS, HTTP, TLS, packets (SCAFFOLD)
- `engine-social` — social media activity (SCAFFOLD)
- `engine-system` — OS logs, processes, installs, crashes (SCAFFOLD)

## Key Design Decisions
- `DataGenerator` returns `Box<dyn Artifact>` (type-erased) so generators can be held in heterogeneous collections
- `Artifact` trait does NOT require `Serialize` supertrait — uses `to_bytes()` instead to avoid forcing serde on WASM consumers
- RNG parameters use `&mut (impl RngCore + CryptoRng)` — CryptoRng alone is insufficient (marker trait only)
- Workspace dependency inheritance via `[workspace.dependencies]` — never duplicate version specs in sub-crates
- engine-browser must compile to both native and `wasm32-unknown-unknown`

## Before Making Any Changes
1. Run `cargo test --workspace` to verify current state
2. Run `cargo check --target wasm32-unknown-unknown -p engine-browser` to verify WASM compat
3. Check that README.md, ARCHITECTURE.md, CONTRIBUTING.md, SECURITY.md, CHANGELOG.md exist

## Code Standards
- Language: Rust (edition 2024)
- Error handling: `thiserror` for library errors. Never `unwrap()` in library code.
- Documentation: Every public function, struct, module gets a `///` doc comment.
- Testing: 80%+ coverage for core modules. `proptest` for crypto/math. Every bug fix gets a regression test.
- Security: Audited crates only for crypto (ring, ed25519-dalek, chacha20poly1305). No custom crypto. Zeroize secrets. No secrets in logs.
- Logging: `tracing` crate. ERROR/WARN/INFO/DEBUG/TRACE levels.
- Dependencies: Minimize. `cargo audit` before adding new deps. Use workspace dependency inheritance.
- Cargo.lock: Do NOT commit (this is a library crate).

## After Making Changes
1. Run `cargo fmt --all` and `cargo clippy --workspace -- -D warnings`
2. Run `cargo test --workspace` — all tests must pass
3. Run `cargo check --target wasm32-unknown-unknown -p engine-browser`
4. Update CHANGELOG.md for significant changes
5. Update ARCHITECTURE.md if architecture changed

## Narrative Framing
All public-facing text must frame PlausiDen as a civil rights tool restoring the presumption of innocence. Use: "plausible deniability," "presumption of innocence," "forensic reliability," "data sovereignty," "surveillance resistance," "digital civil rights." Avoid: "hacking," "evasion," "anti-forensics," "hide," "trick," "fool."

NEVER include personal political beliefs or ideology of any contributor in any file.

## Ecosystem Dependencies
- plausiden-inject: Consumes artifacts from this engine, writes to OS data stores
- plausiden-swarm: Distributes encrypted fragments across P2P network
- plausiden-browser-ext: Uses engine-browser compiled to WASM
- plausiden-desktop: Uses engine + inject for desktop pollution
- plausiden-android: Uses engine via JNI bridge
