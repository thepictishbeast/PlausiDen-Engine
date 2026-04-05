# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/).

## [0.1.0] - 2026-04-04

### Added
- `engine-core`: Core traits (`DataGenerator`, `Artifact`), `UserProfile` builder, `OrganicScheduler`, `EngineConfig`, entropy management
- `engine-browser`: `HistoryGenerator` with referrer chains, `CookieGenerator` matching visited domains, `SearchGenerator` with interest-based queries
- Scaffold crates: `engine-fs`, `engine-comms`, `engine-location`, `engine-input`, `engine-network`, `engine-social`, `engine-system`
- WASM compilation support for `engine-browser`
- CI pipeline with format check, clippy, tests, WASM verification, and security audit
- Project documentation: README, ARCHITECTURE, CONTRIBUTING, SECURITY, CLAUDE.md
