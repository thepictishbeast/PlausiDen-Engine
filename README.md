# PlausiDen Engine

The core data generation library for the PlausiDen ecosystem. Generates synthetic digital artifacts — browser history, cookies, search queries, files, contacts, GPS traces, network traffic — that are forensically indistinguishable from organic human data.

## The Problem

Digital forensic evidence is treated as infallible by courts and law enforcement. Data found on a device is assumed to have been created by the device's owner. This assumption is wrong — malware can plant files, shared networks create ambient data, cloud sync generates data without user action, and timestamps are trivially manipulated. But in practice, the mere presence of data shifts the burden of proof to the defendant.

PlausiDen Engine restores the presumption of innocence. If synthetic data is indistinguishable from organic data, forensic analysis becomes unreliable, and data presence alone cannot establish guilt.

## How It Works

The engine is a Rust workspace with specialized generators for each forensic data category:

```
engine-core          Traits, profiles, scheduling, configuration
engine-browser       History, cookies, searches, bookmarks, downloads
engine-fs            Files, metadata, thumbnails, trash artifacts
engine-comms         Contacts, calls, SMS, calendar, email headers
engine-location      GPS traces, WiFi history, cell towers, EXIF
engine-input         Keystrokes, touch events, mouse movement
engine-network       DNS queries, HTTP timing, TLS fingerprints
engine-social        Social media activity patterns
engine-system        OS logs, process history, install records
```

Every generator takes a `UserProfile` (demographic, device, interests, activity schedule) and produces artifacts with organic timing patterns, realistic referrer chains, and internally consistent metadata.

## Current Status

| Component | Status |
|-----------|--------|
| engine-core | Implemented |
| engine-browser (history, cookies, searches) | Implemented |
| engine-browser (bookmarks, downloads, autofill, localStorage) | Scaffolded |
| engine-fs | Scaffolded |
| engine-comms | Scaffolded |
| engine-location | Scaffolded |
| engine-input | Scaffolded |
| engine-network | Scaffolded |
| engine-social | Scaffolded |
| engine-system | Scaffolded |
| WASM compilation | Verified |
| Adversarial test suite | Planned |

## Quick Start

```bash
git clone https://github.com/redcaptian1917/PlausiDen-Engine.git
cd PlausiDen-Engine
just check-all
```

## The PlausiDen Ecosystem

This repo is part of PlausiDen — an AI-powered plausible deniability suite that protects against surveillance and forensic overreach.

- **plausiden-inject** — Platform-specific injection adapters (Linux, macOS, Windows, Android, iOS)
- **plausiden-swarm** — P2P data pollution network with differential privacy guarantees
- **plausiden-browser-ext** — Tier 0 browser extension (Chrome/Firefox)
- **plausiden-desktop** — Tier 2 Tauri desktop app
- **plausiden-android** — Tier 1 Android app
- **plausiden-usb** — Tier 4 hardware device with cryptographic proof of connection

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## Security

See [SECURITY.md](SECURITY.md). Report vulnerabilities to security@plausiden.com.

## License

Business Source License 1.1 with Apache 2.0 change date of 2030-04-04. See [LICENSE](LICENSE).
