> # ⚠️ DO NOT USE — UNVERIFIED — UNSAFE ⚠️
>
> This software is **unverified and unsafe for any production use**.
> It is published publicly only for transparency, third-party audit,
> and reproducibility. Treat every commit as guilty until proven
> innocent.
>
> By using this code you accept:
> - **No warranty** of any kind, express or implied.
> - **No fitness** for any particular purpose.
> - **No guarantee** of correctness, safety, or freedom from defects.
> - **Zero liability** on the maintainer for any damages — data loss,
>   security compromise, financial loss, or any consequential damages.
>
> The code is under active engineering development per the
> [Adversarial Validation Protocol v2](https://github.com/thepictishbeast/PlausiDen-AVP-Doctrine/blob/main/AVP2_PROTOCOL.md).
> Every commit's default verdict is **STILL BROKEN**. AVP-2 requires
> a minimum of 36 verification passes before a `SHIP-DECISION:`
> annotation may be considered. **No commit in this repository has
> reached `SHIP-DECISION:` status.**

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
| engine-core (traits, profile, scheduling, entropy) | Implemented |
| engine-core::erasure (mlock + zeroize + Ed25519 signing) | Implemented (Unix; Windows `VirtualLock` pending) |
| engine-core::duress (constant-time passphrase verification) | Implemented (core; KDF integration pending) |
| engine-core::deadman (decision layer, arm / disarm / evaluate) | Implemented (tokio wrapper follow-on) |
| engine-browser (history, cookies, searches) | Implemented |
| engine-browser (bookmarks, downloads, autofill, localStorage) | Scaffolded |
| engine-comms::notifications (Prairie-Land pathway, weight=900) | Implemented (core; diurnal / per-profile mix follow-on) |
| engine-comms (contacts, calls, SMS, calendar, email headers) | Scaffolded |
| engine-fs | Scaffolded |
| engine-location | Scaffolded |
| engine-input | Scaffolded |
| engine-network (TLS fingerprints, DNS, HTTP) | Scaffolded |
| engine-social | Scaffolded |
| engine-system | Scaffolded |
| WASM compilation | Verified |
| Adversarial distinguisher (AUC ≤ 0.55 target) | Planned |

## Security Primitives — the three pillars

- **Cryptographic erasure** (`engine-core::erasure`) — 32-byte keys
  in mlocked RAM with `MADV_DONTDUMP` on Linux, zeroized on drop.
  `ErasureReceipt` is Ed25519-signed over a canonical 25-byte
  payload (`key_id || erased_at-BE || reason-tag`) so a third party
  can verify a receipt without trusting this runtime — only the
  published public key and the canonical encoding.
- **Duress passphrases** (`engine-core::duress`) — constant-time
  compare via `subtle::ConstantTimeEq`, all-or-nothing iteration,
  no response-timing side channel leaking which entry matched.
  Responses: `MountDecoy / SilentErase / SilentAlert /
  SanitizedMount / Composite`.
- **Dead-man switch** (`engine-core::deadman`) — pure `evaluate()`
  decision layer (host drives the timer). Status:
  `Disarmed / Fresh / Warning / Fire`. Actions: `EraseKey /
  AlertContacts / SwarmDestroy / WipePaths / CustomHook /
  Composite`.

See `OPSEC.md` for the operational-security constraints these
primitives impose on hosts (swap-disable, `RLIMIT_MEMLOCK`,
Windows gap, KDF responsibility, response-timing advice).

## Quick Start

```bash
git clone https://github.com/thepictishbeast/PlausiDen-Engine.git
cd PlausiDen-Engine
just check-all
```

### Composing the three pillars

A runnable demo under `engine-core/examples/` walks through a
journalist's threat model — `ErasableKey` held in memory, a
`DuressConfig` whose duress passphrase fires `SilentErase`, and a
`DeadmanConfig` whose 24-hour silence fires
`Composite(EraseKey + AlertContacts)`, all finishing with an
Ed25519-signed `ErasureReceipt` verified against a verifying key.

```bash
cargo run --example journalist_deadman -p engine-core
```

The example prints each decision step on stdout; read it
top-to-bottom as a copy-paste pattern for your own integration.

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
