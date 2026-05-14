# PlausiDen-Engine — vision document

> If PlausiDen-Engine did everything we wanted, what would this say?

**[shipped]** / **[queued]** / **[concept]**.

---

## 1. What PlausiDen-Engine IS

**Core data-generation library that synthesises forensically-
indistinguishable digital artifacts** — browser history,
cookies, search queries, files, contacts, GPS traces, network
traffic, social activity. The non-UI engine half of the
PlausiDen mission: restore the presumption of innocence by
making forensic-data presence prove nothing.

A Rust workspace with specialised generators per category:

| Crate | Generates |
|---|---|
| `engine-core`     | Traits, profiles, scheduling, configuration |
| `engine-browser`  | History / cookies / searches / bookmarks / downloads |
| `engine-fs`       | Files / metadata / thumbnails / trash artifacts |
| `engine-comms`    | Contacts / calls / SMS / calendar / email headers |
| `engine-location` | GPS traces / WiFi history / cell towers / EXIF |
| `engine-input`    | Keystrokes / touch events / mouse movement |
| `engine-network`  | DNS queries / HTTP timing / TLS fingerprints |
| `engine-social`   | Social-media activity patterns |
| `engine-system`   | OS logs / process history / install records |

PlausiDen-Engine is **not** a UI tool. Not a frontend (UI tools
that consume Engine — Atrium, AppGuard, BorderCloak — wrap it
with operator-facing surfaces). Not malware (Engine generates
synthetic data on the operator's own machine, with consent).
Not a forensic-evasion tool for committed crimes (Engine
restores neutrality, doesn't hide actual evidence).

## Dependencies

**Direct:**
- PlausiDen-Obs (typed events when generation runs)
- PlausiDen-AVP-Doctrine (graded against AVP-2)
- PlausiDen-Tests (contract harnesses for forensic-
  indistinguishability properties)

**Transitive:**
- (Obs root → AVP-Doctrine root → Tests via Canon → Canon root)

**Consumed by:** every PlausiDen UI / tool that needs synthetic
data — PlausiDen-Atrium, PlausiDen-AppGuard, PlausiDen-Product-*
crates that ship synthetic-data features. Forge does NOT
consume Engine directly (Engine is a runtime concern; Forge is
build-time).

## The meta-mission: AI-built UI reliability

Engine sits adjacent to the AI-built-UI mission rather than at
its centre. Its parallel mission: **AI agents synthesising
forensic data on behalf of operators need typed, contract-
verified generators.** An agent generating synthetic browser
history has to produce data forensically indistinguishable from
organic — that's a typed contract Engine enforces, not a
free-form LLM "make it look real" guess.

## 2. Capability map

| Capability | Status |
|---|---|
| `engine-core` traits + profiles + scheduling | shipped |
| Browser-history / cookie / search / bookmark / download generators | shipped |
| Filesystem / metadata / thumbnail / trash generator | shipped |
| Contacts / calls / SMS / calendar / email-header generator | shipped |
| GPS / WiFi / cell-tower / EXIF generator | shipped |
| Keystroke / touch / mouse generator | shipped |
| DNS / HTTP / TLS-fingerprint generator | shipped |
| Social-activity-pattern generator | partial |
| OS-log / process-history / install-record generator | partial |
| Forensic-indistinguishability property tests | queued |
| Per-profile coherence (timestamps, GPS, network all align) | queued |
| Differential-comparator vs organic-data baseline | concept |
| TLA+ specification of profile-coherence invariants | concept |
| Per-jurisdiction synthetic-data legality profile | concept |
| Hardware-attested synthesis (TPM signs every generated artifact) | concept |
| MCP server for agent queries (`generate_profile`, `synth_artifact`) | concept |
| Federation: peer-engine cross-verification of synthetic-data quality | concept |

## 3. Architecture

```
┌──────────── PlausiDen-Engine ────────────┐
│  engine-core (traits, profiles, schedule)│
│       │                                   │
│       ▼                                   │
│  Per-category generators (parallel):      │
│  ┌─ browser ─┐ ┌─ fs ─┐ ┌─ comms ──┐    │
│  ┌─ location┐ ┌─input┐ ┌─ network ─┐    │
│  ┌─ social ─┐ ┌─system┐                  │
│       │                                   │
│       ▼                                   │
│  Profile-coherence layer (cross-generator │
│  invariants: timestamps + GPS + network   │
│  all consistent within a single profile)  │
└───────────────────────────────────────────┘
       │                              │
       ▼                              ▼
   Consumer UIs                 PlausiDen-Obs
   (Atrium / AppGuard /         (typed events when
    Product-* tools)             generation runs,
                                 signed)
```

## 4. Roadmap

- **Sprint 1:** Forensic-indistinguishability property tests;
  per-profile coherence checks; differential-comparator vs
  organic baseline.
- **Sprint 2:** TLA+ specification of profile-coherence
  invariants; hardware-attested synthesis; MCP server.
- **Sprint 3:** Per-jurisdiction legality profiles; federation
  cross-verification.

## 5. Acceptance criteria

1. Every category generator produces data forensically
   indistinguishable from organic baselines under the
   differential-comparator.
2. Profile-coherence holds: a generated profile's timestamps,
   GPS, network, social activity are all internally
   consistent.
3. TLA+ spec proves coherence invariants are preserved across
   any generator update.
4. Hardware attestation lets a third party verify a synthetic
   artifact was generated by Engine (and therefore restores
   the burden of proof to the prosecution).
5. Every generation event lands as a typed Obs audit event,
   signed.
