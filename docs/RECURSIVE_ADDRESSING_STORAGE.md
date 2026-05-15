# Recursive-Addressing Storage — cross-reference

The full design doc lives in the LFI repo:
**`PlausiDen-AI/docs/RECURSIVE_ADDRESSING_STORAGE.md`**
(GitHub: <https://github.com/thepictishbeast/PlausiDen-AI/blob/main/docs/RECURSIVE_ADDRESSING_STORAGE.md>)

## Why this doc exists here

PlausiDen-Engine ships the synthetic-data generation side of the
PlausiDen plausible-deniability story. The recursive-addressing
storage layer is a **different mechanism** but a **complementary
composition** target:

- **PlausiDen-Engine** generates plausible-looking innocuous content
  (synthetic emails, browsing history, document trees, etc.) at the
  **content layer**.
- **plausiden-recursive-storage** (new LFI-workspace crate, design
  in PlausiDen-AI/docs/) provides a **substrate layer** where that
  synthetic content can be the *surface decoding* of a multi-decoding
  filesystem while real content lives in the same physical storage
  under a different addressing scheme.

They compose: Engine produces the surface; the storage layer hosts
both surface and real content over the same primitives, with the
addressing scheme separating them.

## What changes for PlausiDen-Engine

Nothing concrete yet — this is a parallel-track research/v1.5 item.
Implementation begins after LFI v1.0 critical path completes
(Confidentiality Kernel, PlausiDen Secrets, core LFI capability).

When implementation does begin, Engine will likely gain:

1. A **surface-content generator mode** that produces output explicitly
   shaped for storage-layer consumption (statistically matching
   real-filesystem distributions: file-size, timestamp clustering,
   directory depth, file-type frequency).
2. A **primitive-pool feeder** mode that contributes synthetic
   chunks to the storage layer's base alphabet.
3. Hooks for the storage layer's audit log so Engine-generated
   surface content has a traceable provenance even when the deeper
   addressing scheme is sealed.

## Scope reminder

This pointer doc deliberately stays thin to avoid drift. Authoritative
content stays in the LFI repo. Update there; this file only updates
when the *relationship between Engine and storage* changes.
