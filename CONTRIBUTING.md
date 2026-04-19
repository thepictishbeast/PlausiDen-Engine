# Contributing to PlausiDen Engine

## Before You Start

1. Read `CLAUDE.md` for project standards
2. Read `ARCHITECTURE.md` for design decisions
3. Read `SECURITY.md` for security requirements

## Development Setup

```bash
# Install Rust (stable)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Add WASM target
rustup target add wasm32-unknown-unknown

# Install just
cargo install just

# Run all checks
just check-all
```

## Making Changes

1. Create a branch from `main`
2. Write your code following the standards in `CLAUDE.md`
3. Run `just check-all` — all checks must pass
4. Update `CHANGELOG.md` for significant changes
5. Submit a pull request

## Code Standards

- **Rust edition 2024** — use current idioms
- **No `unwrap()` in library code** — use `?` or `.expect("reason")`
- **Every public item gets a `///` doc comment**
- **80%+ test coverage** for implemented modules
- **`proptest`** for property-based testing on crypto/math code
- **Workspace dependency inheritance** — never duplicate versions in sub-crates

## Inline annotations (AVP-2)

We use a small, grep-friendly annotation vocabulary so CI and human
reviewers can audit assumptions without reading every commit. Use the
exact tags below; the `grep -rn 'TAG:'` for each should return every
instance in the repo.

| Tag                 | When to use                                                                                                                                                                   |
|---------------------|-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `BUG ASSUMPTION:`   | Every public function. One line describing what could go wrong in this code path.                                                                                             |
| `SAFETY:`           | Required above every `unsafe` block. Prove why the block is sound.                                                                                                            |
| `SECURITY:`         | Threat mitigated by this code + how. Use near constant-time compares, bounded deserialization, zeroize calls.                                                                 |
| `REGRESSION-GUARD:` | Code that exists only to prevent a past bug from returning. Include a reference to the test that would fail without it.                                                       |
| `SHIP-DECISION:`    | Dated annotation listing accepted residual risks and the human (or Claude session) who signed off. Required before any `cargo publish` / binary release.                      |
| `FOSS-ABSORBED:`    | `<crate> <version> <reason for vendoring>` — required when a third-party crate is hard-forked into this repo (see AVP-2 FOSS absorption protocol).                            |
| `AVP-PASS-N:`       | `<date> finding and resolution` — records that a specific AVP-2 pass found and closed an issue. Drop into the body of whichever function was touched.                          |
| `UX-DEBT:`          | Manual verification still required; note the risk if shipped without. Useful when a UI change cannot be covered by type-checker or unit test alone.                           |
| `CROSSFIX:`         | `<source-repo> <description>` — when a fix from a sibling repo is ported here. The source repo's commit SHA belongs in the message, not the code.                             |
| `DEBUG-REMOVE:`     | Line must be stripped before release. CI `cargo deny check` should flag any surviving instance.                                                                               |

Example of a well-annotated constant-time compare:

```rust
/// BUG ASSUMPTION: caller supplies a KDF-hashed candidate — raw
/// passphrase bytes here would still compare constant-time but would
/// leak the plaintext to any future log addition.
pub fn verify_hash(real: &[u8], candidate: &[u8]) -> bool {
    // SECURITY: subtle::ConstantTimeEq mitigates a wall-clock timing
    // side-channel. Do NOT replace with `==` or `Vec::eq`.
    // REGRESSION-GUARD: test `timing_variance_under_200ns` fails
    // if this is swapped for `==`.
    real.ct_eq(candidate).into()
}
```

## Narrative Framing

All public-facing text frames PlausiDen as a civil rights tool restoring the presumption of innocence. Never include personal political beliefs or ideology in any file.

## Security

- Audited crates only for cryptographic operations
- No custom cryptography
- Zeroize all secret material after use
- No secrets in log output at any level
- Run `cargo audit` before adding new dependencies

## License

By contributing, you agree that your contributions will be licensed under the BSL 1.1 with Apache 2.0 change date.
