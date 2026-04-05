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
