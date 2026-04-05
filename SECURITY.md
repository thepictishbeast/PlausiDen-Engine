# Security Policy

## Reporting Vulnerabilities

Report security vulnerabilities to **security@plausiden.com**.

Do NOT open a public GitHub issue for security vulnerabilities.

We will acknowledge receipt within 48 hours and provide an initial assessment within 7 days.

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.1.x   | Yes       |

## Security Standards

### Cryptography
- All random number generation via `OsRng` or `ChaCha20Rng` seeded from OS entropy
- Symmetric encryption: ChaCha20-Poly1305
- Key exchange: X25519
- Signatures: Ed25519
- Hashing: BLAKE3 (speed), SHA-256 (compatibility)
- Password hashing: Argon2id (64 MiB memory, 3 iterations minimum)
- Key material zeroized via `zeroize` crate
- No custom cryptography

### Dependencies
- All dependencies audited via `cargo audit` in CI
- Minimized dependency count
- Prefer crates with no unsafe code or audited unsafe

### Data Handling
- No telemetry, analytics, or phone-home capability
- No secrets in log output at any level
- Generated artifact content never appears in logs
