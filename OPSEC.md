# PlausiDen-Engine — Operational Security

This document covers the security-sensitive operational choices that
users and integrators of `plausiden-engine` need to understand. The
engine is a library — it does not run as a daemon or hold
long-lived state on its own — but the types it exposes (especially
`engine-core::erasure` and `engine-core::duress`) have deployment-side
responsibilities that cannot be enforced from inside the library.

Authored: Claude 3, 2026-04-17.

---

## 1. Who this guidance is for

- **Integrators** wiring `engine-core` into a Desktop, Browser-Ext,
  or Android host.
- **Operators** running those hosts on machines that will hold
  `ErasableKey` instances for longer than a brief session.
- **Maintainers** extending `engine-core::erasure` / `duress` with
  new storage variants or response types.

---

## 2. Threat models covered

- Accidental disclosure of key material via swap, coredump, or
  process-memory snapshot.
- Duress passphrase scenarios where an adversary has physical access
  plus the ability to compel a user to type a passphrase.
- Side-channel discovery of which duress entry matched (via
  response timing).
- Forensic memory analysis of a suspended / crashed process.

---

## 3. Threat models NOT covered

- Active kernel compromise that bypasses `mlock` and reads physical
  RAM directly. Tier 3 territory (seL4 / PlausiDenOS).
- JTAG / cold-boot attacks against DRAM after power-off. The
  `zeroize` crate races the power timeline; DRAM remanence can
  preserve bits for seconds to minutes depending on temperature.
  Defense: full-disk encryption with hardware-backed key, shutdown-
  is-acceptable policy, not "suspend-to-RAM."
- Privileged `ptrace` attachments that read live process memory.
  `MADV_DONTDUMP` protects core dumps, not `ptrace`. Defense:
  kernel.yama.ptrace_scope = 2 or higher.

---

## 4. `engine-core::erasure` — operational considerations

### 4.1 Swap must be disabled on sensitive machines

`ErasableKey::new_in_memory` calls `mlock(2)` to pin the 32-byte key
material in RAM. This prevents the kernel from paging the key to
swap — **but only for the pages we mlock**. Any stale copy that was
on the heap before we mlocked, any copy passed by value into the
function (the `material: [u8; 32]` argument is ON THE STACK before
we Box it), can be paged if pressure arrives in the microsecond
window between allocation and mlock.

Operators holding long-lived secrets MUST disable swap:

- Linux: `swapoff -a`; remove swap entries from `/etc/fstab`;
  disable zRAM if configured (`systemctl disable zram-generator`).
- macOS: `sudo nvram boot-args="vm_compressor=1"` disables the
  swap compressor; Filevault encrypts swap but doesn't prevent it.
- Windows: Control Panel → System → Advanced → Performance Settings
  → Advanced → Virtual Memory → No paging file.

These are engineering choices, not kernel guarantees — verify after
every OS update. The v1.2 mandate is "document this caveat"; this
document is that documentation.

### 4.2 RLIMIT_MEMLOCK

On Linux, unprivileged processes have a default `RLIMIT_MEMLOCK` of
64 KiB (kernels < 5.17) or 8 MiB (since 5.17). Each `ErasableKey`
pins a 4 KiB page, so the 64 KiB limit allows ~16 keys before
`new_in_memory` returns `EngineError::MlockFailed`.

For hosts expecting many keys:

- Raise `RLIMIT_MEMLOCK` in the systemd unit:
  `LimitMEMLOCK=infinity` (or a specific byte count).
- Or grant the capability: `setcap cap_ipc_lock+ep <binary>`.

Either increases the attack surface slightly (an attacker who
compromises the process can mlock more memory than a normal process
could, starving the system). For most deployments the `LimitMEMLOCK`
approach is sufficient.

### 4.3 MADV_DONTDUMP is best-effort

On Linux, `madvise(MADV_DONTDUMP)` excludes the page from
coredumps. Some container runtimes, some older kernels, and some
custom kernels do not honor it. We do NOT error on its failure —
the primary defense is `mlock` + zeroize-on-drop. If coredump
exclusion matters for your deployment, also:

- `ulimit -c 0` in the shell / systemd `LimitCORE=0`.
- `/proc/sys/kernel/core_pattern` routes coredumps to `/dev/null`
  or to a logging system, not to a writable disk.
- Disable `systemd-coredump` service if unused.

### 4.4 Windows path is pending

`ErasableKey::new_in_memory` on non-Unix (including Windows) returns
with `locked: false` and no pinning. This is a known gap — task
#22's follow-on adds `VirtualLock`. Until then, Windows users should
treat `KeyStorage::Memory` as providing zeroize-on-drop but NOT
swap-resistance. Use `KeyStorage::Hardware` (TPM / Secure Enclave /
FIDO2) for Windows secrets if the threat model needs swap-resistance
today.

### 4.5 ErasureReceipt signatures are placeholder

The `ErasureReceipt.signature` field is currently a 64-byte zero
vec. Ed25519 signing lands with the engine signing-keys work;
consumers must NOT treat a current receipt as cryptographically
verifiable yet.

---

## 5. `engine-core::duress` — operational considerations

### 5.1 Passphrase hashing is the caller's responsibility

`verify()` does a byte-wise constant-time compare. The caller must
hash the typed passphrase with a memory-hard KDF (Argon2id at
minimum, scrypt acceptable, plain BLAKE3 is NOT) before passing to
`verify`. Storing BLAKE3-only hashes is acceptable only if the
passphrase itself has ≥128 bits of entropy, which most human-chosen
passphrases do not.

### 5.2 No response-timing side channel

`verify()` walks every configured duress entry unconditionally,
even after finding a match. This prevents "Count the wall-clock
time; if it's short, the match was early in the list" attacks.

The caller who **invokes** the matched response introduces timing
variance (decoy mount vs. silent erase are different syscalls with
different latencies). If the deployment needs timing indistinguish-
ability across responses, the caller must defer response execution
until AFTER a fixed wait, or always execute the slowest response
path (populated with no-ops for fast paths).

### 5.3 Response labels are for configuration only

`DuressEntry.label` is an optional human-readable name for the
settings UI. It is NOT returned from `verify()`. The security rule:
the popup / unlock prompt must never reveal which label matched —
even a "Duress (panic)" log line tells an adversary with access to
logs which configured entry fired.

Keep labels out of logs. The ring-buffer logger in Browser-Ext
(`log.ts::redactSecrets`) strips them; equivalent redaction is the
caller's responsibility on other platforms.

### 5.4 Don't short-circuit the verify for "empty real_hash"

A user who hasn't configured a real passphrase (fresh install) has
`real_hash: vec![]`. `verify(&cfg, b"")` in that state returns
`VerifyOutcome::Real` (empty matches empty in constant time). This
is by design — the unlock flow is responsible for requiring the
user to configure a real passphrase before relying on verify. The
engine does not enforce "non-empty real hash" because empty-hash
states are legitimate during setup.

Deployment check: reject `DuressConfig` where `real_hash.is_empty()`
at the unlock boundary, not inside `verify`.

---

## 6. Known failure modes

- **mlock limit exhaustion under key rotation churn.** If the host
  creates and drops ErasableKeys faster than munlock accounting
  catches up, `new_in_memory` starts returning MlockFailed. Seen
  on containerized deployments with tight `LimitMEMLOCK`. Fix:
  raise the limit.
- **zeroize racing a SIGKILL.** `ZeroizeOnDrop` / manual Drop
  don't fire if the process is killed with SIGKILL. There is no
  defense for this at the library level — full-disk encryption
  and power-off-on-suspicion are the only mitigations.
- **Fork-and-orphan.** Child processes inherit the mlocked pages
  but the parent owns the KeyId. If a fork is needed, decide
  upfront whether the child or parent keeps the key, have one
  side call `erase()`. We do not offer a "clone" method
  deliberately.

---

## 7. Recommended reading

- `man 2 mlock` — kernel page-locking semantics.
- `man 2 madvise` — MADV_DONTDUMP specifically.
- RFC 8439 — ChaCha20-Poly1305 (what ErasableKeys are typically
  used with).
- RFC 8032 — Ed25519 (what ErasureReceipt signatures will use).
- `zeroize` crate documentation, section "Caveats."
- `subtle` crate documentation, section "Timing attacks."
- OWASP Cryptographic Storage Cheat Sheet.

---

## 8. What this document does not cover

- Specific KDF tuning for your deployment's threat model. Argon2id
  parameters trade memory against authentication latency; consult
  OWASP or the libsodium docs.
- Secure-enclave integration. `KeyStorage::Hardware` is a variant;
  actually implementing it requires platform-specific code
  (kernel keyring, Secure Enclave framework, TPM PKCS#11, YubiKey
  PIV, etc.) outside this library.
- Passphrase-policy UX (complexity, rotation, recovery). That
  belongs in the host's settings UI.
