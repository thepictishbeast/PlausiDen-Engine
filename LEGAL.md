# Legal considerations — PlausiDen Engine

This document is NOT legal advice. It summarizes the considerations
authors and integrators should think about before shipping code that
consumes `engine-core`'s security primitives (`erasure`, `duress`,
`deadman`). If any of these situations applies to you, consult
qualified counsel in your jurisdiction.

Authored: Claude 3, 2026-04-18.

Related docs: `OPSEC.md` (operational constraints), `SECURITY.md`
(threat model), each consumer repo's own `LEGAL.md`
(jurisdiction-specific analysis — e.g. `PlausiDen-Browser-Ext/LEGAL.md`
covers US CFAA / GDPR / DMA with primary sources).

---

## 1. License

Engine is licensed under Business Source License 1.1 with an
Apache-2.0 change date (see `LICENSE`). Until the change date passes,
commercial redistribution is permitted only for non-competing uses
(i.e. not repackaging PlausiDen's own deliverables). Integrators who
vendor Engine into a closed-source commercial product should read the
full `LICENSE` + consult counsel on derivative-work interpretation.

---

## 2. Cryptographic erasure (`engine-core::erasure`)

### What it does

`ErasableKey` holds 32 bytes of key material in mlocked RAM and
zeroes them on drop. `ErasableKey::erase()` destroys the material
and returns an Ed25519-signed `ErasureReceipt` proving when + why
the key was destroyed.

### Legal posture

- **Spoliation.** Intentional destruction of evidence during
  pending or reasonably-foreseeable litigation can trigger
  adverse-inference instructions, sanctions, or in egregious
  cases obstruction-of-justice charges (US: Silvestri v. GM
  (4th Cir. 2001); UK: CPR 31.21). Integrators whose application
  fires `erase()` while litigation is pending or foreseeable
  should document a legitimate operational reason (e.g.
  data-minimization policy, user-requested export, crypto-key
  rotation) that predates the litigation trigger.
- **Daubert reliability challenges (US).** A signed
  `ErasureReceipt` is a positive audit artifact — it proves
  destruction happened at a specific time with a specific reason.
  Integrators can use it to rebut allegations of covert
  destruction (contrast "the data just wasn't there" with "the
  data was erased at 14:32:07 UTC per policy X, receipt ID Y").
- **GDPR / right to erasure.** Article 17 (right to erasure / "right
  to be forgotten") gives EU data subjects the right to have their
  personal data deleted. `ErasableKey` implementing a true
  cryptographic-erasure deletion (no recovery possible without the
  key) arguably satisfies Article 17 even when the encrypted
  ciphertext persists in backups — Recital 26 excludes
  irreversibly-anonymized data from the GDPR's scope.

---

## 3. Duress passphrases (`engine-core::duress`)

### What it does

A user configures a "duress" passphrase in addition to their real
one. Typing the duress passphrase fires a caller-chosen response
(`SilentErase`, `SilentAlert`, `MountDecoy`, etc.) while appearing
to unlock successfully from the attacker's perspective.

### Legal posture

- **Fifth Amendment (US).** Decryption compulsion doctrine is
  unsettled — the Supreme Court has not yet ruled. Circuit split:
  11th Circuit (In re Grand Jury Subpoena, 670 F.3d 1335 (2012))
  held that compelled decryption is testimonial, protected by 5A;
  3rd Circuit (US v. Apple MacPro, 851 F.3d 238 (2017)) held the
  foregone-conclusion doctrine permits compulsion when the
  government already knows the suspect has the capability. A
  duress passphrase is NOT "refusing to decrypt" — it's complying
  with a decryption order using a valid configured credential.
  The legal status of using a duress passphrase under court order
  is genuinely unresolved; if litigation arises, the core question
  is whether typing the duress passphrase constitutes
  false-statement to a government agent (18 USC §1001).
- **Article 6 ECHR (Europe).** The right against self-incrimination
  in criminal proceedings protects compelled production of
  documents (Funke v. France, 1993). A duress passphrase that
  triggers a `SilentErase` response could be characterized as
  destroying evidence under compulsion — potentially risky in
  jurisdictions with "tipping-off" offences (UK POCA 2002 §333A)
  or similar disclosure obligations.
- **Civil-context uses (abusive-partner, stalkerware, border
  forensics).** The civil-rights case for duress passphrases is
  strongest in non-prosecutorial contexts: coerced unlock by an
  intimate-partner stalker, rubber-hose border agent fishing
  expeditions, ransomware operator demanding proof of payment.
  Counsel should frame integrations around these use cases,
  not around prosecutorial defence, to minimize
  obstruction-of-justice exposure.

---

## 4. Dead-man switches (`engine-core::deadman`)

### What it does

A `DeadmanConfig` fires a `TriggerAction` (typically `EraseKey` +
`AlertContacts`) if the user fails to check in within a configured
window. `evaluate()` is a pure decision function — the host
schedules the polling.

### Legal posture

- **Prosecutorial angle.** A dead-man switch firing after an
  arrest / detention / seizure could be characterized as
  tampering with evidence (US: 18 USC §1519; UK: CJA 2003 §§44-46),
  particularly if it fires AFTER a search warrant was executed
  but before forensic extraction completed. Integrators should
  document that the timer is user-configured for legitimate
  operational reasons (journalist travelling to a high-risk
  region, activist in a jurisdiction with a history of
  border-device seizures) that predate any specific legal
  trigger.
- **Civil / next-of-kin.** Dead-man switches are commonplace in
  estate-planning contexts — a notarized Google Inactive Account
  Manager is a dead-man switch in the classical sense. The legal
  exposure scales with what the switch DOES, not with the switch
  itself. `AlertContacts` to a pre-identified attorney is lower
  exposure than `WipePaths` across a shared filesystem.
- **Shared / corporate devices.** A deadman fire on a
  corporate-managed laptop may violate employer data-retention
  policies; on a family / shared account, unrelated users lose
  access to data they didn't consent to destroy. Integrators
  should surface a pre-arm warning when the config touches paths
  outside the user's private home tree.

---

## 5. Shared-account and enterprise-managed scenarios

Engine primitives assume the user owns the device or at least the
account. In shared contexts:

- **Family account:** an `ErasableKey::erase()` tied to a shared
  encryption key affects every user on that account. Consumers
  should require a confirming UI gesture before firing.
- **Enterprise MDM / EDR:** corporate policy may prohibit local
  cryptographic erasure (data retention mandates, e-discovery
  readiness). `deadman::Fire` firing `EraseKey` on a managed
  device could violate the employment contract or regulatory
  requirements (SEC 17a-4 in finance, HIPAA in healthcare). Out
  of scope for Engine — consumers bear the compliance burden.
- **Jointly-owned data:** a journalist's source material and a
  family member's shared photo album sitting under the same
  `ErasableKey` is a bad integration. Key-separation is the
  consumer's responsibility (see `engine-core::erasure::KeyId`
  for the identity primitive that makes this tractable).

---

## 6. Out of scope

This document does NOT:

- Provide legal advice for any specific jurisdiction. Consult
  counsel.
- Analyze downstream consumer applications' posture (those have
  their own LEGAL.md with jurisdiction-specific analysis).
- Cover the legality of the *data being protected* — Engine
  generates or stores synthetic artifacts and erasable keys; the
  legality of specific content is not Engine's concern.
- Address employment / contract / NDA concerns that might restrict
  use of these primitives (e.g. a compliance officer's NDA may
  preclude configuring a duress passphrase on a corporate device).

---

## 7. Reporting legal inquiries

If you receive a legal notice (subpoena, preservation order,
search warrant) affecting an Engine-using application: DO NOT
trigger any Engine primitive that destroys evidence. Contact
qualified counsel immediately. A pending legal hold typically
overrides any configured dead-man timer or duress response;
failing to suspend automated destruction can escalate civil
issues to criminal exposure.
