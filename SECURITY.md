# Security Policy

SN360 Desktop Agent (SDA) is a security product. We take
vulnerability reports seriously and prioritise them ahead of
other work.

## Supported versions

We accept and triage vulnerability reports against the current
release branch (the most recent tagged release on `main`). Older
preview tags are not supported.

## Reporting a vulnerability

**Do not open a public issue, pull request, or discussion thread
for security vulnerabilities.**

Send the report to **[security@uney.com](mailto:security@uney.com)**.
Encrypt sensitive details with our PGP key (fingerprint published
at [https://uney.com/.well-known/security.txt](https://uney.com/.well-known/security.txt))
if the issue involves credentials, exploit code, or PII.

A useful report includes:

- A short description of the vulnerability and its impact.
- The affected SDA version (from `sda-agent --version`) and OS.
- Reproduction steps, ideally with a minimal config and a
  redacted log excerpt.
- Any proof-of-concept code or sample inputs.
- Whether the issue has been disclosed elsewhere.

## Our response

We aim to:

- Acknowledge the report within **2 business days**.
- Provide an initial assessment (confirmed / not confirmed /
  needs more information) within **7 business days**.
- Publish a fix in a tagged release within **90 days** for
  high-severity issues, sooner for actively exploited ones.

We will coordinate disclosure with you. Public advisories
(CVE, GitHub Security Advisory, changelog entry) credit the
reporter unless you ask to remain anonymous.

## Out of scope

The following are not vulnerabilities for the purposes of this
policy:

- Operator misconfiguration that disables a security feature
  (e.g. running with `local_detection.enabled: false`,
  `mdm.auto_remediate.* : false`, or `device_control.enabled:
  false` and then being surprised that the feature does not
  work). The defaults documented in
  [`docs/configuration-reference.md`](./docs/configuration-reference.md)
  are the supported configuration.
- Theoretical issues that require an already-compromised host
  (e.g. an attacker with `root` / `SYSTEM` and `SeDebugPrivilege`
  is by definition outside the agent's threat model).
- False positives or false negatives in regex-based DLP
  patterns. DLP is precision-tuned and intentionally errs toward
  fewer false positives; tune the pattern set in
  [`docs/configuration-reference.md`](./docs/configuration-reference.md)
  rather than reporting baseline coverage as a vulnerability.
- Performance issues without a security impact. File these as
  regular bugs.

## Crypto and signing posture

A high-level summary of the cryptographic invariants the agent
relies on lives in [`docs/security.md`](./docs/security.md):

- TLS 1.3 only (via `rustls`) when the enhanced protocol is on.
- Ed25519 signatures on TRDS detection bundles, signed action
  jobs, configuration profiles, software catalogue manifests,
  and script runner payloads. Key rotation sets are pinned in
  the agent at build time.
- ChaCha20-Poly1305 + per-device HKDF-SHA256 wrapping key on
  recovery-key escrow.
- Blake3 fingerprints on DLP evidence (no matched bytes — see
  the redaction invariant in
  [`docs/architecture.md`](./docs/architecture.md)).
- Self-pid exclusion on the memory scanner, enforced at both the
  PAL trait boundary and the rule engine.

If you find a way to bypass any of these invariants, that is a
security vulnerability and we want to hear about it.

## Hall of fame

Maintained on our website at
[https://sn360.com/security/credits](https://sn360.com/security/credits)
once we have credited reports to publish.
