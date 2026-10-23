# TrustVault threat model

Initial design-stage threat register, dated 2026-10-23. These are threats and
planned controls, not claims that controls or tests already exist. The API
must deny access unless a valid authenticated identity and an explicit
authorization rule allow it.

| # | Threat | Planned mitigation | Test to add |
| --- | --- | --- | --- |
| 1 | User guesses another document ID (IDOR) | Check document ownership/grants server-side on every request. | User A cannot read User B's document by known or guessed ID. |
| 2 | Viewer attempts to edit metadata | Separate read and edit grants; enforce action-specific API policy. | Viewer edit request is denied and audited. |
| 3 | Revoked user reuses stale access | Query current grant state on each request; do not use long-lived signed URLs. | Revocation makes the next read and download fail. |
| 4 | Client forges admin role or owner ID | Derive identity and role from server-side session and database; ignore client permission fields. | Forged role/owner values do not grant privileges. |
| 5 | Search leaks restricted document names or owners | Apply authorization predicates inside the server-side search query before returning any row or count. | Search results and counts exclude inaccessible records. |
| 6 | Unauthorized download/preview | Re-authorize immediately before fetching and streaming each object. | Unauthorized download and preview fail without bytes or private metadata. |
| 7 | Malicious or oversized upload | Enforce size limits, allow-listed content types, signature/content checks, and safe streaming; consider malware scanning. | Invalid signatures, disallowed types, and over-limit files are rejected. |
| 8 | Path traversal or object-key manipulation | Generate opaque object keys on the server; never concatenate user filenames into filesystem paths or keys. | Traversal strings and crafted identifiers cannot read/write another object. |
| 9 | Public exposure of stored files | Keep the B2 bucket private; serve bytes only through authorized API routes. | Configuration/integration test verifies no public object access path is emitted. |
| 10 | SQL injection through search or metadata | Zod-validate inputs and use parameterized `mysql2` queries; allow-list sort fields. | Injection-shaped inputs are treated as data or rejected. |
| 11 | Session theft or fixation | Use opaque server-side sessions, rotate on login/privilege change, and set Secure/HttpOnly/SameSite cookies with bounded lifetime. | Cookie attributes and session rotation/expiry are verified. |
| 12 | Cross-site request forgery | Use SameSite cookies plus a CSRF token/origin check for state-changing requests. | Cross-origin state changes without valid CSRF proof are denied. |
| 13 | Brute-force login or API abuse | Apply rate limits to authentication and sensitive endpoints; return generic login failures. | Repeated requests hit the configured limit without account enumeration. |
| 14 | Permission change without matching audit record | Update grants and append the audit event in one database transaction. | Forced audit insert failure rolls back the permission update. |
| 15 | Audit record altered or removed | Append-only application code; link canonical events with hashes and verify sequence/chain. | Changing or deleting an event causes verification to report tampering. |
| 16 | Privileged database operator rewrites whole audit chain | Document limitation; later consider externally anchored hashes or independent immutable storage. | Demonstrate chain verification detects local edits; explicitly test/document that a fully recomputed chain cannot be detected by itself. |
| 17 | Sensitive document metadata exposed in errors/logs | Use generic external errors; redact filenames, content, cookies, credentials, and SQL details from logs. | Denied responses do not disclose metadata; log-redaction tests cover secrets. |
| 18 | Stolen database/storage credentials | Least-privilege accounts, TLS, secret environment variables, rotation, and separate test credentials. | Configuration checks fail closed when required production secrets are missing. |
| 19 | Destructive admin or owner deletion request | Require authorization, use safe deletion/retention policy, and audit the operation; avoid deleting bytes before metadata transaction outcome is known. | Unauthorized delete fails; authorized delete and audit state remain consistent on injected failure. |
| 20 | Production data contaminates automated tests | Use isolated test database/schema and synthetic fixtures; refuse production-like DB targets in test mode. | Test bootstrap rejects a configured production database and cleans only its isolated schema. |

## Accepted residual risks (initial)

- A database administrator with full write access can rewrite records and
  recompute an unanchored audit hash chain. Hash chaining is tamper-evident
  against partial edits, not independently immutable.
- Server-mediated file streaming means API availability and bandwidth affect
  downloads. This is an intentional trade-off for immediate grant revocation.
- A compromised API process or its credentials can access data within those
  credentials' privileges. Least privilege, monitoring, and secret rotation
  reduce impact but do not eliminate this trust boundary.
- File type checks cannot prove a file is harmless. Malware scanning and
  isolated preview/rendering may be needed before real-world use.
- Provider outages, account compromise, and backup/restore mistakes remain
  operational risks; backups and restore drills must be configured and tested.

Each planned test becomes meaningful only once its corresponding endpoint or
control exists. No security test has run as of this design milestone.
