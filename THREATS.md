# TrustVault threat model

Threat register updated 2026-10-23. The API now has MySQL-backed document
metadata and permission repository code plus in-memory route tests. The local
MySQL login is not configured, so database queries, transactions, migrations,
and relational behavior have not been exercised against MySQL. There are no
file upload/download/preview routes or private storage integration.

| # | Threat | Current mitigation/status | Verification or remaining test |
| --- | --- | --- | --- |
| 1 | User guesses another document ID (IDOR) | Parameterized MySQL queries filter reads by current server session, owner, or explicit read grant; inaccessible IDs return generic 404. | In-memory Supertest verifies cross-owner ID access and denied-read auditing. MySQL repository still needs integration verification. |
| 2 | Viewer attempts to edit metadata | Global viewer role is excluded from SQL edit predicate, even if an edit grant exists; owner/admin policy is enforced on server. | Tests verify viewer edit and deletion denied and denied attempts audited. |
| 3 | Revoked user reuses stale access | Each request resolves the current DB session and each document query reads current permission rows; no signed URLs are issued. | Test verifies next read fails after grant revocation. No downloads exist yet. |
| 4 | Client forges admin role or owner ID | Role/identity come from joined server-side session records; create schema rejects extra `role`/`ownerId` fields. | Test confirms forged fields are rejected. Production database-backed auth still needs integration verification. |
| 5 | Search leaks restricted document names or owners | Collection query returns only rows satisfying current read authorization. | Test confirms a viewer's collection omits another user's document; production SQL untested. |
| 6 | Unauthorized download/preview | No file or download endpoints are implemented until private storage and streaming checks are ready. | No file bytes are currently served. Add endpoint-specific tests before implementing storage routes. |
| 7 | Malicious or oversized upload | Enforce size limits, allow-listed content types, signature/content checks, and safe streaming; consider malware scanning. | Invalid signatures, disallowed types, and over-limit files are rejected. |
| 8 | Path traversal or object-key manipulation | Generate opaque object keys on the server; never concatenate user filenames into filesystem paths or keys. | Traversal strings and crafted identifiers cannot read/write another object. |
| 9 | Public exposure of stored files | Keep the B2 bucket private; serve bytes only through authorized API routes. | Configuration/integration test verifies no public object access path is emitted. |
| 10 | SQL injection through search or metadata | Zod-validate inputs and use parameterized `mysql2` queries; allow-list sort fields. | Injection-shaped inputs are treated as data or rejected. |
| 11 | Session theft or fixation | Use opaque server-side sessions, rotate on login/privilege change, and set Secure/HttpOnly/SameSite cookies with bounded lifetime. | Cookie attributes and session rotation/expiry are verified. |
| 12 | Cross-site request forgery | Use SameSite cookies plus a CSRF token/origin check for state-changing requests. | Cross-origin state changes without valid CSRF proof are denied. |
| 13 | Brute-force login or API abuse | Apply rate limits to authentication and sensitive endpoints; return generic login failures. | Repeated requests hit the configured limit without account enumeration. |
| 14 | Permission change without matching audit record | MySQL grant/revoke operations and corresponding audit inserts share one transaction. | In-memory tests verify grant/revoke audit records. Add MySQL failure-injection transaction test when a DB is available. |
| 15 | Audit record altered or removed | Application audit inserts link events using SHA-256 previous/event hashes; pure verifier checks order and content. No update/delete audit API exists. | Test changes an event after hashing and confirms chain verification fails. MySQL persistence path remains unverified. |
| 16 | Privileged database operator rewrites whole audit chain | Document limitation; consider externally anchored hashes or independent immutable storage for a stronger boundary. | A recomputed whole chain cannot be detected by this local verifier alone; no external anchoring exists. |
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

Automated route tests currently use an in-memory repository, not MySQL. The
single MySQL integration test remains skipped until an explicitly isolated
test schema is configured. Passing route tests do not prove production
database security.
