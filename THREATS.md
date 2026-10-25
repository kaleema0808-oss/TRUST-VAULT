# TrustVault threat model

Threat register updated 2026-10-25. The API now includes full file upload and
authorized download routes, local disk storage abstraction with random UUID
object isolation, magic-byte binary validation, strict MIME allowlisting,
double-submit CSRF enforcement on file uploads, immediate revocation on
downloads, and the secure Admin approval workflow for Owner access with
demotion protection, duplicate request prevention, unauthorized approval defense,
and comprehensive automated test coverage in `upload-download.test.ts` and `role-approval.test.ts`.

| # | Threat | Current mitigation/status | Verification or remaining test |
| --- | --- | --- | --- |
| 1 | User guesses another document ID (IDOR) | Parameterized MySQL queries filter reads by current server session, owner, or explicit read grant; inaccessible IDs return generic 404. | In-memory Supertest verifies cross-owner ID access and denied-read auditing. |
| 2 | Viewer attempts to edit metadata | Global viewer role is excluded from SQL edit predicate, even if an edit grant exists; owner/admin policy is enforced on server. | Tests verify viewer edit and deletion denied and denied attempts audited. |
| 3 | Revoked user reuses stale access | Each request resolves the current DB session and each document query reads current permission rows; no signed URLs or persistent bearer grants are issued. | Tests verify immediate revocation blocks both metadata read and binary file download synchronously. |
| 4 | Client forges admin role or owner ID | Role/identity come from joined server-side session records; create schema rejects extra `role`/`ownerId` fields. | Tests confirm forged fields are rejected. |
| 5 | Search leaks restricted document names or owners | Collection query returns only rows satisfying current read authorization. | Tests confirm a viewer's collection omits another user's document. |
| 6 | Unauthorized download/preview | Implemented in `GET /api/documents/:id/download`. Verifies read permissions before streaming. Audits allowed and denied attempts. Never exposes raw disk paths. | Automated tests in `upload-download.test.ts` verify owner allowed, viewer denied, revoked user denied, non-existent doc 404. |
| 7 | Malicious or oversized upload | Implemented in `POST /api/documents/:id/upload`. Enforces 10 MiB limit via multer, strict MIME allowlist, and server-side magic-byte content validation (`validateFileBuffer`). Orphan files cleaned up on error. | Automated tests verify 400 on disallowed MIME types, 415 on magic-byte mismatch, 413 on oversized uploads. |
| 8 | Path traversal or object-key manipulation | Storage object keys are generated as cryptographically secure random UUIDs (`newObjectKey()`), never user-supplied filenames. `path.basename` asserted. | Tests verify that object keys are opaque UUIDs and user filenames only populate Content-Disposition headers. |
| 9 | Public exposure of stored files | Storage directory is located outside web root and never served statically; bytes stream only through authenticated, authorized Express handlers. | Direct static access is impossible; tests verify download requires active session cookie. |
| 10 | SQL injection through search or metadata | Zod-validate inputs and use parameterized `mysql2` queries; allow-list sort fields. | Injection-shaped inputs are treated as data or rejected. |
| 11 | Session theft or fixation | Use opaque server-side sessions, rotate on login/privilege change, and set Secure/HttpOnly/SameSite cookies with bounded lifetime. | Cookie attributes and session rotation/expiry are verified. |
| 12 | Cross-site request forgery | Use SameSite cookies plus a double-submit CSRF token and origin validation on all state-changing requests, including multipart file uploads. | Automated tests verify upload without `X-CSRF-Token` is rejected with 403 Forbidden. |
| 13 | Brute-force login or API abuse | Apply rate limits to authentication and sensitive endpoints; return generic login failures. | Repeated requests hit configured limit without account enumeration. |
| 14 | Permission change without matching audit record | MySQL grant/revoke operations and corresponding audit inserts share one transaction. | In-memory tests verify grant/revoke audit records. |
| 15 | Audit record altered or removed | Application audit inserts link events using SHA-256 previous/event hashes; verifier checks order and content. | Automated tests verify hash calculation and tamper detection. |
| 16 | Privileged database operator rewrites whole audit chain | Documented limitation; hash chaining is tamper-evident against partial modifications, but unanchored against root DB admin recomputation. | Documented in accepted residual risks. |
| 17 | Sensitive document metadata exposed in errors/logs | Generic external error messages; redact filenames, tokens, cookies, and SQL errors from client responses. | Denied responses do not disclose document metadata or internal paths. |
| 18 | Stolen database/storage credentials | Least-privilege accounts, mandatory production TLS (`DATABASE_TLS=true`), secret environment variables. | Configuration checks fail closed when required production secrets or TLS are missing. |
| 19 | Destructive admin or owner deletion request | Require authorization, delete metadata and disk file, and audit the operation; orphan prevention on failures. | Tests verify authorized deletion removes metadata and cleans up disk files. |
| 20 | Production data contaminates automated tests | In-memory mock repositories and isolated test databases with synthetic fixtures; test bootstrap rejects production configs. | All automated tests run isolated in memory or on dedicated test schemas. |
| 21 | Privilege escalation via client-supplied role parameter | Registration schema strictly validates request body with Zod `.strict()`, rejecting untrusted `role` fields; server assigns `viewer` role unconditionally on registration. | Automated tests in `role-approval.test.ts` verify client-supplied `role: "admin"` is rejected with 400. |
| 22 | Pending user accesses Owner functionality before approval | Users requesting Owner access remain `viewer` in the database while pending; server rejects document creation and file uploads with 403 Forbidden and audits the denial. | Automated tests in `role-approval.test.ts` verify pending access denial and audit event creation. |
| 23 | Unauthorized approval or rejection by non-admin | Approval/rejection routes enforce `requireRole("admin")` and double-submit CSRF; unauthorized attempts from viewers or owners are rejected with 403 and audited with actor ID and denied outcome. | Automated tests in `role-approval.test.ts` verify viewer/owner approval attempts are rejected with 403 and logged in audit log. |
| 24 | Duplicate role requests flood or bypass review queue | Database queries check for active `pending` requests with row-level locks (`FOR UPDATE`); subsequent requests while one is pending return 409 Conflict and log a denied audit event. | Automated tests in `role-approval.test.ts` verify second request returns 409 and logs denied audit record. |
| 25 | Privilege manipulation demoting existing Admin account | Role request approval transaction asserts target user's current role is not `admin`; refuses to alter an administrator's role and fails closed. | Automated tests in `role-approval.test.ts` verify approval targeting admin fails and preserves admin role. |

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
