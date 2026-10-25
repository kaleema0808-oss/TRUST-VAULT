# AI-use log

Entries are dated when the work actually occurred. This log is a record of
real use, not a retrospective prompt archive. Commit references will be added
only after actual commits exist.

## 2026-10-23

- **Prompt/task:** Inspect the TrustVault workspace, recommend a deployment-
  compatible secure architecture, explain data flow and major threats, verify
  provider compatibility/pricing, and implement only the first manageable
  milestone.
- **Use:** AI inspected the empty workspace and fetched current provider
  documentation, then drafted the initial architecture and threat model.
- **Human review / correction:** The workspace had no files or Git repository,
  so no existing code could be assessed and no commit history existed. The
  DigitalOcean pricing page did not expose a verifiable current cluster quote;
  the recommendation was left conditional rather than inventing a price or
  claiming managed MySQL is free. No code, tests, deployment, or security
  guarantee was claimed.
- **Commit:** None; no commit has been created.

## 2026-10-23 — Milestone 2 and repository connection

- **Prompt/task:** Build the React/TypeScript/Vite and Express/TypeScript
  foundations, MySQL schema and migrations, authentication/session/CSRF
  foundation, safe health checks, and tests; then connect this local project
  to the user's existing GitHub repository without replacing remote history.
- **Use:** AI added the initial workspace, migration, authentication routes and
  middleware, tests, local setup documentation, and repository integration
  steps. The existing GitHub repository was inspected before any transfer; it
  was empty, configured for `main`, and had no remote files or commits.
- **Actual problems discovered and fixes made:**
  - Initial type-checking found that Node's `scrypt` callback overload did not
    accept the promisified options used. Replaced it with a typed Promise
    wrapper.
  - The first authentication test run exposed OpenSSL's default scrypt memory
    cap as too small for the selected work factor. Set a bounded 128 MiB
    `maxmem`; the targeted API tests then passed.
  - The first npm audit found a moderate and two critical advisories in the
    initial Vitest dependency tree. Upgraded Vitest to 5.0.5 and regenerated
    the lockfile; the subsequent full npm audit reported zero vulnerabilities.
  - Review identified a username timing difference on unknown login accounts.
    Added a cached dummy scrypt hash so an unknown account follows a password
    verification path too.
- **Verification:** `npm run test -w @trustvault/api` reported 5 passed and 1
  skipped (the isolated MySQL constraint test; no test database was configured).
  `npm run typecheck` passed, `npm run build` passed, and `npm audit` reported
  zero vulnerabilities. These are local results, not production verification.
- **Commit:** The implementation was later pushed to the existing GitHub
  repository. Its current history is recorded by commits
  `65311266c6a32c64dda526dd29697f306e57c1db` and
  `7594d673e45ae1ef575e796000faacf22f34a45c`.

## 2026-10-23 — Local foundation workspace

- **Prompt/task:** Inspect the existing TrustVault files, preserve existing
  work, organize the frontend and backend as `client/` and `server/`, verify
  the database and test setup, and update beginner-friendly setup guidance.
- **Use:** AI reviewed the existing README, threat model, prompt log, npm
  workspaces, migration, API, frontend and tests before changing anything.
  The existing `apps/web` and `apps/api` directories were moved intact to
  `client/` and `server/`; no files were deleted. Workspace names/scripts,
  docs, lockfile, basic error handling and focused health/validation tests
  were updated.
- **Actual problems discovered and fixes made:**
  - The working directory is not a Git repository despite the GitHub project
    existing. Git status/root checks failed; no repository, commits or remotes
    were created or changed.
  - The Windows `MySQL267` service is running, but the `mysql` CLI was not on
    `PATH`; the example credentials failed a safe `SELECT 1` connection
    attempt with `ER_ACCESS_DENIED_ERROR`. No database connection or migration
    is claimed. The README now explains how to configure a local database
    account and verify readiness.
  - After moving the API folder, its `.env` resolver would have looked outside
    the project root. Corrected the path and verified the API loads without an
    `.env` file for liveness testing.
  - The first liveness smoke attempt exposed that development configuration
    rejected an empty DB password before the API could start. Allowed the
    development default while preserving the explicit nonempty-password
    requirement in production.
  - Malformed JSON requests previously fell through to a generic server error.
    They now receive a generic `400` response; oversized bodies receive `413`.
- **Verification:** `npm test` reported 8 passed and 1 skipped (MySQL
  integration test; no isolated test schema configured). `npm run typecheck`
  and `npm run build` passed. `npm audit` reported zero vulnerabilities. Live
  HTTP smoke test returned `GET /health/live` 200 and `GET /health/ready` 503,
  consistent with the failed MySQL authentication. No migration, deployment,
  commit or push was performed.
- **Commit:** None, as requested.

## 2026-10-23 — Database setup verification

- **Prompt/task:** Inspect the existing MySQL configuration, verify only the
  currently configured credentials using a read-only connection, inspect the
  migration before application, run the existing checks, and accurately
  document database/Git status.
- **Use:** AI inspected the root README and `.env.example`, server config and
  env loader, pool, migration runner and SQL, and the MySQL integration test.
  AI attempted only `SELECT 1`; it did not create or change MySQL users or
  databases, apply migrations, delete data, or alter Git history.
- **Actual observations:** Windows reports `MySQL267` running, but the MySQL
  CLI is not on PATH and the root `.env` does not exist. The app therefore
  tried host `127.0.0.1`, port `3306`, database `trustvault`, user
  `trustvault_app`, with `DATABASE_PASSWORD` unset; authentication failed
  with `ER_ACCESS_DENIED_ERROR`. The example password is a placeholder and was
  not used as an actual credential. No migration was applied. The migration
  SQL was inspected and contains only table-creation statements for the five
  requested tables.
- **Verification:** `npm test` reported 8 passed, 1 skipped (no isolated
  `MYSQL_TEST_DATABASE`). `npm run typecheck` and `npm run build` passed;
  `npm audit` reported zero vulnerabilities. Git status, remote and repository
  root checks failed because this workspace folder has no `.git`; no history
  or remotes were changed.
- **Documentation update:** README now lists exact connection settings,
  explains the authentication failure and provides read-only existence checks
  plus safe Workbench steps. Database/user creation and migration remain
  pending explicit target confirmation and valid local credentials.
- **Commit:** None; no commit or push was performed.

## 2026-10-24 — File upload/download authorization, audit trail, and security hardening

- **Prompt/task:** Implement real file upload and authorized download with
  tamper-resistant audit trail, magic-byte file signature validation, CSRF
  protection, immediate revocation enforcement, and comprehensive authorization
  tests for the Snovasys Fresher Hiring Challenge 2026.
- **Use:** AI designed and implemented:
  - Disk storage backend (`server/src/storage/local.ts`) with strict MIME
    allowlisting (PDF, JPEG, PNG, GIF, WebP, plain text, Word, Excel) and
    content inspection against magic byte signatures.
  - Secure file endpoints: `POST /api/documents/:id/upload` (multipart/form-data
    with CSRF validation, magic-byte inspection, orphan cleanup) and
    `GET /api/documents/:id/download` (permission-gated streaming with safe
    Content-Disposition).
  - Database schema migration (`003_add_file_metadata.sql`) adding
    `original_name`, `mime_type`, and `file_size` columns.
  - Complete audit recording: successful uploads (`document.upload`) and downloads
    (`document.download`), as well as denied attempts (`document.upload.denied`,
    `document.download.denied`).
  - Frontend integration in `client/src/main.tsx` and `client/src/api.ts` with
    attach/replace file and download buttons.
  - Production database TLS resilience: added `DATABASE_TLS_CA` and
    `DATABASE_TLS_REJECT_UNAUTHORIZED` options in `config.ts`, `pool.ts`, and
    `migrate.ts`.
- **Actual problems discovered and fixes made:**
  - Client-supplied `Content-Type` headers can easily be forged. Added server-side
    magic-byte validation in `local.ts` (`validateFileBuffer`) that verifies the
    first bytes of uploaded buffers match expected signatures (e.g. `%PDF-` for PDF,
    `FF D8 FF` for JPEG, `89 50 4E 47` for PNG), rejecting spoofed uploads with 415.
  - Path traversal risk on download/upload: neutralized by generating random UUIDs
    for on-disk object keys (`newObjectKey()`), never storing files under
    user-supplied names, and asserting `path.basename(key) === key`.
  - Immediate revocation: permission checks are executed within transactional
    database queries (`FOR UPDATE` locking on document mutations), guaranteeing
    that any permission revocation immediately cuts off download access.
  - Render cloud database TLS: managed MySQL providers require TLS with specific CA
    trust bundles. Added support for CA certificate overrides and TLS verification
    flags.
- **Verification:**
  - `npm run test` reports 29 passed, 1 skipped across `auth.test.ts`,
    `upload-download.test.ts`, and `documents.test.ts`.
  - `npm run typecheck` passed cleanly across both workspace packages.
  - `npm run build` compiled both server and client to `dist/` with zero errors.
  - Local database migration `003_add_file_metadata.sql` was applied successfully.
- **Commit:** `c541e26e2158e7dc5aa5ca4eae16e01665791445`.

## 2026-10-24 — Production login HTTP 500 debugging, startup migrations, and account provisioning

- **Prompt/task:** Debug and fix the production login HTTP 500 error on Render
  connected to Aiven MySQL. Preserve existing code, verify database migration status,
  sanitize error logging without credential leakage, support production account
  provisioning, ensure cross-site session cookie compatibility, and update tests.
- **Use:** AI investigated production endpoints, Git history, and server code:
  - Discovered that `GET /health/ready` succeeded via `SELECT 1`, but any login
    attempt (including non-existent users) returned HTTP 500 because migrations
    were never executed against the production Aiven MySQL database, leaving the
    `users` table absent.
  - Discovered that TypeScript (`tsc`) did not copy `src/db/migrations` into `dist/`,
    causing `node dist/db/migrate.js` to fail with `ENOENT`. Updated build script
    to copy migrations and enhanced migration runner with multi-path resolution.
  - Made schema migrations idempotent (`CREATE TABLE IF NOT EXISTS`) and integrated
    safe auto-migration into server startup before listener initialization.
  - Implemented `server/src/db/provision.ts` to provision `admin`, `owner`, and
    `viewer` accounts via environment variables (`ADMIN_PASSWORD` / `DEV_ADMIN_PASSWORD`),
    ensuring scrypt password hashing and role preservation without hardcoded secrets.
  - Sanitized server-side error logging in `app.ts` to redact connection strings,
    tokens, and credentials while logging structured error names, codes, and stacks.
  - Added `X-CSRF-Token` to CORS `Access-Control-Allow-Headers` in `app.ts`.
  - Configured session cookies to `SameSite=None; Secure` in production for cross-site
    requests between Vercel (`vercel.app`) and Render (`onrender.com`).
- **Verification:**
  - `npm test` reports 34 passed, 1 skipped across 5 test suites.
  - `npm run typecheck` passed cleanly across both workspace packages.
  - `npm run build` compiled both server and client with zero errors and copied migrations.
- **Commit:** `309ce52b5756306cbdf2960682245b73fe83307b`.

## 2026-10-25 — Full project audit, security hardening, and production readiness

- **Prompt/task:** Perform comprehensive audit of entire application (auth, authorization,
  file storage, audit trail, migrations, documentation, live deployment), fix identified issues,
  safeguard existing user accounts against automatic password overwrite, ensure safe startup
  failures, document ephemeral storage trade-offs, and produce final submission report.
- **Use:** AI performed systematic review:
  - Validated live production database status: confirmed migrations 001/002/003 are applied,
    and live registration/login works with `SameSite=None; Secure; HttpOnly` cookies.
  - Hardened `provision.ts`: added whitespace and enclosing-quote sanitization (`cleanPassword`),
    prevented automatic overwriting of existing accounts on startup, and restricted password
    rotation to explicit `ROTATE_USER_PASSWORDS=true` opt-in.
  - Hardened `server.ts`: ensured process fails fast and safely with sanitized error logs if
    migrations or provisioning fail during startup, preventing partial or corrupt server boots.
  - Hardened `local.ts`: fixed Windows path resolution with spaces using `fileURLToPath` and
    `path.resolve`, maintaining UUID-based object key isolation and magic-byte validation.
  - Added structured Five-Minute Evaluation & Demo Plan in `WRITEUP.md` Section 6 and updated
    live URLs and deployment caveats in `README.md`.
- **Verification:**
  - `npm run typecheck`: 0 errors.
  - `npm run build`: cleanly compiles client and server, copying migrations.
  - `npm test`: 34 passed, 1 skipped.
- **Commit:** `cf4be54848d7d6b35d7945ca69532585f9e2bceb`.

## 2026-10-25 — Secure Admin approval workflow for Owner access

- **Prompt/task:** Implement a secure Admin approval workflow for Owner access in the existing TrustVault project. Inspect current architecture, auth, registration flow, roles, database migrations, audit logging, tests, and deployment. Requirements: new users can request Owner access through registration or role-request flow; requests remain pending until authenticated Admin approves; pending users must not receive Owner privileges; never trust client-supplied role; Admin-only interface to list, approve, reject requests; record request, approval, rejection, and role-change events in audit trail with actor, target user, timestamp, outcome; prevent duplicate requests, unauthorized approvals, and privilege escalation; existing Admin accounts must not be demoted; add database migration 004 and automated tests; keep existing demo accounts working; update README, API docs, THREATS.md, and PROMPTS.md; run typecheck, build, and tests.
- **Use:** AI performed end-to-end design, implementation, and verification:
  - Inspected Git status (`clean`), database schema, and test suite baseline (34 passed, 1 skipped).
  - Added database migration `server/src/db/migrations/004_add_role_requests.sql` creating InnoDB `role_requests` table with foreign keys to `users(id)` for requester and reviewer, status enum (`pending`, `approved`, `rejected`), and indexes on user status and request status.
  - Implemented `RoleRequestRepository` and `MysqlRoleRequestRepository` in `server/src/auth/repository.ts` with serialized isolation (`FOR UPDATE` row locking), duplicate request checks, admin demotion immunity, and transactional inclusion in the tamper-evident SHA-256 audit hash chain via `appendAuditEventWithConnection`.
  - Updated `POST /api/auth/register` to support optional `requestOwner` and `reason` while strictly validating with Zod `.strict()` to reject client-supplied `role` fields. New accounts are strictly created with `role: "viewer"`.
  - Added authenticated viewer endpoints `POST /api/auth/role-requests` (with duplicate detection returning 409 Conflict) and `GET /api/auth/role-requests/mine`.
  - Added Admin endpoints `GET /api/admin/role-requests`, `POST /api/admin/role-requests/:id/approve`, and `POST /api/admin/role-requests/:id/reject` in `server/src/app.ts` with CSRF validation and automated audit logging of unauthorized non-admin attempts.
  - Extended client API (`client/src/api.ts`), registration UI with Owner request checkbox (`client/src/AuthPage.tsx`), viewer pending notification banner & request action (`client/src/main.tsx`), Admin "Owner requests" review view with pending counter badge, and status badges in `client/src/style.css`.
  - Created automated test suite `server/tests/role-approval.test.ts` covering pending access denial, unforgeable role assignment, duplicate request rejection, unauthorized approval defense, approval workflow, rejection workflow, admin demotion immunity, and cryptographic audit chain verification.
  - Updated `README.md` (milestone, schema, API endpoints table, workflow details), `THREATS.md` (threats 21-25 with mitigations and test references), and `PROMPTS.md`.
- **Verification:**
  - `npm run typecheck`: 0 errors across `@trustvault/server` and `@trustvault/client`.
  - `npm test`: 42 passed, 1 skipped across 6 test suites (8 new tests in `role-approval.test.ts`).
  - `npm run build`: compiled client and server cleanly with migration files copied to `dist/db/migrations`.
- **Commit:** None, pending explicit user approval as instructed.
