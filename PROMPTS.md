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

## 2026-10-24 — Remote clone validation and dependency correction

- **Prompt/task:** Inspect the existing clone and feature branch, review the
  staged snapshot for secrets and unrelated files, run the project checks, and
  publish verified milestone work without rewriting history or touching
  MySQL.
- **Use:** AI fetched the existing remote refs and confirmed that the staged
  application snapshot exactly matched remote `main` at
  `fd6ca82ba57cdd427241a5a5df2ddead7d1f580f`. The local feature branch was
  safely fast-forwarded to that commit; the already-published app changes
  were not duplicated. `.env`, environment-specific files, private keys and
  upload/storage paths are ignored; no such files or credentials were staged.
- **Actual problems discovered and fixes made:**
  - The clone had no `node_modules`, so the first test, typecheck and build
    attempts could not find Vitest or TypeScript. `npm ci` restored exactly the
    lockfile dependencies.
  - `npm audit` then identified high-severity advisory
    GHSA-mrhx-c7xc-m3w5 in Zod 3.25.76. A targeted update to Zod 4.6.7 was
    compatible with the current code and cleared the advisory; no broad
    `npm audit fix --force` was used.
- **Verification:** After the targeted update, `npm test` reported 15 passed
  and 1 skipped (the isolated MySQL integration test), `npm run typecheck`
  passed, `npm run build` passed, and `npm audit` reported zero
  vulnerabilities. The MySQL integration test remains skipped because no
  isolated test database/credentials are configured; no connection check or
  migration was run.
- **Commit:** The dependency correction and this entry are committed on
  `trustvault-local-work` in commit
  `514cff002ddc38baefb28c0889a7a7cc4e484055`.
