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
- **Commit:** Added only after the actual repository commit is created and
  verified.
