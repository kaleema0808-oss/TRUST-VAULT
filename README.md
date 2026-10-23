# TrustVault

TrustVault is a private document-sharing application for the Snovasys Fresher
Hiring Challenge 2026. It is being built in milestones, prioritizing access
control and explainable security decisions over feature count.

## Current milestone

- [x] Workspace inspection and architecture recommendation
- [x] React/Vite and Express/TypeScript project setup
- [x] MySQL connection configuration and initial versioned schema migration
- [x] Authentication foundation: password hashes, database-backed sessions,
  logout, expiry, CSRF token and role middleware
- [x] API health checks and isolated-auth tests
- [ ] Configure and run isolated MySQL integration tests
- [ ] Add document endpoints only alongside authorization tests
- [ ] Private object storage, permission management and audit hash chain
- [ ] Deployment and live security verification

The database integration test was skipped in this environment because no
isolated MySQL test database was configured. No document endpoints, file
storage, audit-chain implementation, or deployment is claimed complete.

## Architecture

| Layer | Choice |
| --- | --- |
| Frontend | React + TypeScript + Vite |
| API | Node.js + Express + TypeScript |
| Validation | Zod |
| Database | MySQL via `mysql2/promise`, prepared statements and SQL migrations |
| Tests | Vitest + Supertest; optional MySQL integration test uses a separately named test schema |

The browser calls the API over HTTPS. The server derives the current account,
role and session from a random HttpOnly cookie and server-side MySQL rows; it
does not trust browser-provided role, owner, or permission fields. Mutating
requests require the configured frontend `Origin`, and authenticated mutations
also require an `X-CSRF-Token` matching the token hash stored for that session.
Local Vite requests use a same-origin development proxy. Production hosting
must provide a same-site reverse proxy/custom-domain setup for cookie-based
sessions; cross-site third-party cookies are not assumed to work.

Password values are never stored as plaintext. The application stores a
salted scrypt hash. Session cookies contain an opaque random token, while
MySQL stores only its SHA-256 hash and an expiry time. A password verification
is performed for unknown login accounts too, reducing account-enumeration
timing differences.

## MySQL schema in beginner-friendly terms

The migration in
[`apps/api/src/db/migrations/001_initial_schema.sql`](./apps/api/src/db/migrations/001_initial_schema.sql)
creates these InnoDB tables:

- **`users`**: one account per row. `id` is its primary key (unique row
  identity); `email` has a unique constraint so two accounts cannot use the
  same address. `role` is restricted to `admin`, `owner`, or `viewer`.
  `password_hash` stores a derived password hash, never the password.
- **`sessions`**: one server-managed login per row. `token_hash` is the primary
  key; `user_id` is a foreign key to `users.id`, which prevents a session from
  referring to a nonexistent account. Indexes on `user_id` and `expires_at`
  make a user's sessions and expired rows efficient to locate. The raw cookie
  token is not stored.
- **`documents`**: metadata for a future private file. `owner_id` is a foreign
  key to `users.id`. `object_key` uniquely identifies the future private
  storage object; it is not a public URL. Owner/date and category/date indexes
  will support later authorized searches. File bytes are not in this table.
- **`document_permissions`**: a grant for one named user on one document.
  Foreign keys point to the document, grantee, and account that issued it. A
  unique `(document_id, user_id)` key prevents duplicate grant rows, and a
  check constraint prevents edit permission without read permission. MySQL
  enforces these constraints even if an application bug attempts an invalid
  insert.
- **`audit_events`**: the future application audit stream. It references its
  actor and optionally a document, and indexes actor/document/time for later
  dashboard queries. The hash columns are reserved for a later implementation;
  the chain is not implemented in this milestone.

A **primary key** gives each row its stable identity. A **foreign key** makes
relationships real database rules, not just assumptions in code. A **unique
constraint** prevents duplicate identities/grants. An **index** is an
additional lookup structure that speeds selected queries at the cost of extra
storage and slower writes. A **join** lets the application query a permission
row together with its user/document; no document permission or document
endpoints exist yet. A **transaction** groups related writes so they succeed
or roll back together; the later permission-change plus audit write will need
one. This milestone's seed writes are not presented as that feature.

## Prerequisites

- Node.js 22+ and npm
- MySQL 8.0.16+ (for enforced `CHECK` constraints)
- Git

Never point tests at production. Use separate least-privilege local application
and test database accounts in a real deployment.

## Local setup (Windows PowerShell)

From a clean clone, run:

```powershell
npm ci
Copy-Item .env.example .env
```

Create a local database and a restricted application user from your MySQL
administrative client. Replace the local password with your own value; this
example is for a disposable local developer database only:

```sql
CREATE DATABASE trustvault CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci;
CREATE USER 'trustvault_app'@'localhost' IDENTIFIED BY 'replace-with-a-unique-local-password';
GRANT SELECT, INSERT, UPDATE, DELETE, CREATE, ALTER, INDEX, REFERENCES
  ON trustvault.* TO 'trustvault_app'@'localhost';
```

Edit `.env` to set `DATABASE_PASSWORD` to the password used for the local
database account. Do not add `.env` to Git. Then:

```powershell
npm run db:migrate
```

The migration runner applies numbered `.sql` files once and records their
filenames in `schema_migrations`. Set three different development-only
passwords (at least 12 characters) in the current PowerShell session and seed:

```powershell
$env:DEV_ADMIN_PASSWORD = Read-Host "Local demo admin password"
$env:DEV_OWNER_PASSWORD = Read-Host "Local demo owner password"
$env:DEV_VIEWER_PASSWORD = Read-Host "Local demo viewer password"
npm run seed:dev
```

Seeded development emails are `admin@trustvault.local`,
`owner@trustvault.local`, and `viewer@trustvault.local`. The script refuses
production mode, requires strong nonempty environment-supplied passwords,
hashes them, and does not print or commit them.

Start the app and run checks:

```powershell
npm run dev
npm run test
npm run typecheck
npm run build
npm audit
```

The Vite site runs at `http://localhost:5173`; the API listens on
`http://localhost:3001`. `GET /health/live` is a database-independent liveness
check. `GET /health/ready` runs only `SELECT 1` and returns a generic
unavailable response if MySQL cannot be reached; it does not expose SQL
details.

### Optional MySQL constraint test

Use a separate disposable schema whose name begins `trustvault_test_`; never
use the application or production database. Create it and grant the test
account access in local MySQL:

```sql
CREATE DATABASE trustvault_test_local CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci;
GRANT SELECT, INSERT, UPDATE, DELETE, CREATE, ALTER, INDEX, REFERENCES
  ON trustvault_test_local.* TO 'trustvault_app'@'localhost';
```

Apply the migration to that isolated schema and run tests:

```powershell
$env:DATABASE_NAME = "trustvault_test_local"
npm run db:migrate
$env:MYSQL_TEST_DATABASE = "trustvault_test_local"
npm run test
Remove-Item Env:DATABASE_NAME
Remove-Item Env:MYSQL_TEST_DATABASE
```

The optional integration test refuses database names outside the test prefix.
If the variable is absent, Vitest reports the constraint test as skipped; that
is not a passing database-constraint verification.

## API endpoints implemented so far

| Method and path | Access | Behavior |
| --- | --- | --- |
| `GET /health/live` | Public | Liveness only |
| `GET /health/ready` | Public | Safe `SELECT 1` readiness check |
| `POST /api/auth/login` | Public, same configured `Origin` required | Validates credentials; returns generic credential failure |
| `GET /api/auth/me` | Authenticated session | Returns server-derived account identity and role |
| `GET /api/auth/csrf` | Authenticated session | Rotates and returns that session's CSRF token |
| `POST /api/auth/logout` | Authenticated session + valid CSRF token + configured `Origin` | Deletes current session and clears cookie |
| `GET /api/admin/check` | Authenticated `admin` role | Small role-middleware check; returns 403 to other roles |

All listed routes are backed by the API; there are no document/download
endpoints yet. This is an implementation inventory, not a claim that the whole
application is secure.

## Security and deployment caveats

Production startup requires a nonempty database password, `DATABASE_TLS=true`,
and an HTTPS `APP_ORIGIN`. Use real provider TLS certificates and validate the
selected provider's networking/allow-list settings when deploying. No
credentials are in the frontend. No provider account, database, bucket or
application has been deployed by this milestone.

The architecture recommendation and provider checks are recorded above in
milestone history; hosting costs and availability must be rechecked before
provisioning. See [`THREATS.md`](./THREATS.md) for planned controls, tests and
residual risks and [`PROMPTS.md`](./PROMPTS.md) for the actual AI-use log.

## Interview summary

The database models users as the parent records for sessions, ownership and
grants. A foreign key prevents orphaned relationships; unique keys prevent
duplicate emails or grants; indexes make permission lookups efficient.
Authentication uses random opaque server-side sessions, scrypt password
hashes, expiry and CSRF defenses. The upcoming document handlers must still
authorize every request against current owner/grant records before any
metadata or file bytes are returned.
