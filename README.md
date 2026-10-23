# TrustVault — Milestone 1: Working Local Foundation

TrustVault is a private document-sharing application for the Snovasys Fresher
Hiring Challenge 2026. It is being built in milestones, prioritizing access
control and explainable security decisions over feature count.

## Milestone 1 status

- [x] Workspace inspection and architecture recommendation
- [x] React/Vite and Express/TypeScript project setup
- [x] MySQL connection-pool configuration and initial versioned schema migration file
- [x] Authentication foundation: password hashes, database-backed sessions,
  logout, expiry, CSRF token and role middleware
- [x] API health checks and isolated-auth tests
- [ ] Configure and run isolated MySQL integration tests
- [x] Add metadata endpoints with server-side owner/grant authorization and route tests
- [x] Add transaction-bound permission audit records and hash-chain verification helper
- [ ] Verify MySQL repository queries and transaction rollback against an isolated MySQL database
- [ ] Add private file storage and authorized download/preview routes
- [ ] Private object storage, permission management and audit hash chain
- [ ] Deployment and live security verification

Document metadata and permission routes now exist with server-side access
checks, immediate permission re-evaluation, denied-attempt auditing, and a
hash-chain verification helper. Route tests use an in-memory repository, so
they do not prove MySQL execution or persistence. The Windows MySQL service is
running, but no root `.env` exists and `SELECT 1` failed with
`ER_ACCESS_DENIED_ERROR`; no migration has been applied. Route security tests
and local compilation pass, but the MySQL-specific integration test remains
skipped until a dedicated test schema and valid credentials are configured.
File storage, download/preview routes, live database verification, and
deployment remain unfinished.

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
[`server/src/db/migrations/001_initial_schema.sql`](./server/src/db/migrations/001_initial_schema.sql)
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
row together with its user/document. A **transaction** groups related
permission and audit writes so they succeed or roll back together. Although
these repository queries are implemented, the MySQL migration and transactions
have not been run against a configured database yet.

## Prerequisites

- Node.js 22+ and npm
- MySQL 8.0.16+ (for enforced `CHECK` constraints)
- Git

Never point tests at production. Use separate least-privilege local application
and test database accounts in a real deployment.

### MySQL status on the inspected machine

The Windows service `MySQL267` is running, but the `mysql` command-line client
was not found on `PATH`. No root `.env` file exists. The app therefore used
these defaults for the safe connection test:

| Setting | Expected value |
| --- | --- |
| Host | `127.0.0.1` |
| Port | `3306` |
| Database | `trustvault` |
| Username | `trustvault_app` |
| Password | `DATABASE_PASSWORD` (unset; application default is empty) |
| TLS | `DATABASE_TLS=false` for local development |

The `.env.example` value `replace-with-a-local-password` is only a placeholder;
it is not a valid password or an existing credential. `SELECT 1` failed with
`ER_ACCESS_DENIED_ERROR`, so MySQL is running but TrustVault has **not**
authenticated or connected to its database. No schema or migration has been
applied. Do not treat the MySQL integration test as passing while it is skipped.

### Safe local database setup

These instructions require an administrator login in MySQL Workbench (or the
MySQL command-line client). Do not paste an administrator password into this
chat or commit it. Before creating anything, check whether the `trustvault`
database and `trustvault_app`@`127.0.0.1` account already exist. Do not drop,
rename, or overwrite an existing database or account. If either already exists
and you do not know its purpose, stop and ask before changing it.

In Workbench, connect to your local MySQL server with your administrator
account, open a SQL tab, and run these **read-only checks** first:

```sql
SELECT SCHEMA_NAME
FROM INFORMATION_SCHEMA.SCHEMATA
WHERE SCHEMA_NAME = 'trustvault';

SELECT User, Host
FROM mysql.user
WHERE User = 'trustvault_app' AND Host = '127.0.0.1';
```

If both checks show no matching rows and you approve creating a fresh local
TrustVault database/account, run the following in Workbench. Replace the
example password with a unique local development password there; do not reuse
your Windows or GitHub password:

```sql
CREATE DATABASE trustvault CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci;
CREATE USER 'trustvault_app'@'127.0.0.1' IDENTIFIED BY 'replace-with-a-unique-local-password';
GRANT SELECT, INSERT, UPDATE, DELETE, CREATE, ALTER, INDEX, REFERENCES
  ON trustvault.* TO 'trustvault_app'@'127.0.0.1';
```

The application host is `127.0.0.1`, so the user is restricted to that local
TCP host rather than `%` (any host). The privilege grant is limited to this
database. `CREATE`, `ALTER`, `INDEX`, and `REFERENCES` support the migration
runner; runtime access should later be split from migration privileges.

In the project root, copy `.env.example` to `.env` if it does not exist. Set
`DATABASE_PASSWORD` in `.env` to the local app-user password you just chose;
do not print it, commit it, or send it in chat. Confirm
`DATABASE_HOST=127.0.0.1`, `DATABASE_PORT=3306`,
`DATABASE_NAME=trustvault`, `DATABASE_USER=trustvault_app`, and
`DATABASE_TLS=false`.

The migration command is `npm run db:migrate` (root script delegates to
`npm run db:migrate -w @trustvault/server`, which runs `tsx src/db/migrate.ts`).
It creates `schema_migrations` and applies numbered SQL files not already
recorded. The currently inspected
[`001_initial_schema.sql`](./server/src/db/migrations/001_initial_schema.sql)
contains only `CREATE TABLE` statements for `users`, `sessions`, `documents`,
`document_permissions`, and `audit_events`, with keys and constraints; it
contains no `DROP`, `DELETE`, or `ALTER` of existing application data. I have
not run it because the configured account could not authenticate and no
dedicated target is currently confirmed.

After the dedicated account is configured, run `npm run db:migrate`, then
check `http://localhost:3001/health/ready`; a `200` with
`{"status":"ok","database":"connected"}` verifies the connection. The isolated
integration-test schema is separate and must be created explicitly before
running the optional database test.

## Local setup (Windows PowerShell)

From the project root in a clean clone, run:

```powershell
npm ci
```

Follow [Safe local database setup](#safe-local-database-setup) above to inspect
the target and create a dedicated local database/account only if it does not
already exist. Copy `.env.example` to `.env` if needed, then set the matching
local app-account password in `.env`. Never commit or share `.env`. Commands
load it from the project root, including when run from the server workspace.
After confirming the dedicated target:

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

Start the app in one PowerShell terminal:

```powershell
npm run dev
```

Run checks in another terminal from the project root:

```powershell
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

If you want to start just one side while learning, use a separate terminal:

```powershell
npm run dev -w @trustvault/client
npm run dev -w @trustvault/server
```

### Optional MySQL constraint test

Use a separate disposable schema whose name begins `trustvault_test_`; never
use the application or production database. Create it and grant the test
account access in local MySQL:

```sql
CREATE DATABASE trustvault_test_local CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci;
GRANT SELECT, INSERT, UPDATE, DELETE, CREATE, ALTER, INDEX, REFERENCES
  ON trustvault_test_local.* TO 'trustvault_app'@'127.0.0.1';
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

The optional integration test loads settings from the root `.env` and refuses
database names outside the test prefix.
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
| `GET /api/documents` | Authenticated user | Lists documents readable by this user; collection access is audited |
| `POST /api/documents` | `admin` or `owner`, valid CSRF token | Creates metadata owned by the authenticated account; client owner/role fields are rejected |
| `GET /api/documents/:documentId` | Authenticated owner, admin, or user with current read grant | Returns authorized metadata only; inaccessible IDs return generic 404 and are audited |
| `PATCH /api/documents/:documentId` | `admin`, owning `owner`, or `owner` with explicit edit grant; valid CSRF token | Edits metadata and audits in one DB transaction |
| `DELETE /api/documents/:documentId` | Same edit access as metadata edit; valid CSRF token | Deletes metadata and audits in one DB transaction |
| `PUT /api/documents/:documentId/permissions/:userId` | `admin`, owning `owner`, or `owner` with explicit edit grant; valid CSRF token | Creates/updates a named user's read/edit grant and audits transactionally |
| `DELETE /api/documents/:documentId/permissions/:userId` | Same permission-management access; valid CSRF token | Revokes grant; next request uses current DB state and is denied |

The global `viewer` role is read-only even if someone submits an edit grant.
Only an `owner` may use a separate explicit edit grant on a document they do
not own; `admin` can manage all records. Every request checks current
session/grant state in the repository; permission revocation therefore affects
the next API request. A normal inaccessible/missing-document response is
generic 404. Authenticated denials are written to audit events without putting
the guessed document ID into the foreign-key column. Grant/revoke and edit
changes plus their audit entries share a transaction. Audit hashes detect
partial event alteration, but a privileged actor who can rewrite the entire
database can recompute an unanchored chain.

The source folders are `client/` (React/Vite frontend) and `server/` (Express
API). These metadata routes return no storage object key or file URL. No
upload, download, or preview endpoint exists because private file storage is
not yet configured. Route tests currently use an in-memory repository;
production MySQL behavior remains unverified.

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
