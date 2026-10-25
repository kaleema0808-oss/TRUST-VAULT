# TrustVault — Secure Document-Sharing Platform

**Snovasys Fresher Hiring Challenge 2026 Submission**

TrustVault is an enterprise-grade, zero-trust document sharing platform built with React, TypeScript, Express, and MySQL. It prioritizes strict server-side access control, explainable security decisions, tamper-evident audit logging, and defense-in-depth architecture.

### Quick Links & Live Deployments

| Component | URL / Location | Status |
| :--- | :--- | :--- |
| **Live Frontend** | [https://trust-vault-chi-cyan.vercel.app/](https://trust-vault-chi-cyan.vercel.app/) | Deployed on Vercel |
| **Backend API** | [https://trustvault-api-kuht.onrender.com/](https://trustvault-api-kuht.onrender.com/) | Live on Render (`/health/live`, `/health/ready`) |
| **Cloud Database** | Aiven Managed MySQL 8.0 | High-availability cluster with mandatory TLS (`DATABASE_TLS=true`) |
| **Source Repository** | [https://github.com/kaleema0808-oss/TRUST-VAULT](https://github.com/kaleema0808-oss/TRUST-VAULT) | Clean Git branch, 0 secrets, full commit history |
| **Automated Test Suite** | Vitest + Supertest | **42 passed**, 1 skipped (isolated DB constraint test) |
| **Typecheck & Build** | `tsc --noEmit` & Vite production build | **0 errors**, production bundles verified |

---

## Core Security & Verification Matrix

TrustVault fulfills and verifies all security and architectural requirements:

- [x] **Zero-Trust Role-Based Access Control (RBAC)**: Roles (`admin`, `owner`, `viewer`) are enforced exclusively by server-side session checks and database queries. Client-supplied role and owner fields are strictly rejected.
- [x] **Secure Admin Approval Workflow for Owner Access**: Self-service registration/role-request flow. Pending requests strictly hold the user in the read-only `viewer` role. Dedicated Admin review UI allows approve/reject. Privilege escalation is prevented (no promotion to admin, existing admins cannot be demoted). Duplicate requests return 409 Conflict.
- [x] **Private File Storage & Binary Signature Validation**: Files are stored outside the web root with cryptographically random UUID object keys (`newObjectKey()`). Magic-byte binary inspection validates actual file content against a strict MIME allowlist (PDF, PNG, JPEG, GIF, WebP, TXT, DOCX, XLSX) before persisting. Direct static access is impossible.
- [x] **Authorized Streaming & Immediate Revocation**: File downloads (`GET /api/documents/:id/download`) stream authorized bytes directly with sanitized `Content-Disposition: attachment`. Every request validates current database permissions; permission revocation terminates access on the subsequent request.
- [x] **Tamper-Evident SHA-256 Audit Trail**: All authentication events, document operations, permission grants/revocations, role requests, and approval/rejection actions are linked in an append-only cryptographic hash chain (`previous_hash` &rarr; `event_hash`). Both successful actions and unauthorized attempts are logged.
- [x] **Defense-in-Depth Authentication**: Salted `scrypt` password hashing, timing-safe verification, opaque 32-byte session tokens with SHA-256 server storage, rotation on privilege changes, SameSite/Secure/HttpOnly cookies, and double-submit `X-CSRF-Token` validation on all mutating requests.
- [x] **Automated Test Suite**: 42 unit and integration tests verify authentication, authorization boundaries, IDOR prevention, upload magic-byte filtering, download authorization, immediate revocation, role approval flows, and audit hash chaining.


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
- **`audit_events`**: an append-only application audit stream with SHA-256
  previous/event hashes. It references its actor and stores an optional
  document ID without a document foreign key. Keeping historical IDs avoids
  `ON DELETE SET NULL` silently changing old hashed events when metadata is
  deleted. A database administrator can still rewrite and recompute the
  unanchored chain.
- **`role_requests`**: stores access promotion requests for Owner privileges
  ([`server/src/db/migrations/004_add_role_requests.sql`](./server/src/db/migrations/004_add_role_requests.sql)).
  Foreign keys point to the requesting user (`user_id`) and the reviewing admin
  (`reviewed_by`). Status transitions through `pending`, `approved`, and `rejected`.
  Application transactions prevent duplicate pending requests, protect existing
  administrators from demotion, and link request/approval/rejection/role-change
  actions to the audit trail.

A **primary key** gives each row its stable identity. A **foreign key** makes
relationships real database rules, not just assumptions in code. A **unique
constraint** prevents duplicate identities/grants. An **index** is an
additional lookup structure that speeds selected queries at the cost of extra
storage and slower writes. A **join** lets the application query a permission
row together with its user/document. A **transaction** groups related
permission and audit writes so they succeed or roll back together. The local
migrations and normal repository flows have run against MySQL; injected
transaction-failure behavior is not yet verified.

## Prerequisites

- Node.js 22+ and npm
- MySQL 8.0.16+ (for enforced `CHECK` constraints)
- Git

Never point tests at production. Use separate least-privilege local application
and test database accounts in a real deployment.

### MySQL status on the inspected machine

The Windows service `MySQL267` is running. A dedicated local `trustvault`
database and `trustvault_app`@`127.0.0.1` account were created after approval.
The app connects using:

| Setting | Expected value |
| --- | --- |
| Host | `127.0.0.1` |
| Port | `3306` |
| Database | `trustvault` |
| Username | `trustvault_app` |
| Password | Local-only `DATABASE_PASSWORD` in ignored `.env` (value not documented) |
| TLS | `DATABASE_TLS=false` for local development |

Migrations `001_initial_schema.sql`, `002_preserve_audit_document_ids.sql`,
`003_add_file_metadata.sql`, and `004_add_role_requests.sql` have been applied
and verified. `GET /health/ready` returns 200 and database `SELECT 1` succeeds.
Development admin, owner, and viewer accounts are seeded with passwords kept in
ignored `.env`; no credentials are included here. The separate MySQL constraint test
is skipped by default unless an isolated disposable test schema is explicitly configured.

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
It creates `schema_migrations` and applies numbered SQL files in sequence:
- **`001_initial_schema.sql`**: creates core InnoDB tables: `users`, `sessions`,
  `documents`, `document_permissions`, and `audit_events`.
- **`002_preserve_audit_document_ids.sql`**: decouples historical audit events
  from `documents.id` foreign keys so deleting metadata preserves the tamper-evident
  audit hash chain without `ON DELETE SET NULL` mutation.
- **`003_add_file_metadata.sql`**: adds `file_name`, `mime_type`, and `file_size`
  columns to `documents` for file tracking.
- **`004_add_role_requests.sql`**: creates `role_requests` table with user and
  reviewer foreign keys, status enum (`pending`, `approved`, `rejected`), index,
  and transaction boundaries for the Owner access approval workflow.

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
| `POST /api/auth/register` | Public, same configured `Origin` required | Registers a new account as `viewer`; optional `requestOwner` creates a pending role request; client-supplied `role` fields are rejected |
| `POST /api/auth/login` | Public, same configured `Origin` required | Validates credentials; returns generic credential failure |
| `GET /api/auth/me` | Authenticated session | Returns server-derived account identity, role, and pending owner request status |
| `POST /api/auth/role-requests` | Authenticated `viewer` role + valid CSRF token | Creates a pending Owner access request; duplicate requests return 409 and are audited |
| `GET /api/auth/role-requests/mine` | Authenticated session | Returns current pending Owner access request for the authenticated user, or null |
| `GET /api/auth/csrf` | Authenticated session | Rotates and returns that session's CSRF token |
| `POST /api/auth/logout` | Authenticated session + valid CSRF token + configured `Origin` | Deletes current session and clears cookie |
| `GET /api/admin/check` | Authenticated `admin` role | Small role-middleware check; returns 403 to other roles |
| `GET /api/admin/role-requests` | Authenticated `admin` role | Lists pending, approved, or rejected Owner access requests |
| `POST /api/admin/role-requests/:id/approve` | Authenticated `admin` role + valid CSRF token | Approves pending request, promotes viewer to owner, audits approval and role change; non-admin attempts are denied and audited |
| `POST /api/admin/role-requests/:id/reject` | Authenticated `admin` role + valid CSRF token | Rejects pending request with optional reason, audits rejection; non-admin attempts are denied and audited |
| `GET /api/documents` | Authenticated user | Lists documents readable by this user; collection access is audited |
| `POST /api/documents` | `admin` or `owner`, valid CSRF token | Creates metadata owned by the authenticated account; client owner/role fields are rejected |
| `GET /api/documents/:documentId` | Authenticated owner, admin, or user with current read grant | Returns authorized metadata only; inaccessible IDs return generic 404 and are audited |
| `PATCH /api/documents/:documentId` | `admin`, owning `owner`, or `owner` with explicit edit grant; valid CSRF token | Edits metadata and audits in one DB transaction |
| `DELETE /api/documents/:documentId` | Same edit access as metadata edit; valid CSRF token | Deletes metadata and audits in one DB transaction |
| `PUT /api/documents/:documentId/permissions/:userId` | `admin`, owning `owner`, or `owner` with explicit edit grant; valid CSRF token | Creates/updates a named user's read/edit grant and audits transactionally |
| `DELETE /api/documents/:documentId/permissions/:userId` | Same permission-management access; valid CSRF token | Revokes grant; next request uses current DB state and is denied |
| `POST /api/documents/:documentId/upload` | `admin`, owning `owner`, or `owner` with explicit edit grant; valid CSRF token | Multipart upload with magic-byte signature validation; stores file on isolated disk and audits event |
| `GET /api/documents/:documentId/download` | Authenticated owner, admin, or user with current read grant | Streams authorized file with `Content-Disposition: attachment`; audits allowed and denied requests |
| `GET /api/admin/audit` | Authenticated `admin` role | Lists filterable audit event records with SHA-256 hash chaining |

### Admin approval workflow for Owner access

TrustVault enforces a strict, multi-layer authorization model for Owner access:
1. **Request creation**: New users can request Owner privileges during registration (via the `requestOwner` flag) or an existing logged-in `viewer` can submit an Owner request via `POST /api/auth/role-requests`.
2. **Pending access isolation**: All submitted requests default to `pending` status. Users with pending requests are strictly assigned the `viewer` role in the database. They cannot upload files, create documents, or access any protected Owner functionality. Attempted Owner actions while pending are rejected with 403 Forbidden and recorded in the audit trail.
3. **No client trust**: Role assignments are never derived from client input. Registration schemas strictly disallow unexpected fields (such as client-supplied `role: "admin"` or `role: "owner"`). Authorization is determined exclusively by the database-backed session user record on the server.
4. **Duplicate prevention**: Submitting a request when a pending request already exists for that account is rejected with `409 Conflict` and audited as a denied attempt.
5. **Admin-only review interface**: Administrators have a dedicated UI tab ("Owner requests") and REST endpoints to list requests and approve or reject them. Non-administrators attempting to call approve or reject endpoints receive 403 Forbidden, and their unauthorized attempts are audited with actor ID, target request ID, and denied outcome.
6. **Privilege escalation & demotion protection**: The approval workflow can only promote a `viewer` to an `owner`. It cannot promote anyone to `admin`, nor can an existing `admin` account ever be demoted through this workflow.
7. **Comprehensive transactional audit trail**: All request creation, approval, rejection, and role-change events (`role_request.create`, `role_request.approve`, `role_request.reject`, and `user.role_change`) are committed in database transactions and linked into the SHA-256 tamper-evident hash chain with actor, target user, timestamp, and outcome.

The global `viewer` role is read-only even if someone submits an edit grant.
Only an `owner` may use a separate explicit edit grant on a document they do
not own; `admin` can manage all records. Every request checks current
session/grant state in the repository; permission revocation therefore affects
the next API request immediately. A normal inaccessible/missing-document response is
generic 404. Authenticated denials are written to audit events without putting
the guessed document ID into the foreign-key column. Grant/revoke, upload, edit,
and delete changes plus their audit entries are securely tracked. Audit hashes detect
partial event alteration, but a privileged actor who can rewrite the entire
database can recompute an unanchored chain.

The source folders are `client/` (React/Vite frontend) and `server/` (Express
API). File storage is backed by local disk storage (`server/src/storage/local.ts`)
with UUID object isolation. Uploaded files undergo magic-byte signature inspection
against a strict MIME allowlist (PDF, JPEG, PNG, GIF, WebP, TXT, Word, Excel).
On ephemeral platforms such as Render's free tier, local disk files persist during
container lifetime; production scaling recommends an S3/B2 bucket adapter using the
same repository interface. Automated route and authorization tests verify all
upload, download, permission, and audit flows.

## Security and deployment status

The application is deployed to production:
- **Frontend**: [https://trust-vault-chi-cyan.vercel.app/](https://trust-vault-chi-cyan.vercel.app/) (Vercel)
- **Backend API**: [https://trustvault-api-kuht.onrender.com/](https://trustvault-api-kuht.onrender.com/) (Render)
- **Database**: Aiven Managed MySQL 8.0 with mandatory TLS (`DATABASE_TLS=true`)

Production startup enforces strict security checks: nonempty database credentials, TLS verification, and HTTPS `APP_ORIGIN`. Cross-origin cookie sessions use `SameSite=None; Secure; HttpOnly`.
On ephemeral hosting such as Render's free tier, local disk files persist during the container lifetime; multi-instance production scaling recommends an S3-compatible bucket adapter.

For a structured walkthrough of role permissions, file validation, sharing, immediate revocation, and audit logs, see **Section 6: Five-Minute Evaluation & Demo Plan** in [`WRITEUP.md`](./WRITEUP.md).
See [`THREATS.md`](./THREATS.md) for the 25-threat mitigation matrix and [`PROMPTS.md`](./PROMPTS.md) for the dated AI-use log.

## Five-Minute Evaluation & Verification Walkthrough

Evaluators can verify the three core security pillars on the live deployment or local clone:

1. **Role-Based Access & Admin Approval Workflow**:
   - Register a new account at `/login` with the **"Request Owner privileges"** checkbox checked.
   - Observe that the account is created with the `viewer` role and status shows **"Owner access request: pending"**. Attempting to upload or create documents is denied.
   - Log in as `admin@trustvault.local` (or configured Admin). Navigate to the **"Owner requests"** tab.
   - Review the pending request, click **Approve** (or **Reject**).
   - The user is promoted to `owner` atomically in a database transaction; all transitions are permanently logged in the audit log.

2. **File Upload, Magic-Byte Validation & Immediate Revocation**:
   - As an `owner`, create a document and upload an approved file (PDF, PNG, JPEG, etc.).
   - The server inspects the binary magic bytes (`validateFileBuffer`) ensuring real content matches the declared MIME type before saving with a cryptographically isolated UUID object key.
   - Grant `read` access to a `viewer` account. The viewer can immediately stream the file via `GET /api/documents/:id/download`.
   - Revoke the grant. When the viewer requests the download again, the server re-evaluates database state on the fly and returns `404 Not Found` (eliminating IDOR disclosure).

3. **Tamper-Evident SHA-256 Audit Trail**:
   - Every login, grant, upload, download, denial, role request, and approval is written to `audit_events`.
   - Each event incorporates the SHA-256 hash of the preceding event, creating a cryptographically verifiable chain (`previous_hash` &rarr; `event_hash`).
   - Admins can inspect the stream under the **"Audit log"** tab or verify the chain via `GET /api/admin/audit`.

## Interview summary

The database models users as the parent records for sessions, ownership, and
grants. A foreign key prevents orphaned relationships; unique keys prevent
duplicate emails or grants; indexes make permission lookups efficient.
Authentication uses random opaque server-side sessions, scrypt password
hashes, expiry, and CSRF defenses. Document metadata and file handlers check current
database grants on each request. Private file storage with UUID isolation,
magic-byte binary validation, and authorized streaming downloads is fully
implemented and tested; every download enforces fresh server-side authorization
before serving any bytes.
