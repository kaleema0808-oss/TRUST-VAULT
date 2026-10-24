# TrustVault — Project Write-Up
**Snovasys Fresher Hiring Challenge 2026**

---

## 1. Project Overview

TrustVault is a secure document-sharing web application built with a zero-trust authorization model, rigorous file validation, and a tamper-resistant cryptographic audit trail. It was built using TypeScript across the entire stack:
- **Frontend**: React 18, Vite, Vanilla CSS with custom design tokens, dark mode aesthetics.
- **Backend**: Node.js, Express, strict TypeScript, Helmet, cookie-based session management, double-submit CSRF protection.
- **Database**: MySQL 8.0+ (InnoDB) with transactional consistency (`FOR UPDATE` row locking) and schema migrations.
- **Storage**: Local filesystem storage abstraction with UUID object isolation, MIME allowlisting, and magic-byte signature inspection.

---

## 2. Core Security & Architectural Features

### 2.1 Authentication & Role Hierarchy
- **Three distinct roles**: `admin`, `owner`, and `viewer`.
- **Password Hashing**: Node's native `scrypt` with bounded memory (`maxmem: 128 MiB`), unique per-user 16-byte salts, and constant-time dummy verification for non-existent users to eliminate timing attacks.
- **Session Security**: Cryptographically random 32-byte session tokens stored in the database with expiry timestamps, transmitted via `HttpOnly`, `SameSite=Lax`, and `Secure` (in production) cookies.
- **CSRF Defense**: Double-submit CSRF tokens required on all mutating HTTP methods (`POST`, `PUT`, `PATCH`, `DELETE`).

### 2.2 Fine-Grained Access Control & Document Management
- **Ownership & Isolation**: Owners can create, edit, upload files to, delete, and share their own documents. Cross-user access via ID guessing or search enumeration is strictly blocked and audited.
- **Named Permissions**: Owners and Admins can grant explicit `canRead` and `canEdit` permissions to named user accounts.
- **Immediate Revocation**: Permission revocations take effect synchronously within database transactions. No stale permission tokens or client-side caching delays exist.
- **Admin Oversight**: Admins have system-wide read access to documents and exclusive access to the audit trail log viewer.

### 2.3 Upload & Download Security
- **MIME Allowlist**: Strictly limited to safe business document types (`application/pdf`, `image/jpeg`, `image/png`, `image/gif`, `image/webp`, `text/plain`, Microsoft Word `.doc`/`.docx`, Microsoft Excel `.xlsx`).
- **Magic-Byte Signature Verification**: Even if a malicious user alters the `Content-Type` header or file extension, the server inspects the first 16 bytes of the binary payload to verify actual magic numbers (`%PDF-`, `\xFF\xD8\xFF`, `\x89PNG\r\n\x1a\n`, etc.). Mismatched payloads are rejected with `415 Unsupported Media Type`.
- **Path Traversal Immunity**: Files are stored on disk using cryptographically generated UUIDs (`newObjectKey()`), never user-supplied file names. Files are sanitized using `path.basename` checks.
- **Controlled Streaming**: Downloads are served with strict `Content-Disposition: attachment`, explicit `Content-Type`, and `X-Content-Type-Options: nosniff` to prevent browser mime-sniffing and cross-site scripting (XSS).

### 2.4 Tamper-Resistant Audit Trail
- **Comprehensive Logging**: Every security-critical action is logged:
  - Document uploads (`document.upload`) and downloads (`document.download`).
  - Document updates, deletions, and permission changes (`permission.grant`, `permission.revoke`).
  - Explicit denied attempts (`document.read.denied`, `document.download.denied`, `document.upload.denied`, `document.update.denied`, `document.delete.denied`).
- **Cryptographic Chaining**: Audit events contain previous-event SHA-256 hash chaining, ensuring any retroactive database tampering or record deletion invalidates the chain.
- **Admin Audit View**: Filterable by actor, action, outcome (`allowed` / `denied`), and document ID.

---

## 3. Current Status & Verification Matrix

| Requirement | Implementation Status | Automated Verification |
|-------------|-----------------------|------------------------|
| Admin / Owner / Viewer Auth | Complete | `auth.test.ts` (8 passing tests) |
| Password Hashing & Timing Mitigation | Complete | Unit tested in `auth.test.ts` |
| Document CRUD & Search Isolation | Complete | `documents.test.ts` (7 passing tests) |
| Named Read/Edit Grants & Revocation | Complete | Verified in `documents.test.ts` & `upload-download.test.ts` |
| Real File Upload & Storage | Complete | `upload-download.test.ts` (14 passing tests) |
| Magic-Byte Content Validation | Complete | Unit tests for PDF, JPEG, PNG, Text, Mismatches |
| Authorized Download Streaming | Complete | Verified with owner/viewer access checks |
| Denied Access Attempt Auditing | Complete | Tested for upload, download, and read denials |
| Cryptographic Audit Trail Chaining | Complete | Verified schema & hash generation |
| Responsive UI with Custom Styling | Complete | React SPA with Dark Mode Design System |

**Test Results Summary**:
- Vitest Test Suite: **29 passed**, 1 skipped (isolated MySQL schema integration test).
- TypeScript Typecheck: **0 errors** across `@trustvault/server` and `@trustvault/client`.
- Production Build: Clean builds for both client (`dist/`) and server (`dist/`).

---

## 4. Honest Limitations & Operational Trade-offs

1. **Ephemeral Disk on Free-Tier Containers**:
   - The application currently uses local filesystem storage (`server/src/storage/local.ts`).
   - On containerized platforms like Render's free tier, local filesystem storage is ephemeral (restarts or redeployments wipe local files). The file authorization, validation, metadata, and streaming layer is complete and fully functional, but distributed object storage (S3 / Cloudflare R2) is required for persistent multi-instance production.
2. **Production Database TLS Handshake**:
   - The production server is deployed on Render (`https://trustvault-api-kuht.onrender.com/health/live` is live).
   - In production, strict TLS (`DATABASE_TLS=true`) is enforced. When connecting to cloud MySQL providers (such as Aiven or Supabase), the provider's specific CA bundle must be provided via `DATABASE_TLS_CA` or certificate verification configured (`DATABASE_TLS_REJECT_UNAUTHORIZED`). We have updated `config.ts` and `pool.ts` to support these settings cleanly.
3. **Zod Advisory**:
   - `npm audit` notes an advisory for Zod `< 4.6.6`. The project runs Zod `3.25.76`. Upgrading to Zod v4 introduces breaking schema syntax changes; remaining on the stable v3 branch with strict runtime validation is the safer engineering decision within the challenge timeframe.

---

## 5. Next Steps for Production Hardening

If granted additional production rollout time, the following enhancements would be prioritized:
1. **Cloud Object Storage Adapter**: Implement an S3/B2 storage provider implementing the same storage interface (`storeFile`, `serveFile`, `deleteFile`) using presigned URLs or buffered streams.
2. **Distributed Rate Limiting**: Migrate the memory-based Express rate limiter to Redis to protect against distributed brute-force attacks across autoscaling instances.
3. **ClamAV Antivirus Scanning**: Integrate asynchronous antivirus stream scanning for uploaded documents before committing them to persistent storage.
4. **Audit Log Export & SIEM Webhooks**: Provide scheduled CSV/JSON exports and real-time webhook streaming for enterprise SIEM integration.
