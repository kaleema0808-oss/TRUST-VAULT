/**
 * Upload/download authorization tests.
 * Covers: authorized upload, unauthorized upload, viewer download denial,
 * revocation immediate effect, missing CSRF, disallowed MIME type,
 * and unit tests for file validation helpers.
 */
import request from "supertest";
import { beforeAll, describe, expect, it } from "vitest";
import { createApp } from "../src/app.js";
import type { AppConfig } from "../src/config.js";
import type {
  AuditInput,
  AuthRepository,
  AuthSession,
  AuthUser,
  DocumentInput,
  DocumentPermission,
  DocumentRecord,
  DocumentRepository,
  DocumentRole,
  FileMetadataInput,
} from "../src/auth/repository.js";
import { hashPassword } from "../src/security/password.js";
import {
  validateFileBuffer,
  ALLOWED_MIME_TYPES,
  MAX_FILE_BYTES,
} from "../src/storage/local.js";

const config: AppConfig = {
  nodeEnv: "test",
  apiPort: 3001,
  appOrigin: "http://localhost:5173",
  sessionTtlHours: 1,
};

const password = "test-password-123";
let passwordHash = "";

beforeAll(async () => {
  passwordHash = await hashPassword(password);
});

// ── Minimal combined repository ─────────────────────────────────────────────
class UploadTestRepository implements AuthRepository, DocumentRepository {
  readonly users: AuthUser[] = [
    { id: 1, email: "admin@example.test", role: "admin", passwordHash: "" },
    { id: 2, email: "owner-a@example.test", role: "owner", passwordHash: "" },
    { id: 4, email: "viewer@example.test", role: "viewer", passwordHash: "" },
  ];
  readonly sessions = new Map<string, AuthSession>();
  readonly documents = new Map<number, DocumentRecord>();
  readonly grants = new Map<string, DocumentPermission>();
  readonly audit: AuditInput[] = [];
  readonly fileStore = new Map<number, { objectKey: string; originalName: string; mimeType: string }>();
  private nextId = 1;

  constructor() {
    for (const u of this.users) u.passwordHash = passwordHash;
  }

  async findUserByEmail(email: string) { return this.users.find((u) => u.email === email) ?? null; }
  async findSession(hash: string) {
    const s = this.sessions.get(hash);
    if (!s || s.expiresAt.getTime() <= Date.now()) return null;
    const user = this.users.find((u) => u.id === s.userId);
    return user ? { session: s, user: { id: user.id, email: user.email, role: user.role } } : null;
  }
  async createSession(s: AuthSession) { this.sessions.set(s.tokenHash, s); }
  async updateCsrfToken(hash: string, csrfHash: string) { const s = this.sessions.get(hash); if (s) s.csrfTokenHash = csrfHash; }
  async deleteSession(hash: string) { this.sessions.delete(hash); }
  async createUser(email: string, ph: string, role: import("../src/auth/repository.js").UserRole) {
    const id = this.users.length + 100;
    const user = { id, email, role, passwordHash: ph };
    this.users.push(user);
    return user;
  }
  async listUsers() { return this.users.map((u) => ({ id: u.id, email: u.email, role: u.role })); }

  private key(docId: number, uid: number) { return `${docId}:${uid}`; }
  private canRead(doc: DocumentRecord, uid: number, role: DocumentRole) {
    return role === "admin" || doc.ownerId === uid || this.grants.get(this.key(doc.id, uid))?.canRead === true;
  }
  private canEdit(doc: DocumentRecord, uid: number, role: DocumentRole) {
    return role === "admin" || (role === "owner" && (doc.ownerId === uid || this.grants.get(this.key(doc.id, uid))?.canEdit === true));
  }

  async listAccessible(uid: number, role: DocumentRole) {
    return [...this.documents.values()].filter((d) => this.canRead(d, uid, role));
  }
  async getAccessible(docId: number, uid: number, role: DocumentRole) {
    const d = this.documents.get(docId);
    return d && this.canRead(d, uid, role) ? d : null;
  }
  async create(uid: number, input: DocumentInput) {
    const id = this.nextId++;
    const now = new Date().toISOString();
    const doc: DocumentRecord = { id, ownerId: uid, ...input, originalName: null, mimeType: null, fileSize: null, createdAt: now, updatedAt: now };
    this.documents.set(id, doc);
    await this.appendAudit({ actorUserId: uid, documentId: id, action: "document.create", outcome: "allowed", details: { documentId: id } });
    return doc;
  }
  async update(docId: number, uid: number, role: DocumentRole, input: DocumentInput) {
    const d = this.documents.get(docId);
    if (!d || !this.canEdit(d, uid, role)) return null;
    const updated = { ...d, ...input, updatedAt: new Date().toISOString() };
    this.documents.set(docId, updated);
    await this.appendAudit({ actorUserId: uid, documentId: docId, action: "document.edit", outcome: "allowed", details: { documentId: docId } });
    return updated;
  }
  async delete(docId: number, uid: number, role: DocumentRole) {
    const d = this.documents.get(docId);
    if (!d || !this.canEdit(d, uid, role)) return false;
    this.documents.delete(docId);
    await this.appendAudit({ actorUserId: uid, documentId: docId, action: "document.delete", outcome: "allowed", details: { documentId: docId } });
    return true;
  }
  async grant(docId: number, uid: number, role: DocumentRole, targetUid: number, perm: DocumentPermission) {
    const d = this.documents.get(docId);
    if (!d || !this.canEdit(d, uid, role) || !this.users.some((u) => u.id === targetUid)) return false;
    this.grants.set(this.key(docId, targetUid), perm);
    await this.appendAudit({ actorUserId: uid, documentId: docId, action: "permission.grant", outcome: "allowed", details: { targetUid, ...perm } });
    return true;
  }
  async revoke(docId: number, uid: number, role: DocumentRole, targetUid: number) {
    const d = this.documents.get(docId);
    if (!d || !this.canEdit(d, uid, role)) return false;
    this.grants.delete(this.key(docId, targetUid));
    await this.appendAudit({ actorUserId: uid, documentId: docId, action: "permission.revoke", outcome: "allowed", details: { targetUid } });
    return true;
  }
  async appendAudit(event: AuditInput) { this.audit.push(event); }
  async listAuditEvents() { return this.audit.map((e, i) => ({ id: i + 1, ...e, createdAt: new Date().toISOString() })); }
  async listPermissions(docId: number, uid: number, role: DocumentRole) {
    const d = this.documents.get(docId);
    if (!d || !this.canRead(d, uid, role)) return [];
    const result: import("../src/auth/repository.js").PermissionRecord[] = [];
    for (const [k, perm] of this.grants.entries()) {
      const [dId, uId] = k.split(":").map(Number);
      if (dId === docId) {
        const user = this.users.find((u) => u.id === uId);
        if (user) result.push({ userId: uId, email: user.email, canRead: perm.canRead, canEdit: perm.canEdit, grantedBy: uid });
      }
    }
    return result;
  }
  async updateFileMetadata(docId: number, uid: number, role: DocumentRole, meta: FileMetadataInput): Promise<boolean> {
    const d = this.documents.get(docId);
    if (!d || !this.canEdit(d, uid, role)) return false;
    this.fileStore.set(docId, { objectKey: meta.objectKey, originalName: meta.originalName, mimeType: meta.mimeType });
    await this.appendAudit({ actorUserId: uid, documentId: docId, action: "document.upload", outcome: "allowed", details: { documentId: docId, originalName: meta.originalName } });
    return true;
  }
  async getObjectKeyForDownload(docId: number, uid: number, role: DocumentRole) {
    const d = this.documents.get(docId);
    if (!d || !this.canRead(d, uid, role)) return null;
    const f = this.fileStore.get(docId);
    return f ? { objectKey: f.objectKey, originalName: f.originalName, mimeType: f.mimeType } : null;
  }
}

async function loginAs(app: ReturnType<typeof createApp>, email: string) {
  const res = await request(app).post("/api/auth/login")
    .set("Origin", config.appOrigin)
    .send({ email, password });
  expect(res.status).toBe(200);
  return { cookie: res.headers["set-cookie"][0].split(";")[0], csrf: res.body.csrfToken as string };
}

function makeApp() {
  const repo = new UploadTestRepository();
  const app = createApp(repo, config, async () => undefined, repo);
  return { app, repo };
}

// ── Unit tests: file validation ─────────────────────────────────────────────
describe("upload security: file validation unit tests", () => {
  it("rejects a disallowed MIME type (shell script)", () => {
    expect(validateFileBuffer(Buffer.from("#!/bin/sh"), "application/x-sh")).toContain("not allowed");
  });

  it("rejects PDF magic bytes declared as image/jpeg", () => {
    const pdfBytes = Buffer.from("%PDF-1.4 test", "ascii");
    expect(validateFileBuffer(pdfBytes, "image/jpeg")).toContain("does not match");
  });

  it("accepts correct PDF magic bytes", () => {
    expect(validateFileBuffer(Buffer.from("%PDF-1.4 x", "ascii"), "application/pdf")).toBeNull();
  });

  it("accepts correct PNG magic bytes", () => {
    const png = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);
    expect(validateFileBuffer(png, "image/png")).toBeNull();
  });

  it("accepts correct JPEG magic bytes", () => {
    const jpg = Buffer.from([0xff, 0xd8, 0xff, 0xe0, 0x00, 0x10]);
    expect(validateFileBuffer(jpg, "image/jpeg")).toBeNull();
  });

  it("MAX_FILE_BYTES equals 10 MiB", () => {
    expect(MAX_FILE_BYTES).toBe(10 * 1024 * 1024);
  });

  it("ALLOWED_MIME_TYPES includes common safe types, excludes executables", () => {
    expect(ALLOWED_MIME_TYPES).toContain("application/pdf");
    expect(ALLOWED_MIME_TYPES).toContain("image/jpeg");
    expect(ALLOWED_MIME_TYPES).toContain("image/png");
    expect(ALLOWED_MIME_TYPES).toContain("text/plain");
    expect(ALLOWED_MIME_TYPES).not.toContain("application/x-sh");
    expect(ALLOWED_MIME_TYPES).not.toContain("application/octet-stream");
    expect(ALLOWED_MIME_TYPES).not.toContain("application/x-executable");
  });
});

// ── HTTP authorization tests: upload/download ────────────────────────────────
describe("upload/download authorization (HTTP, in-memory repository)", () => {
  const pdfBuffer = Buffer.concat([Buffer.from("%PDF-1.4", "ascii"), Buffer.alloc(100)]);

  it("owner can upload a file; audit event is recorded as allowed", async () => {
    const { app, repo } = makeApp();
    const owner = await loginAs(app, "owner-a@example.test");

    const doc = await request(app).post("/api/documents")
      .set("Origin", config.appOrigin).set("Cookie", owner.cookie).set("X-CSRF-Token", owner.csrf)
      .send({ name: "contract", category: "legal" });
    expect(doc.status).toBe(201);
    const id = doc.body.document.id as number;

    const up = await request(app)
      .post(`/api/documents/${id}/upload`)
      .set("Origin", config.appOrigin)
      .set("Cookie", owner.cookie)
      .set("X-CSRF-Token", owner.csrf)
      .attach("file", pdfBuffer, { filename: "contract.pdf", contentType: "application/pdf" });

    expect(up.status).toBe(204);
    expect(repo.fileStore.has(id)).toBe(true);
    expect(repo.audit.some((e) =>
      e.action === "document.upload" && e.outcome === "allowed" && e.actorUserId === 2,
    )).toBe(true);
  });

  it("viewer with read-only grant cannot upload; denial is audited", async () => {
    const { app, repo } = makeApp();
    const owner = await loginAs(app, "owner-a@example.test");

    const doc = await request(app).post("/api/documents")
      .set("Origin", config.appOrigin).set("Cookie", owner.cookie).set("X-CSRF-Token", owner.csrf)
      .send({ name: "sensitive", category: "hr" });
    const id = doc.body.document.id as number;
    await repo.grant(id, 2, "owner", 4, { canRead: true, canEdit: false });

    const viewer = await loginAs(app, "viewer@example.test");
    const up = await request(app)
      .post(`/api/documents/${id}/upload`)
      .set("Origin", config.appOrigin)
      .set("Cookie", viewer.cookie)
      .set("X-CSRF-Token", viewer.csrf)
      .attach("file", pdfBuffer, { filename: "sneaky.pdf", contentType: "application/pdf" });

    expect(up.status).toBe(404); // masked as 404 to prevent enumeration
    expect(repo.audit.some((e) =>
      e.action === "document.upload" && e.outcome === "denied" && e.actorUserId === 4,
    )).toBe(true);
  });

  it("download denied for viewer with no read access; denial is audited", async () => {
    const { app, repo } = makeApp();
    const owner = await loginAs(app, "owner-a@example.test");

    const doc = await request(app).post("/api/documents")
      .set("Origin", config.appOrigin).set("Cookie", owner.cookie).set("X-CSRF-Token", owner.csrf)
      .send({ name: "private", category: "legal" });
    const id = doc.body.document.id as number;
    repo.fileStore.set(id, { objectKey: "key-xyz", originalName: "private.pdf", mimeType: "application/pdf" });

    const viewer = await loginAs(app, "viewer@example.test");
    const dl = await request(app).get(`/api/documents/${id}/download`).set("Cookie", viewer.cookie);

    expect(dl.status).toBe(404);
    expect(repo.audit.some((e) =>
      e.action === "document.download" && e.outcome === "denied" && e.actorUserId === 4,
    )).toBe(true);
  });

  it("download denied on first request after read grant is revoked (immediate revocation)", async () => {
    const { app, repo } = makeApp();
    const owner = await loginAs(app, "owner-a@example.test");

    const doc = await request(app).post("/api/documents")
      .set("Origin", config.appOrigin).set("Cookie", owner.cookie).set("X-CSRF-Token", owner.csrf)
      .send({ name: "shared", category: "general" });
    const id = doc.body.document.id as number;
    repo.fileStore.set(id, { objectKey: "key-rev", originalName: "shared.pdf", mimeType: "application/pdf" });

    // Grant read to viewer (id 4)
    await request(app).put(`/api/documents/${id}/permissions/4`)
      .set("Origin", config.appOrigin).set("Cookie", owner.cookie).set("X-CSRF-Token", owner.csrf)
      .send({ canRead: true, canEdit: false });

    const viewer = await loginAs(app, "viewer@example.test");
    // Download while granted — should get allowed audit (404 from disk is fine)
    await request(app).get(`/api/documents/${id}/download`).set("Cookie", viewer.cookie);
    expect(repo.audit.some((e) =>
      e.action === "document.download" && e.outcome === "allowed" && e.actorUserId === 4,
    )).toBe(true);

    // Revoke
    await request(app).delete(`/api/documents/${id}/permissions/4`)
      .set("Origin", config.appOrigin).set("Cookie", owner.cookie).set("X-CSRF-Token", owner.csrf);

    // Must be denied now
    const after = await request(app).get(`/api/documents/${id}/download`).set("Cookie", viewer.cookie);
    expect(after.status).toBe(404);
    expect(repo.audit.some((e) =>
      e.action === "document.download" && e.outcome === "denied" && e.actorUserId === 4,
    )).toBe(true);
  });

  it("upload rejected without CSRF token → 403", async () => {
    const { app } = makeApp();
    const owner = await loginAs(app, "owner-a@example.test");

    const doc = await request(app).post("/api/documents")
      .set("Origin", config.appOrigin).set("Cookie", owner.cookie).set("X-CSRF-Token", owner.csrf)
      .send({ name: "no-csrf", category: "test" });
    const id = doc.body.document.id as number;

    const up = await request(app)
      .post(`/api/documents/${id}/upload`)
      .set("Origin", config.appOrigin)
      .set("Cookie", owner.cookie)
      // No X-CSRF-Token
      .attach("file", pdfBuffer, { filename: "f.pdf", contentType: "application/pdf" });

    expect(up.status).toBe(403);
  });

  it("upload rejected for disallowed MIME type → 400", async () => {
    const { app } = makeApp();
    const owner = await loginAs(app, "owner-a@example.test");

    const doc = await request(app).post("/api/documents")
      .set("Origin", config.appOrigin).set("Cookie", owner.cookie).set("X-CSRF-Token", owner.csrf)
      .send({ name: "script-test", category: "test" });
    const id = doc.body.document.id as number;

    const up = await request(app)
      .post(`/api/documents/${id}/upload`)
      .set("Origin", config.appOrigin)
      .set("Cookie", owner.cookie)
      .set("X-CSRF-Token", owner.csrf)
      .attach("file", Buffer.from("#!/bin/bash\n"), { filename: "evil.sh", contentType: "application/x-sh" });

    expect(up.status).toBe(400);
  });

  it("upload rejected when PDF magic bytes mismatch declared mime → 415", async () => {
    const { app } = makeApp();
    const owner = await loginAs(app, "owner-a@example.test");

    const doc = await request(app).post("/api/documents")
      .set("Origin", config.appOrigin).set("Cookie", owner.cookie).set("X-CSRF-Token", owner.csrf)
      .send({ name: "fake-pdf", category: "test" });
    const id = doc.body.document.id as number;

    // Declare application/pdf but send PNG bytes
    const pngBytes = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, ...Buffer.alloc(92)]);
    const up = await request(app)
      .post(`/api/documents/${id}/upload`)
      .set("Origin", config.appOrigin)
      .set("Cookie", owner.cookie)
      .set("X-CSRF-Token", owner.csrf)
      .attach("file", pngBytes, { filename: "fake.pdf", contentType: "application/pdf" });

    expect(up.status).toBe(415);
  });
});
