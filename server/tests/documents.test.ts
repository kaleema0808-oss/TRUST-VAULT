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
} from "../src/auth/repository.js";
import { hashPassword } from "../src/security/password.js";
import { createAuditEventHash, verifyAuditChain, type ChainAuditEvent } from "../src/security/audit-chain.js";

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

class TestRepository implements AuthRepository, DocumentRepository {
  readonly users: AuthUser[] = [
    { id: 1, email: "admin@example.test", role: "admin", passwordHash: "" },
    { id: 2, email: "owner-a@example.test", role: "owner", passwordHash: "" },
    { id: 3, email: "owner-b@example.test", role: "owner", passwordHash: "" },
    { id: 4, email: "viewer@example.test", role: "viewer", passwordHash: "" },
  ];
  readonly sessions = new Map<string, AuthSession>();
  readonly documents = new Map<number, DocumentRecord>();
  readonly grants = new Map<string, DocumentPermission>();
  readonly audit: AuditInput[] = [];
  private nextDocumentId = 1;

  constructor() {
    for (const user of this.users) user.passwordHash = passwordHash;
  }

  async findUserByEmail(email: string) {
    return this.users.find((user) => user.email === email) ?? null;
  }

  async findSession(tokenHash: string) {
    const session = this.sessions.get(tokenHash);
    if (!session || session.expiresAt.getTime() <= Date.now()) return null;
    const user = this.users.find((candidate) => candidate.id === session.userId);
    return user ? { session, user: { id: user.id, email: user.email, role: user.role } } : null;
  }

  async createSession(session: AuthSession) {
    this.sessions.set(session.tokenHash, session);
  }

  async updateCsrfToken(tokenHash: string, csrfTokenHash: string) {
    const session = this.sessions.get(tokenHash);
    if (session) session.csrfTokenHash = csrfTokenHash;
  }

  async deleteSession(tokenHash: string) {
    this.sessions.delete(tokenHash);
  }

  async createUser(email: string, passwordHash: string, role: import("../src/auth/repository.js").UserRole) {
    const id = this.users.length + 100;
    const user = { id, email, role, passwordHash };
    this.users.push(user);
    return user;
  }

  async listUsers() {
    return this.users.map((u) => ({ id: u.id, email: u.email, role: u.role }));
  }

  private key(documentId: number, userId: number) {
    return `${documentId}:${userId}`;
  }

  private canRead(document: DocumentRecord, userId: number, role: DocumentRole) {
    return role === "admin" || document.ownerId === userId ||
      this.grants.get(this.key(document.id, userId))?.canRead === true;
  }

  private canEdit(document: DocumentRecord, userId: number, role: DocumentRole) {
    return role === "admin" || (
      role === "owner" &&
      (document.ownerId === userId ||
        this.grants.get(this.key(document.id, userId))?.canEdit === true)
    );
  }

  async listAccessible(userId: number, role: DocumentRole) {
    return [...this.documents.values()].filter((doc) => this.canRead(doc, userId, role));
  }

  async getAccessible(documentId: number, userId: number, role: DocumentRole) {
    const document = this.documents.get(documentId);
    return document && this.canRead(document, userId, role) ? document : null;
  }

  async create(userId: number, input: DocumentInput) {
    const id = this.nextDocumentId++;
    const now = new Date().toISOString();
    const document: DocumentRecord = { id, ownerId: userId, ...input, createdAt: now, updatedAt: now };
    this.documents.set(id, document);
    await this.appendAudit({
      actorUserId: userId, documentId: id, action: "document.create",
      outcome: "allowed", details: { documentId: id },
    });
    return document;
  }

  async update(documentId: number, userId: number, role: DocumentRole, input: DocumentInput) {
    const document = this.documents.get(documentId);
    if (!document || !this.canEdit(document, userId, role)) return null;
    const updated = { ...document, ...input, updatedAt: new Date().toISOString() };
    this.documents.set(documentId, updated);
    await this.appendAudit({
      actorUserId: userId, documentId, action: "document.edit",
      outcome: "allowed", details: { documentId },
    });
    return updated;
  }

  async delete(documentId: number, userId: number, role: DocumentRole) {
    const document = this.documents.get(documentId);
    if (!document || !this.canEdit(document, userId, role)) return false;
    this.documents.delete(documentId);
    await this.appendAudit({
      actorUserId: userId, documentId, action: "document.delete",
      outcome: "allowed", details: { documentId },
    });
    return true;
  }

  async grant(
    documentId: number,
    userId: number,
    role: DocumentRole,
    targetUserId: number,
    permission: DocumentPermission,
  ) {
    const document = this.documents.get(documentId);
    if (!document || !this.canEdit(document, userId, role) ||
        !this.users.some((candidate) => candidate.id === targetUserId)) return false;
    this.grants.set(this.key(documentId, targetUserId), permission);
    await this.appendAudit({
      actorUserId: userId, documentId, action: "permission.grant",
      outcome: "allowed", details: { targetUserId, ...permission },
    });
    return true;
  }

  async revoke(documentId: number, userId: number, role: DocumentRole, targetUserId: number) {
    const document = this.documents.get(documentId);
    if (!document || !this.canEdit(document, userId, role)) return false;
    this.grants.delete(this.key(documentId, targetUserId));
    await this.appendAudit({
      actorUserId: userId, documentId, action: "permission.revoke",
      outcome: "allowed", details: { targetUserId },
    });
    return true;
  }

  async appendAudit(event: AuditInput) {
    this.audit.push(event);
  }

  async listAuditEvents(_filters: import("../src/auth/repository.js").AuditFilter) {
    return this.audit.map((e, i) => ({
      id: i + 1,
      actorUserId: e.actorUserId,
      documentId: e.documentId,
      action: e.action,
      outcome: e.outcome,
      details: e.details,
      createdAt: new Date().toISOString(),
    }));
  }

  async listPermissions(documentId: number, userId: number, role: DocumentRole) {
    const document = this.documents.get(documentId);
    if (!document || !this.canRead(document, userId, role)) return [];
    const result: import("../src/auth/repository.js").PermissionRecord[] = [];
    for (const [key, perm] of this.grants.entries()) {
      const [docId, uId] = key.split(":").map(Number);
      if (docId === documentId) {
        const user = this.users.find((u) => u.id === uId);
        if (user) result.push({ userId: uId, email: user.email, canRead: perm.canRead, canEdit: perm.canEdit, grantedBy: userId });
      }
    }
    return result;
  }
}

async function login(app: ReturnType<typeof createApp>, email: string) {
  const response = await request(app).post("/api/auth/login")
    .set("Origin", config.appOrigin)
    .send({ email, password });
  expect(response.status).toBe(200);
  return {
    cookie: response.headers["set-cookie"][0].split(";")[0],
    csrf: response.body.csrfToken as string,
  };
}

function setup() {
  const repository = new TestRepository();
  const app = createApp(repository, config, async () => undefined, repository);
  return { app, repository };
}

describe("document access control and audit", () => {
  it("detects an altered event in the hash-linked audit chain", () => {
    const firstPayload = {
      actorUserId: 2,
      documentId: 9,
      action: "document.read",
      outcome: "allowed" as const,
      details: { documentId: 9, name: "private" },
      createdAt: "2026-10-23T12:00:00.000Z",
    };
    const firstHash = createAuditEventHash(firstPayload, null);
    const secondPayload = {
      actorUserId: 4,
      documentId: 9,
      action: "document.read",
      outcome: "denied" as const,
      details: { reason: "authorization_denied" },
      createdAt: "2026-10-23T12:01:00.000Z",
    };
    const events: ChainAuditEvent[] = [
      { ...firstPayload, previousHash: null, eventHash: firstHash },
      {
        ...secondPayload,
        previousHash: firstHash,
        eventHash: createAuditEventHash(secondPayload, firstHash),
      },
    ];
    expect(verifyAuditChain(events)).toBe(true);
    events[0].details.name = "changed";
    expect(verifyAuditChain(events)).toBe(false);
  });

  it("does not expose another owner's document through ID guessing or search", async () => {
    const { app, repository } = setup();
    const owner = await login(app, "owner-b@example.test");
    const created = await request(app).post("/api/documents")
      .set("Origin", config.appOrigin).set("Cookie", owner.cookie).set("X-CSRF-Token", owner.csrf)
      .send({ name: "private-plan", category: "planning" });
    expect(created.status).toBe(201);
    const documentId = created.body.document.id as number;

    const viewer = await login(app, "viewer@example.test");
    const read = await request(app).get(`/api/documents/${documentId}`).set("Cookie", viewer.cookie);
    expect(read.status).toBe(404);
    expect(read.body).toEqual({ error: "Document not found" });
    expect(JSON.stringify(read.body)).not.toContain("private-plan");

    const list = await request(app).get("/api/documents").set("Cookie", viewer.cookie);
    expect(list.status).toBe(200);
    expect(list.body.documents).toEqual([]);
    expect(repository.audit.some((event) =>
      event.action === "document.read" && event.outcome === "denied" &&
      event.actorUserId === 4 && event.details.requestedDocumentId === documentId,
    )).toBe(true);
  });

  it("uses the authenticated owner rather than forged owner or role fields", async () => {
    const { app } = setup();
    const owner = await login(app, "owner-a@example.test");
    const response = await request(app).post("/api/documents")
      .set("Origin", config.appOrigin).set("Cookie", owner.cookie).set("X-CSRF-Token", owner.csrf)
      .send({ name: "owned", category: "test", ownerId: 3, role: "admin" });
    expect(response.status).toBe(400);
  });

  it("denies viewer edits and deletes, and audits both attempts", async () => {
    const { app, repository } = setup();
    const owner = await login(app, "owner-a@example.test");
    const created = await request(app).post("/api/documents")
      .set("Origin", config.appOrigin).set("Cookie", owner.cookie).set("X-CSRF-Token", owner.csrf)
      .send({ name: "read-only", category: "test" });
    const id = created.body.document.id as number;
    await repository.grant(id, 2, "owner", 4, { canRead: true, canEdit: false });

    const viewer = await login(app, "viewer@example.test");
    const edit = await request(app).patch(`/api/documents/${id}`)
      .set("Origin", config.appOrigin).set("Cookie", viewer.cookie).set("X-CSRF-Token", viewer.csrf)
      .send({ name: "changed", category: "test" });
    const remove = await request(app).delete(`/api/documents/${id}`)
      .set("Origin", config.appOrigin).set("Cookie", viewer.cookie).set("X-CSRF-Token", viewer.csrf);
    expect(edit.status).toBe(404);
    expect(remove.status).toBe(404);
    expect(repository.audit.filter((event) =>
      event.actorUserId === 4 && event.outcome === "denied",
    ).map((event) => event.action)).toEqual(["document.edit", "document.delete"]);
  });

  it("applies a grant immediately and denies access on the first request after revocation", async () => {
    const { app, repository } = setup();
    const owner = await login(app, "owner-a@example.test");
    const created = await request(app).post("/api/documents")
      .set("Origin", config.appOrigin).set("Cookie", owner.cookie).set("X-CSRF-Token", owner.csrf)
      .send({ name: "grant-test", category: "test" });
    const id = created.body.document.id as number;
    const viewer = await login(app, "viewer@example.test");

    const grant = await request(app).put(`/api/documents/${id}/permissions/4`)
      .set("Origin", config.appOrigin).set("Cookie", owner.cookie).set("X-CSRF-Token", owner.csrf)
      .send({ canRead: true, canEdit: false });
    expect(grant.status).toBe(204);
    expect((await request(app).get(`/api/documents/${id}`).set("Cookie", viewer.cookie)).status).toBe(200);

    const revoke = await request(app).delete(`/api/documents/${id}/permissions/4`)
      .set("Origin", config.appOrigin).set("Cookie", owner.cookie).set("X-CSRF-Token", owner.csrf);
    expect(revoke.status).toBe(204);
    expect((await request(app).get(`/api/documents/${id}`).set("Cookie", viewer.cookie)).status).toBe(404);
    expect(repository.audit.some((event) => event.action === "permission.revoke" && event.outcome === "allowed")).toBe(true);
  });

  it("allows only explicit edit grants, never returns a storage URL or object key", async () => {
    const { app } = setup();
    const owner = await login(app, "owner-a@example.test");
    const created = await request(app).post("/api/documents")
      .set("Origin", config.appOrigin).set("Cookie", owner.cookie).set("X-CSRF-Token", owner.csrf)
      .send({ name: "edit-grant", category: "test" });
    const id = created.body.document.id as number;
    const viewer = await login(app, "viewer@example.test");
    await request(app).put(`/api/documents/${id}/permissions/4`)
      .set("Origin", config.appOrigin).set("Cookie", owner.cookie).set("X-CSRF-Token", owner.csrf)
      .send({ canRead: true, canEdit: true });

    const read = await request(app).get(`/api/documents/${id}`).set("Cookie", viewer.cookie);
    expect(read.status).toBe(200);
    expect(read.body.document.object_key).toBeUndefined();
    expect(read.body.document.url).toBeUndefined();
    const viewerEdit = await request(app).patch(`/api/documents/${id}`)
      .set("Origin", config.appOrigin).set("Cookie", viewer.cookie).set("X-CSRF-Token", viewer.csrf)
      .send({ name: "edited", category: "test" });
    expect(viewerEdit.status).toBe(404);

    const ownerB = await login(app, "owner-b@example.test");
    const grant = await request(app).put(`/api/documents/${id}/permissions/3`)
      .set("Origin", config.appOrigin).set("Cookie", owner.cookie).set("X-CSRF-Token", owner.csrf)
      .send({ canRead: true, canEdit: true });
    expect(grant.status).toBe(204);
    const ownerEdit = await request(app).patch(`/api/documents/${id}`)
      .set("Origin", config.appOrigin).set("Cookie", ownerB.cookie).set("X-CSRF-Token", ownerB.csrf)
      .send({ name: "edited", category: "test" });
    expect(ownerEdit.status).toBe(200);
    expect(ownerEdit.body.document.name).toBe("edited");
  });

  it("requires authenticated sessions and CSRF tokens for mutations", async () => {
    const { app } = setup();
    expect((await request(app).post("/api/documents")
      .set("Origin", config.appOrigin)
      .send({ name: "x", category: "x" })).status).toBe(401);
    const owner = await login(app, "owner-a@example.test");
    expect((await request(app).post("/api/documents")
      .set("Origin", config.appOrigin).set("Cookie", owner.cookie)
      .send({ name: "x", category: "x" })).status).toBe(403);
  });
});
