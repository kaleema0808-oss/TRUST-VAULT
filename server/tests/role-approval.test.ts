import request from "supertest";
import { beforeAll, describe, expect, it } from "vitest";
import { createApp } from "../src/app.js";
import type { AppConfig } from "../src/config.js";
import type {
  AuditInput,
  AuthRepository,
  AuthSession,
  AuthUser,
  CreateRoleRequestInput,
  DocumentInput,
  DocumentPermission,
  DocumentRecord,
  DocumentRepository,
  DocumentRole,
  RoleRequestRecord,
  RoleRequestRepository,
  RoleRequestStatus,
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

class RoleApprovalTestRepository implements AuthRepository, DocumentRepository, RoleRequestRepository {
  readonly users: AuthUser[] = [
    { id: 1, email: "admin@example.test", role: "admin", passwordHash: "" },
    { id: 2, email: "owner@example.test", role: "owner", passwordHash: "" },
    { id: 3, email: "viewer@example.test", role: "viewer", passwordHash: "" },
  ];
  readonly sessions = new Map<string, AuthSession>();
  readonly documents = new Map<number, DocumentRecord>();
  readonly grants = new Map<string, DocumentPermission>();
  readonly roleRequests: RoleRequestRecord[] = [];
  readonly audit: ChainAuditEvent[] = [];
  private nextDocId = 1;
  private nextReqId = 1;
  private nextUserId = 10;

  constructor() {
    for (const u of this.users) u.passwordHash = passwordHash;
  }

  // AuthRepository
  async findUserByEmail(email: string) {
    return this.users.find((u) => u.email === email) ?? null;
  }

  async findSession(tokenHash: string) {
    const session = this.sessions.get(tokenHash);
    if (!session || session.expiresAt.getTime() <= Date.now()) return null;
    const user = this.users.find((u) => u.id === session.userId);
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

  async createUser(email: string, passHash: string, role: import("../src/auth/repository.js").UserRole) {
    const user: AuthUser = { id: this.nextUserId++, email, passwordHash: passHash, role };
    this.users.push(user);
    return user;
  }

  async listUsers() {
    return this.users.map((u) => ({ id: u.id, email: u.email, role: u.role }));
  }

  // DocumentRepository
  async listAccessible(userId: number, role: DocumentRole): Promise<DocumentRecord[]> {
    return Array.from(this.documents.values()).filter((doc) => {
      if (role === "admin") return true;
      if (doc.ownerId === userId) return true;
      return this.grants.get(`${doc.id}:${userId}`)?.canRead ?? false;
    });
  }

  async getAccessible(documentId: number, userId: number, role: DocumentRole): Promise<DocumentRecord | null> {
    const doc = this.documents.get(documentId);
    if (!doc) return null;
    if (role === "admin" || doc.ownerId === userId || this.grants.get(`${documentId}:${userId}`)?.canRead) {
      return doc;
    }
    return null;
  }

  async create(userId: number, input: DocumentInput): Promise<DocumentRecord> {
    const doc: DocumentRecord = {
      id: this.nextDocId++,
      ownerId: userId,
      name: input.name,
      category: input.category,
      originalName: null,
      mimeType: null,
      fileSize: null,
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
    };
    this.documents.set(doc.id, doc);
    await this.appendAudit({
      actorUserId: userId,
      documentId: doc.id,
      action: "document.create",
      outcome: "allowed",
      details: { documentId: doc.id },
    });
    return doc;
  }

  async update(documentId: number, userId: number, role: DocumentRole, input: DocumentInput): Promise<DocumentRecord | null> {
    const doc = this.documents.get(documentId);
    if (!doc) return null;
    const canEdit = role === "admin" || (role === "owner" && doc.ownerId === userId) || this.grants.get(`${documentId}:${userId}`)?.canEdit;
    if (!canEdit) return null;
    doc.name = input.name;
    doc.category = input.category;
    doc.updatedAt = new Date().toISOString();
    await this.appendAudit({
      actorUserId: userId,
      documentId,
      action: "document.edit",
      outcome: "allowed",
      details: { documentId },
    });
    return doc;
  }

  async delete(documentId: number, userId: number, role: DocumentRole): Promise<boolean> {
    const doc = this.documents.get(documentId);
    if (!doc) return false;
    const canEdit = role === "admin" || (role === "owner" && doc.ownerId === userId) || this.grants.get(`${documentId}:${userId}`)?.canEdit;
    if (!canEdit) return false;
    this.documents.delete(documentId);
    await this.appendAudit({
      actorUserId: userId,
      documentId,
      action: "document.delete",
      outcome: "allowed",
      details: { documentId },
    });
    return true;
  }

  async grant(documentId: number, userId: number, role: DocumentRole, targetUserId: number, permission: DocumentPermission): Promise<boolean> {
    const doc = this.documents.get(documentId);
    if (!doc) return false;
    const canEdit = role === "admin" || (role === "owner" && doc.ownerId === userId) || this.grants.get(`${documentId}:${userId}`)?.canEdit;
    if (!canEdit) return false;
    this.grants.set(`${documentId}:${targetUserId}`, permission);
    await this.appendAudit({
      actorUserId: userId,
      documentId,
      action: "permission.grant",
      outcome: "allowed",
      details: { targetUserId, canRead: permission.canRead, canEdit: permission.canEdit },
    });
    return true;
  }

  async revoke(documentId: number, userId: number, role: DocumentRole, targetUserId: number): Promise<boolean> {
    const doc = this.documents.get(documentId);
    if (!doc) return false;
    const canEdit = role === "admin" || (role === "owner" && doc.ownerId === userId) || this.grants.get(`${documentId}:${userId}`)?.canEdit;
    if (!canEdit) return false;
    this.grants.delete(`${documentId}:${targetUserId}`);
    await this.appendAudit({
      actorUserId: userId,
      documentId,
      action: "permission.revoke",
      outcome: "allowed",
      details: { targetUserId },
    });
    return true;
  }

  async listPermissions(): Promise<never[]> { return []; }
  async updateFileMetadata(): Promise<boolean> { return true; }
  async getObjectKeyForDownload(): Promise<null> { return null; }

  // RoleRequestRepository
  async createRoleRequest(input: CreateRoleRequestInput): Promise<RoleRequestRecord> {
    const user = this.users.find((u) => u.id === input.userId);
    if (!user) throw new Error("User not found");
    if (user.role !== "viewer") throw new Error("Only viewers can request owner privileges");

    const existing = this.roleRequests.find((r) => r.userId === input.userId && r.status === "pending");
    if (existing) {
      const err = new Error("A pending owner request already exists for this account");
      (err as { code?: string }).code = "DUPLICATE_PENDING_REQUEST";
      throw err;
    }

    const rec: RoleRequestRecord = {
      id: this.nextReqId++,
      userId: input.userId,
      userEmail: user.email,
      requestedRole: "owner",
      status: "pending",
      reason: input.reason ?? null,
      reviewedBy: null,
      reviewedByEmail: null,
      reviewedAt: null,
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
    };
    this.roleRequests.push(rec);

    await this.appendAudit({
      actorUserId: input.userId,
      documentId: null,
      action: "role_request.create",
      outcome: "allowed",
      details: { targetUserId: input.userId, requestedRole: input.requestedRole, reason: input.reason ?? null, requestId: rec.id },
    });

    return rec;
  }

  async findPendingByUserId(userId: number): Promise<RoleRequestRecord | null> {
    return this.roleRequests.find((r) => r.userId === userId && r.status === "pending") ?? null;
  }

  async getById(id: number): Promise<RoleRequestRecord | null> {
    return this.roleRequests.find((r) => r.id === id) ?? null;
  }

  async listRoleRequests(status?: RoleRequestStatus): Promise<RoleRequestRecord[]> {
    if (status) return this.roleRequests.filter((r) => r.status === status);
    return [...this.roleRequests];
  }

  async approveRoleRequest(requestId: number, adminUserId: number): Promise<{ success: boolean; error?: string; request?: RoleRequestRecord }> {
    const req = this.roleRequests.find((r) => r.id === requestId);
    if (!req) return { success: false, error: "Role request not found" };
    if (req.status !== "pending") return { success: false, error: "Role request is not pending" };

    const targetUser = this.users.find((u) => u.id === req.userId);
    if (!targetUser) return { success: false, error: "Target user not found" };
    if (targetUser.role === "admin") return { success: false, error: "Cannot modify role of an administrator" };

    req.status = "approved";
    req.reviewedBy = adminUserId;
    const adminUser = this.users.find((u) => u.id === adminUserId);
    req.reviewedByEmail = adminUser?.email ?? null;
    req.reviewedAt = new Date().toISOString();
    req.updatedAt = req.reviewedAt;

    const previousRole = targetUser.role;
    targetUser.role = "owner";

    await this.appendAudit({
      actorUserId: adminUserId,
      documentId: null,
      action: "role_request.approve",
      outcome: "allowed",
      details: { requestId, targetUserId: targetUser.id, targetEmail: targetUser.email, requestedRole: "owner" },
    });

    await this.appendAudit({
      actorUserId: adminUserId,
      documentId: null,
      action: "user.role_change",
      outcome: "allowed",
      details: { targetUserId: targetUser.id, targetEmail: targetUser.email, previousRole, newRole: "owner", requestId },
    });

    return { success: true, request: req };
  }

  async rejectRoleRequest(requestId: number, adminUserId: number, reason?: string): Promise<{ success: boolean; error?: string; request?: RoleRequestRecord }> {
    const req = this.roleRequests.find((r) => r.id === requestId);
    if (!req) return { success: false, error: "Role request not found" };
    if (req.status !== "pending") return { success: false, error: "Role request is not pending" };

    req.status = "rejected";
    req.reviewedBy = adminUserId;
    const adminUser = this.users.find((u) => u.id === adminUserId);
    req.reviewedByEmail = adminUser?.email ?? null;
    req.reviewedAt = new Date().toISOString();
    req.updatedAt = req.reviewedAt;
    if (reason) req.reason = reason;

    await this.appendAudit({
      actorUserId: adminUserId,
      documentId: null,
      action: "role_request.reject",
      outcome: "allowed",
      details: { requestId, targetUserId: req.userId, targetEmail: req.userEmail, requestedRole: "owner", reason: reason ?? null },
    });

    return { success: true, request: req };
  }

  // Audit
  async appendAudit(event: AuditInput): Promise<void> {
    const previousHash = this.audit.length > 0 ? this.audit[this.audit.length - 1].eventHash : null;
    const createdAt = new Date().toISOString();
    const eventHash = createAuditEventHash({
      actorUserId: event.actorUserId,
      documentId: event.documentId,
      action: event.action,
      outcome: event.outcome,
      details: event.details,
      createdAt,
    }, previousHash);
    this.audit.push({
      actorUserId: event.actorUserId,
      documentId: event.documentId,
      action: event.action,
      outcome: event.outcome,
      details: event.details,
      createdAt,
      previousHash,
      eventHash,
    });
  }

  async listAuditEvents(): Promise<any[]> {
    return this.audit.map((e, idx) => ({
      id: idx + 1,
      actorUserId: e.actorUserId,
      documentId: e.documentId,
      action: e.action,
      outcome: e.outcome,
      details: e.details,
      createdAt: e.createdAt,
    }));
  }
}

async function loginUser(app: any, email: string) {
  const res = await request(app)
    .post("/api/auth/login")
    .set("Origin", config.appOrigin)
    .send({ email, password });
  expect(res.status).toBe(200);
  const cookie = res.headers["set-cookie"]?.[0]?.split(";")[0] ?? "";
  const csrf = res.body.csrfToken as string;
  return { cookie, csrf, user: res.body.user };
}

describe("Admin approval workflow for Owner access", () => {
  it("denies owner privileges to new users registered with pending request, and audits denied attempts", async () => {
    const repo = new RoleApprovalTestRepository();
    const app = createApp(repo, config, async () => {}, repo, repo);

    // 1. Register with requestOwner: true
    const regRes = await request(app)
      .post("/api/auth/register")
      .set("Origin", config.appOrigin)
      .send({
        email: "applicant@example.test",
        password: "applicant-password-123",
        requestOwner: true,
        reason: "Need to upload project files",
      });

    expect(regRes.status).toBe(201);
    expect(regRes.body.user.role).toBe("viewer"); // MUST be viewer, not owner
    expect(regRes.body.pendingRoleRequest).toBe(true);

    const cookie = regRes.headers["set-cookie"]?.[0]?.split(";")[0] ?? "";
    const csrf = regRes.body.csrfToken;

    // 2. Pending request exists
    const pendingReq = await repo.findPendingByUserId(regRes.body.user.id);
    expect(pendingReq).not.toBeNull();
    expect(pendingReq?.status).toBe("pending");
    expect(pendingReq?.requestedRole).toBe("owner");

    // 3. User attempts owner-protected action (creating document) while pending
    const createDocRes = await request(app)
      .post("/api/documents")
      .set("Origin", config.appOrigin)
      .set("Cookie", cookie)
      .set("X-CSRF-Token", csrf)
      .send({ name: "Secret Plan", category: "Confidential" });

    // Must be rejected with 403 Forbidden
    expect(createDocRes.status).toBe(403);
    expect(createDocRes.body.error).toBe("Forbidden");

    // 4. Denied attempt must be recorded in audit log
    const deniedEvent = repo.audit.find(
      (e) => e.actorUserId === regRes.body.user.id && e.action === "document.create" && e.outcome === "denied",
    );
    expect(deniedEvent).toBeDefined();
  });

  it("never trusts client-supplied role parameters on registration", async () => {
    const repo = new RoleApprovalTestRepository();
    const app = createApp(repo, config, async () => {}, repo, repo);

    // Client passes role: "owner" or "admin" directly
    const res = await request(app)
      .post("/api/auth/register")
      .set("Origin", config.appOrigin)
      .send({
        email: "hacker@example.test",
        password: "hacker-password-123",
        role: "admin",
      });

    // Zod strict validation rejects unexpected fields
    expect(res.status).toBe(400);

    // User is never created with admin role
    const found = await repo.findUserByEmail("hacker@example.test");
    expect(found).toBeNull();
  });

  it("prevents duplicate pending requests and audits duplicate attempt", async () => {
    const repo = new RoleApprovalTestRepository();
    const app = createApp(repo, config, async () => {}, repo, repo);

    const viewer = await loginUser(app, "viewer@example.test");

    // Submit first owner request
    const firstReq = await request(app)
      .post("/api/auth/role-requests")
      .set("Origin", config.appOrigin)
      .set("Cookie", viewer.cookie)
      .set("X-CSRF-Token", viewer.csrf)
      .send({ reason: "First request" });

    expect(firstReq.status).toBe(201);
    expect(firstReq.body.request.status).toBe("pending");

    // Submit second owner request while first is pending
    const secondReq = await request(app)
      .post("/api/auth/role-requests")
      .set("Origin", config.appOrigin)
      .set("Cookie", viewer.cookie)
      .set("X-CSRF-Token", viewer.csrf)
      .send({ reason: "Duplicate request" });

    expect(secondReq.status).toBe(409);
    expect(secondReq.body.error).toMatch(/pending owner request already exists/i);

    // Verify duplicate denial was recorded in audit log
    const duplicateAudit = repo.audit.find(
      (e) => e.actorUserId === 3 && e.action === "role_request.create" && e.outcome === "denied",
    );
    expect(duplicateAudit).toBeDefined();
    expect(duplicateAudit?.details.reason).toBe("duplicate_request");
  });

  it("rejects unauthorized approval attempts from viewers and owners, and audits the denial", async () => {
    const repo = new RoleApprovalTestRepository();
    const app = createApp(repo, config, async () => {}, repo, repo);

    // Create a pending request for viewer
    const roleReq = await repo.createRoleRequest({ userId: 3, requestedRole: "owner", reason: "Test" });

    // Viewer attempts to approve their own request
    const viewer = await loginUser(app, "viewer@example.test");
    const viewerApproveRes = await request(app)
      .post(`/api/admin/role-requests/${roleReq.id}/approve`)
      .set("Origin", config.appOrigin)
      .set("Cookie", viewer.cookie)
      .set("X-CSRF-Token", viewer.csrf);

    expect(viewerApproveRes.status).toBe(403);

    // Owner attempts to approve the request
    const owner = await loginUser(app, "owner@example.test");
    const ownerApproveRes = await request(app)
      .post(`/api/admin/role-requests/${roleReq.id}/approve`)
      .set("Origin", config.appOrigin)
      .set("Cookie", owner.cookie)
      .set("X-CSRF-Token", owner.csrf);

    expect(ownerApproveRes.status).toBe(403);

    // Verify denied audit events were recorded with actor ID and action
    const viewerDenial = repo.audit.find(
      (e) => e.actorUserId === 3 && e.action === "role_request.approve" && e.outcome === "denied",
    );
    expect(viewerDenial).toBeDefined();

    const ownerDenial = repo.audit.find(
      (e) => e.actorUserId === 2 && e.action === "role_request.approve" && e.outcome === "denied",
    );
    expect(ownerDenial).toBeDefined();

    // The request status must remain pending
    const current = await repo.getById(roleReq.id);
    expect(current?.status).toBe("pending");
  });

  it("successfully approves a role request, elevates role, enables owner actions, and records full audit trail", async () => {
    const repo = new RoleApprovalTestRepository();
    const app = createApp(repo, config, async () => {}, repo, repo);

    const roleReq = await repo.createRoleRequest({ userId: 3, requestedRole: "owner", reason: "Ready to upload" });
    const admin = await loginUser(app, "admin@example.test");

    // Admin lists role requests
    const listRes = await request(app)
      .get("/api/admin/role-requests")
      .set("Origin", config.appOrigin)
      .set("Cookie", admin.cookie);

    expect(listRes.status).toBe(200);
    expect(listRes.body.requests).toHaveLength(1);
    expect(listRes.body.requests[0].id).toBe(roleReq.id);

    // Admin approves the request
    const approveRes = await request(app)
      .post(`/api/admin/role-requests/${roleReq.id}/approve`)
      .set("Origin", config.appOrigin)
      .set("Cookie", admin.cookie)
      .set("X-CSRF-Token", admin.csrf);

    expect(approveRes.status).toBe(200);
    expect(approveRes.body.request.status).toBe("approved");

    // Target user's role is now owner
    const targetUser = await repo.findUserByEmail("viewer@example.test");
    expect(targetUser?.role).toBe("owner");

    // User can now perform owner action (document creation)
    const newlyPromoted = await loginUser(app, "viewer@example.test");
    expect(newlyPromoted.user.role).toBe("owner");

    const createDocRes = await request(app)
      .post("/api/documents")
      .set("Origin", config.appOrigin)
      .set("Cookie", newlyPromoted.cookie)
      .set("X-CSRF-Token", newlyPromoted.csrf)
      .send({ name: "Project Alpha", category: "Reports" });

    expect(createDocRes.status).toBe(201);
    expect(createDocRes.body.document.name).toBe("Project Alpha");

    // Audit trail must contain role_request.approve and user.role_change events
    const approveEvent = repo.audit.find((e) => e.action === "role_request.approve" && e.outcome === "allowed");
    expect(approveEvent).toBeDefined();
    expect(approveEvent?.actorUserId).toBe(1); // Admin
    expect(approveEvent?.details.targetUserId).toBe(3);

    const roleChangeEvent = repo.audit.find((e) => e.action === "user.role_change" && e.outcome === "allowed");
    expect(roleChangeEvent).toBeDefined();
    expect(roleChangeEvent?.actorUserId).toBe(1);
    expect(roleChangeEvent?.details.targetUserId).toBe(3);
    expect(roleChangeEvent?.details.previousRole).toBe("viewer");
    expect(roleChangeEvent?.details.newRole).toBe("owner");
  });

  it("handles rejection correctly without elevating role and records rejection in audit log", async () => {
    const repo = new RoleApprovalTestRepository();
    const app = createApp(repo, config, async () => {}, repo, repo);

    const roleReq = await repo.createRoleRequest({ userId: 3, requestedRole: "owner", reason: "Please promote me" });
    const admin = await loginUser(app, "admin@example.test");

    const rejectRes = await request(app)
      .post(`/api/admin/role-requests/${roleReq.id}/reject`)
      .set("Origin", config.appOrigin)
      .set("Cookie", admin.cookie)
      .set("X-CSRF-Token", admin.csrf)
      .send({ reason: "Insufficient team justification" });

    expect(rejectRes.status).toBe(200);
    expect(rejectRes.body.request.status).toBe("rejected");

    // Target user remains viewer
    const user = await repo.findUserByEmail("viewer@example.test");
    expect(user?.role).toBe("viewer");

    // Audit trail records rejection
    const rejectEvent = repo.audit.find((e) => e.action === "role_request.reject" && e.outcome === "allowed");
    expect(rejectEvent).toBeDefined();
    expect(rejectEvent?.actorUserId).toBe(1);
    expect(rejectEvent?.details.targetUserId).toBe(3);
    expect(rejectEvent?.details.reason).toBe("Insufficient team justification");
  });

  it("protects existing Admin accounts from demotion", async () => {
    const repo = new RoleApprovalTestRepository();
    const app = createApp(repo, config, async () => {}, repo, repo);

    // Synthesize a role request for an admin user (id 1)
    const adminReq: RoleRequestRecord = {
      id: 99,
      userId: 1, // Admin user
      userEmail: "admin@example.test",
      requestedRole: "owner",
      status: "pending",
      reason: null,
      reviewedBy: null,
      reviewedByEmail: null,
      reviewedAt: null,
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
    };
    repo.roleRequests.push(adminReq);

    const admin = await loginUser(app, "admin@example.test");

    // Attempt to approve
    const approveRes = await request(app)
      .post(`/api/admin/role-requests/${adminReq.id}/approve`)
      .set("Origin", config.appOrigin)
      .set("Cookie", admin.cookie)
      .set("X-CSRF-Token", admin.csrf);

    expect(approveRes.status).toBe(400);
    expect(approveRes.body.error).toMatch(/cannot modify role of an administrator/i);

    // Admin account must not be demoted
    const adminUser = await repo.findUserByEmail("admin@example.test");
    expect(adminUser?.role).toBe("admin");
  });

  it("maintains an unbroken cryptographic hash chain across all role approval events", async () => {
    const repo = new RoleApprovalTestRepository();
    const app = createApp(repo, config, async () => {}, repo, repo);

    const admin = await loginUser(app, "admin@example.test");

    // 1. Create request
    const req1 = await repo.createRoleRequest({ userId: 3, requestedRole: "owner" });

    // 2. Reject request
    await request(app)
      .post(`/api/admin/role-requests/${req1.id}/reject`)
      .set("Origin", config.appOrigin)
      .set("Cookie", admin.cookie)
      .set("X-CSRF-Token", admin.csrf)
      .send({ reason: "Not yet" });

    // 3. Create second request
    const req2 = await repo.createRoleRequest({ userId: 3, requestedRole: "owner", reason: "Second try" });

    // 4. Approve request
    await request(app)
      .post(`/api/admin/role-requests/${req2.id}/approve`)
      .set("Origin", config.appOrigin)
      .set("Cookie", admin.cookie)
      .set("X-CSRF-Token", admin.csrf);

    // 5. Verify the entire cryptographic audit hash chain
    expect(repo.audit.length).toBeGreaterThanOrEqual(5);
    const valid = verifyAuditChain(repo.audit);
    expect(valid).toBe(true);
  });
});
