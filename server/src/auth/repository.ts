import type { RowDataPacket } from "mysql2";
import type { Pool } from "mysql2/promise";
import { randomUUID } from "node:crypto";
import { createAuditEventHash } from "../security/audit-chain.js";

export type UserRole = "admin" | "owner" | "viewer";
export type AuthUser = { id: number; email: string; role: UserRole; passwordHash?: string };
export type AuthSession = {
  tokenHash: string;
  userId: number;
  csrfTokenHash: string;
  expiresAt: Date;
};
export type DocumentRole = "admin" | "owner" | "viewer";
export type DocumentRecord = {
  id: number;
  ownerId: number;
  name: string;
  category: string;
  createdAt: string;
  updatedAt: string;
};
export type DocumentInput = { name: string; category: string };
export type AuditInput = {
  actorUserId: number | null;
  documentId: number | null;
  action: string;
  outcome: "allowed" | "denied";
  details: Record<string, unknown>;
};
export type DocumentPermission = {
  canRead: boolean;
  canEdit: boolean;
};

export interface AuthRepository {
  findUserByEmail(email: string): Promise<AuthUser | null>;
  findSession(tokenHash: string): Promise<{ session: AuthSession; user: AuthUser } | null>;
  createSession(session: AuthSession): Promise<void>;
  updateCsrfToken(tokenHash: string, csrfTokenHash: string): Promise<void>;
  deleteSession(tokenHash: string): Promise<void>;
  createUser(email: string, passwordHash: string, role: UserRole): Promise<AuthUser>;
  listUsers(): Promise<AuthUser[]>;
}

export interface DocumentRepository {
  listAccessible(userId: number, role: DocumentRole): Promise<DocumentRecord[]>;
  getAccessible(documentId: number, userId: number, role: DocumentRole): Promise<DocumentRecord | null>;
  create(userId: number, input: DocumentInput): Promise<DocumentRecord>;
  update(documentId: number, userId: number, role: DocumentRole, input: DocumentInput): Promise<DocumentRecord | null>;
  delete(documentId: number, userId: number, role: DocumentRole): Promise<boolean>;
  grant(documentId: number, userId: number, role: DocumentRole, targetUserId: number, permission: DocumentPermission): Promise<boolean>;
  revoke(documentId: number, userId: number, role: DocumentRole, targetUserId: number): Promise<boolean>;
  appendAudit(event: AuditInput): Promise<void>;
  listAuditEvents(filters: AuditFilter): Promise<AuditEvent[]>;
  listPermissions(documentId: number, userId: number, role: DocumentRole): Promise<PermissionRecord[]>;
}

export type AuditFilter = {
  actorUserId?: number;
  action?: string;
  outcome?: "allowed" | "denied";
  documentId?: number;
  limit?: number;
  offset?: number;
};

export type AuditEvent = {
  id: number;
  actorUserId: number | null;
  actorEmail?: string;
  documentId: number | null;
  action: string;
  outcome: "allowed" | "denied";
  details: Record<string, unknown>;
  createdAt: string;
};

export type PermissionRecord = {
  userId: number;
  email: string;
  canRead: boolean;
  canEdit: boolean;
  grantedBy: number;
};

type UserRow = RowDataPacket & { id: number; email: string; role: UserRole; password_hash: string };
type SessionRow = UserRow & {
  token_hash: string;
  user_id: number;
  csrf_token_hash: string;
  expires_at: Date;
};

export class MysqlAuthRepository implements AuthRepository {
  constructor(private readonly pool: Pool) {}

  async findUserByEmail(email: string): Promise<AuthUser | null> {
    const [rows] = await this.pool.execute<UserRow[]>(
      "SELECT id, email, role, password_hash FROM users WHERE email = ? LIMIT 1",
      [email],
    );
    const row = rows[0];
    return row ? { id: row.id, email: row.email, role: row.role, passwordHash: row.password_hash } : null;
  }

  async findSession(tokenHash: string): Promise<{ session: AuthSession; user: AuthUser } | null> {
    const [rows] = await this.pool.execute<SessionRow[]>(
      `SELECT s.token_hash, s.user_id, s.csrf_token_hash, s.expires_at,
              u.id, u.email, u.role, u.password_hash
       FROM sessions s JOIN users u ON u.id = s.user_id
       WHERE s.token_hash = ? AND s.expires_at > CURRENT_TIMESTAMP(3) LIMIT 1`,
      [tokenHash],
    );
    const row = rows[0];
    return row ? {
      session: {
        tokenHash: row.token_hash,
        userId: row.user_id,
        csrfTokenHash: row.csrf_token_hash,
        expiresAt: row.expires_at,
      },
      user: { id: row.id, email: row.email, role: row.role },
    } : null;
  }

  async createSession(session: AuthSession): Promise<void> {
    await this.pool.execute(
      "INSERT INTO sessions (token_hash, user_id, csrf_token_hash, expires_at) VALUES (?, ?, ?, ?)",
      [session.tokenHash, session.userId, session.csrfTokenHash, session.expiresAt],
    );
  }

  async updateCsrfToken(tokenHash: string, csrfTokenHash: string): Promise<void> {
    await this.pool.execute("UPDATE sessions SET csrf_token_hash = ? WHERE token_hash = ?", [csrfTokenHash, tokenHash]);
  }

  async deleteSession(tokenHash: string): Promise<void> {
    await this.pool.execute("DELETE FROM sessions WHERE token_hash = ?", [tokenHash]);
  }

  async createUser(email: string, passwordHash: string, role: UserRole): Promise<AuthUser> {
    const [result] = await this.pool.execute<import("mysql2").ResultSetHeader>(
      "INSERT INTO users (email, password_hash, role) VALUES (?, ?, ?)",
      [email, passwordHash, role],
    );
    return { id: result.insertId, email, role };
  }

  async listUsers(): Promise<AuthUser[]> {
    const [rows] = await this.pool.execute<UserRow[]>(
      "SELECT id, email, role FROM users ORDER BY email ASC",
    );
    return rows.map((row) => ({ id: row.id, email: row.email, role: row.role }));
  }
}

type DocumentRow = RowDataPacket & {
  id: number;
  owner_id: number;
  name: string;
  category: string;
  created_at: Date;
  updated_at: Date;
};

function toDocument(row: DocumentRow): DocumentRecord {
  return {
    id: row.id,
    ownerId: row.owner_id,
    name: row.name,
    category: row.category,
    createdAt: row.created_at.toISOString(),
    updatedAt: row.updated_at.toISOString(),
  };
}

const readPermissionSql = `(
  ? = 'admin'
  OR d.owner_id = ?
  OR EXISTS (
    SELECT 1 FROM document_permissions p
    WHERE p.document_id = d.id AND p.user_id = ? AND p.can_read = TRUE
  )
)`;
const editPermissionSql = `(
  ? = 'admin'
  OR (
    ? = 'owner'
    AND (
      d.owner_id = ?
      OR EXISTS (
        SELECT 1 FROM document_permissions p
        WHERE p.document_id = d.id AND p.user_id = ? AND p.can_edit = TRUE
      )
    )
  )
)`;

export class MysqlDocumentRepository implements DocumentRepository {
  constructor(private readonly pool: Pool) {}

  async listAccessible(userId: number, role: DocumentRole): Promise<DocumentRecord[]> {
    const [rows] = await this.pool.execute<DocumentRow[]>(
      `SELECT d.id, d.owner_id, d.name, d.category, d.created_at, d.updated_at
       FROM documents d WHERE ${readPermissionSql}
       ORDER BY d.created_at DESC, d.id DESC`,
      [role, userId, userId],
    );
    return rows.map(toDocument);
  }

  async getAccessible(documentId: number, userId: number, role: DocumentRole): Promise<DocumentRecord | null> {
    const [rows] = await this.pool.execute<DocumentRow[]>(
      `SELECT d.id, d.owner_id, d.name, d.category, d.created_at, d.updated_at
       FROM documents d WHERE d.id = ? AND ${readPermissionSql} LIMIT 1`,
      [documentId, role, userId, userId],
    );
    return rows[0] ? toDocument(rows[0]) : null;
  }

  async create(userId: number, input: DocumentInput): Promise<DocumentRecord> {
    const connection = await this.pool.getConnection();
    try {
      await connection.beginTransaction();
      const [result] = await connection.execute(
        "INSERT INTO documents (owner_id, name, category, object_key) VALUES (?, ?, ?, ?)",
        [userId, input.name, input.category, `pending-${randomUUID()}`],
      );
      const insertId = (result as { insertId: number }).insertId;
      const [rows] = await connection.execute<DocumentRow[]>(
        "SELECT id, owner_id, name, category, created_at, updated_at FROM documents WHERE id = ?",
        [insertId],
      );
      const record = rows[0];
      if (!record) throw new Error("Created document could not be retrieved");
      await this.appendAuditWithConnection(connection, {
        actorUserId: userId,
        documentId: record.id,
        action: "document.create",
        outcome: "allowed",
        details: { documentId: record.id },
      });
      await connection.commit();
      return toDocument(record);
    } catch (error) {
      await connection.rollback();
      throw error;
    } finally {
      connection.release();
    }
  }

  async update(documentId: number, userId: number, role: DocumentRole, input: DocumentInput): Promise<DocumentRecord | null> {
    const connection = await this.pool.getConnection();
    try {
      await connection.beginTransaction();
      const [updateResult] = await connection.execute(
        `UPDATE documents d SET name = ?, category = ?
         WHERE d.id = ? AND ${editPermissionSql}`,
        [input.name, input.category, documentId, role, role, userId, userId],
      );
      if ((updateResult as { affectedRows: number }).affectedRows === 0) {
        await connection.rollback();
        return null;
      }
      const [rows] = await connection.execute<DocumentRow[]>(
        "SELECT id, owner_id, name, category, created_at, updated_at FROM documents WHERE id = ?",
        [documentId],
      );
      const record = rows[0];
      if (!record) throw new Error("Updated document could not be retrieved");
      await this.appendAuditWithConnection(connection, {
        actorUserId: userId,
        documentId,
        action: "document.edit",
        outcome: "allowed",
        details: { documentId },
      });
      await connection.commit();
      return toDocument(record);
    } catch (error) {
      await connection.rollback();
      throw error;
    } finally {
      connection.release();
    }
  }

  async delete(documentId: number, userId: number, role: DocumentRole): Promise<boolean> {
    const connection = await this.pool.getConnection();
    try {
      await connection.beginTransaction();
      const [rows] = await connection.execute<RowDataPacket[]>(
        `SELECT d.id FROM documents d WHERE d.id = ? AND ${editPermissionSql} FOR UPDATE`,
        [documentId, role, role, userId, userId],
      );
      if (rows.length === 0) {
        await connection.rollback();
        return false;
      }
      await this.appendAuditWithConnection(connection, {
        actorUserId: userId,
        documentId,
        action: "document.delete",
        outcome: "allowed",
        details: { documentId },
      });
      await connection.execute("DELETE FROM documents WHERE id = ?", [documentId]);
      await connection.commit();
      return true;
    } catch (error) {
      await connection.rollback();
      throw error;
    } finally {
      connection.release();
    }
  }

  async grant(
    documentId: number,
    userId: number,
    role: DocumentRole,
    targetUserId: number,
    permission: DocumentPermission,
  ): Promise<boolean> {
    const connection = await this.pool.getConnection();
    try {
      await connection.beginTransaction();
      const [rows] = await connection.execute<RowDataPacket[]>(
        `SELECT d.id FROM documents d WHERE d.id = ? AND ${editPermissionSql} FOR UPDATE`,
        [documentId, role, role, userId, userId],
      );
      if (rows.length === 0) {
        await connection.rollback();
        return false;
      }
      const [targetRows] = await connection.execute<RowDataPacket[]>(
        "SELECT id FROM users WHERE id = ? FOR UPDATE",
        [targetUserId],
      );
      if (targetRows.length === 0) {
        await connection.rollback();
        return false;
      }
      await connection.execute(
        `INSERT INTO document_permissions (document_id, user_id, can_read, can_edit, granted_by)
         VALUES (?, ?, ?, ?, ?)
         ON DUPLICATE KEY UPDATE can_read = VALUES(can_read), can_edit = VALUES(can_edit), granted_by = VALUES(granted_by)`,
        [documentId, targetUserId, permission.canRead, permission.canEdit, userId],
      );
      await this.appendAuditWithConnection(connection, {
        actorUserId: userId,
        documentId,
        action: "permission.grant",
        outcome: "allowed",
        details: { targetUserId, canRead: permission.canRead, canEdit: permission.canEdit },
      });
      await connection.commit();
      return true;
    } catch (error) {
      await connection.rollback();
      throw error;
    } finally {
      connection.release();
    }
  }

  async revoke(documentId: number, userId: number, role: DocumentRole, targetUserId: number): Promise<boolean> {
    const connection = await this.pool.getConnection();
    try {
      await connection.beginTransaction();
      const [rows] = await connection.execute<RowDataPacket[]>(
        `SELECT d.id FROM documents d WHERE d.id = ? AND ${editPermissionSql} FOR UPDATE`,
        [documentId, role, role, userId, userId],
      );
      if (rows.length === 0) {
        await connection.rollback();
        return false;
      }
      await connection.execute(
        "DELETE FROM document_permissions WHERE document_id = ? AND user_id = ?",
        [documentId, targetUserId],
      );
      await this.appendAuditWithConnection(connection, {
        actorUserId: userId,
        documentId,
        action: "permission.revoke",
        outcome: "allowed",
        details: { targetUserId },
      });
      await connection.commit();
      return true;
    } catch (error) {
      await connection.rollback();
      throw error;
    } finally {
      connection.release();
    }
  }

  async listPermissions(documentId: number, userId: number, role: DocumentRole): Promise<PermissionRecord[]> {
    // Verify the actor has read access to the document first
    const doc = await this.getAccessible(documentId, userId, role);
    if (!doc) return [];
    const [rows] = await this.pool.execute<(RowDataPacket & {
      user_id: number; email: string; can_read: number; can_edit: number; granted_by: number;
    })[]>(
      `SELECT p.user_id, u.email, p.can_read, p.can_edit, p.granted_by
       FROM document_permissions p JOIN users u ON u.id = p.user_id
       WHERE p.document_id = ?
       ORDER BY u.email ASC`,
      [documentId],
    );
    return rows.map((row) => ({
      userId: row.user_id,
      email: row.email,
      canRead: Boolean(row.can_read),
      canEdit: Boolean(row.can_edit),
      grantedBy: row.granted_by,
    }));
  }

  async listAuditEvents(filters: AuditFilter): Promise<AuditEvent[]> {
    const conditions: string[] = [];
    const params: unknown[] = [];
    if (filters.actorUserId !== undefined) {
      conditions.push("a.actor_user_id = ?");
      params.push(filters.actorUserId);
    }
    if (filters.action) {
      conditions.push("a.action = ?");
      params.push(filters.action);
    }
    if (filters.outcome) {
      conditions.push("a.outcome = ?");
      params.push(filters.outcome);
    }
    if (filters.documentId !== undefined) {
      conditions.push("a.document_id = ?");
      params.push(filters.documentId);
    }
    const where = conditions.length > 0 ? `WHERE ${conditions.join(" AND ")}` : "";
    const limit = Math.min(filters.limit ?? 50, 200);
    const offset = filters.offset ?? 0;
    params.push(limit, offset);

    // mysql2 execute requires explicit cast when params is built dynamically
    const [rows] = await this.pool.execute<(RowDataPacket & {
      id: number; actor_user_id: number | null; actor_email: string | null;
      document_id: number | null; action: string; outcome: "allowed" | "denied";
      details: string; created_at: Date;
    })[]>(
      `SELECT a.id, a.actor_user_id, u.email AS actor_email, a.document_id,
              a.action, a.outcome, a.details, a.created_at
       FROM audit_events a
       LEFT JOIN users u ON u.id = a.actor_user_id
       ${where}
       ORDER BY a.id DESC
       LIMIT ? OFFSET ?`,
      params as import("mysql2").ExecuteValues[],
    );
    return rows.map((row) => ({
      id: row.id,
      actorUserId: row.actor_user_id,
      actorEmail: row.actor_email ?? undefined,
      documentId: row.document_id,
      action: row.action,
      outcome: row.outcome,
      details: typeof row.details === "string" ? JSON.parse(row.details) : row.details,
      createdAt: row.created_at.toISOString(),
    }));
  }

  async appendAudit(event: AuditInput): Promise<void> {
    const connection = await this.pool.getConnection();
    try {
      await connection.beginTransaction();
      await this.appendAuditWithConnection(connection, event);
      await connection.commit();
    } catch (error) {
      await connection.rollback();
      throw error;
    } finally {
      connection.release();
    }
  }

  private async appendAuditWithConnection(
    connection: import("mysql2/promise").PoolConnection,
    event: AuditInput,
  ): Promise<void> {
    const [rows] = await connection.execute<RowDataPacket[]>(
      "SELECT event_hash FROM audit_events ORDER BY id DESC LIMIT 1 FOR UPDATE",
    );
    const previousHash = (rows[0]?.event_hash as string | null | undefined) ?? null;
    const createdAtDate = new Date();
    const createdAt = createdAtDate.toISOString();
    const detailsJson = JSON.stringify(event.details);
    const eventHash = createAuditEventHash({
      actorUserId: event.actorUserId,
      documentId: event.documentId,
      action: event.action,
      outcome: event.outcome,
      details: event.details,
      createdAt,
    }, previousHash);
    await connection.execute(
      `INSERT INTO audit_events
        (actor_user_id, document_id, action, outcome, details, previous_hash, event_hash, created_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
      [event.actorUserId, event.documentId, event.action, event.outcome, detailsJson, previousHash, eventHash, createdAtDate],
    );
  }
}
