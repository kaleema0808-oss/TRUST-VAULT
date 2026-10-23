import type { RowDataPacket } from "mysql2";
import type { Pool } from "mysql2/promise";

export type UserRole = "admin" | "owner" | "viewer";
export type AuthUser = { id: number; email: string; role: UserRole; passwordHash?: string };
export type AuthSession = {
  tokenHash: string;
  userId: number;
  csrfTokenHash: string;
  expiresAt: Date;
};

export interface AuthRepository {
  findUserByEmail(email: string): Promise<AuthUser | null>;
  findSession(tokenHash: string): Promise<{ session: AuthSession; user: AuthUser } | null>;
  createSession(session: AuthSession): Promise<void>;
  updateCsrfToken(tokenHash: string, csrfTokenHash: string): Promise<void>;
  deleteSession(tokenHash: string): Promise<void>;
}

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
}
