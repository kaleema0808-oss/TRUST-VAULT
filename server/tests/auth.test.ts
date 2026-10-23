import { createHash } from "node:crypto";
import express from "express";
import request from "supertest";
import { afterEach, describe, expect, it } from "vitest";
import { createApp } from "../src/app.js";
import type { AppConfig } from "../src/config.js";
import { requireAuthentication, requireRole } from "../src/auth/middleware.js";
import type { AuthRepository, AuthSession, AuthUser } from "../src/auth/repository.js";
import { hashPassword } from "../src/security/password.js";

const config: AppConfig = {
  nodeEnv: "test",
  apiPort: 3001,
  appOrigin: "http://localhost:5173",
  sessionTtlHours: 1,
};

class MemoryAuthRepository implements AuthRepository {
  readonly users: AuthUser[] = [];
  readonly sessions = new Map<string, AuthSession>();

  async findUserByEmail(email: string) {
    return this.users.find((user) => user.email === email) ?? null;
  }
  async findSession(tokenHash: string) {
    const session = this.sessions.get(tokenHash);
    if (!session || session.expiresAt.getTime() <= Date.now()) return null;
    const user = this.users.find((candidate) => candidate.id === session.userId);
    return user ? { session, user: { ...user, passwordHash: undefined } } : null;
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
}

const repositories: MemoryAuthRepository[] = [];
async function setup() {
  const repository = new MemoryAuthRepository();
  repositories.push(repository);
  const passwordHash = await hashPassword("test-password-123");
  repository.users.push({ id: 1, email: "admin@example.test", role: "admin", passwordHash });
  repository.users.push({ id: 2, email: "owner@example.test", role: "owner", passwordHash });
  const app = createApp(repository, config, async () => undefined);
  return { app, repository };
}

afterEach(() => {
  repositories.length = 0;
});

describe("authentication foundation", () => {
  it("returns a public liveness response without querying MySQL", async () => {
    const repository = new MemoryAuthRepository();
    const app = createApp(repository, config, async () => {
      throw new Error("liveness must not check MySQL");
    });
    const response = await request(app).get("/health/live");
    expect(response.status).toBe(200);
    expect(response.body).toEqual({ status: "ok" });
  });

  it("returns a safe client error for malformed JSON", async () => {
    const { app } = await setup();
    const response = await request(app).post("/api/auth/login")
      .set("Origin", config.appOrigin)
      .set("Content-Type", "application/json")
      .send('{"email":');
    expect(response.status).toBe(400);
    expect(response.body).toEqual({ error: "Invalid JSON request body" });
  });

  it("validates login input with Zod", async () => {
    const { app } = await setup();
    const response = await request(app).post("/api/auth/login")
      .set("Origin", config.appOrigin)
      .send({ email: "not-an-email", password: "test-password-123", role: "admin" });
    expect(response.status).toBe(400);
    expect(response.body).toEqual({ error: "Invalid email or password" });
  });

  it("rejects incorrect passwords without revealing whether the user exists", async () => {
    const { app } = await setup();
    const known = await request(app).post("/api/auth/login").set("Origin", config.appOrigin)
      .send({ email: "admin@example.test", password: "wrong-password" });
    const unknown = await request(app).post("/api/auth/login").set("Origin", config.appOrigin)
      .send({ email: "missing@example.test", password: "wrong-password" });
    expect(known.status).toBe(401);
    expect(unknown.status).toBe(401);
    expect(known.body).toEqual(unknown.body);
  });

  it("creates a server-side session and rejects access after logout", async () => {
    const { app, repository } = await setup();
    const login = await request(app).post("/api/auth/login").set("Origin", config.appOrigin)
      .send({ email: "admin@example.test", password: "test-password-123" });
    expect(login.status).toBe(200);
    const cookie = login.headers["set-cookie"][0].split(";")[0];
    expect(login.headers["set-cookie"][0]).toContain("HttpOnly");
    expect(login.body.csrfToken).toMatch(/^[a-f0-9]{64}$/);
    expect(repository.sessions.size).toBe(1);

    const me = await request(app).get("/api/auth/me").set("Cookie", cookie);
    expect(me.status).toBe(200);
    expect(me.body.user).toEqual({ id: 1, email: "admin@example.test", role: "admin" });

    const logout = await request(app).post("/api/auth/logout").set("Origin", config.appOrigin)
      .set("Cookie", cookie).set("X-CSRF-Token", login.body.csrfToken);
    expect(logout.status).toBe(204);
    expect(repository.sessions.size).toBe(0);
    expect((await request(app).get("/api/auth/me").set("Cookie", cookie)).status).toBe(401);
  });

  it("rejects missing CSRF tokens and sessions after expiry", async () => {
    const { app, repository } = await setup();
    const login = await request(app).post("/api/auth/login").set("Origin", config.appOrigin)
      .send({ email: "admin@example.test", password: "test-password-123" });
    const cookie = login.headers["set-cookie"][0].split(";")[0];

    expect((await request(app).post("/api/auth/logout").set("Origin", config.appOrigin).set("Cookie", cookie)).status).toBe(403);
    const session = [...repository.sessions.values()][0];
    session.expiresAt = new Date(Date.now() - 1000);
    expect((await request(app).get("/api/auth/me").set("Cookie", cookie)).status).toBe(401);
  });

  it("enforces roles using the role loaded from the server session", async () => {
    const repository = new MemoryAuthRepository();
    const user: AuthUser = { id: 2, email: "owner@example.test", role: "owner" };
    const token = "a".repeat(64);
    const tokenHash = createHash("sha256").update(token).digest("hex");
    repository.users.push(user);
    repository.sessions.set(tokenHash, {
      tokenHash, userId: user.id, csrfTokenHash: "b".repeat(64),
      expiresAt: new Date(Date.now() + 60_000),
    });
    const app = express();
    app.use(express.json());
    app.use((req, _res, next) => {
      const cookie = req.headers.cookie?.split("=")[1];
      if (cookie) Object.assign(req, { cookies: { tv_session: cookie } });
      next();
    });
    app.get("/admin", requireAuthentication(repository), requireRole("admin"), (_req, res) => res.sendStatus(204));

    expect((await request(app).get("/admin").set("Cookie", `tv_session=${token}`)).status).toBe(403);
  });

  it("keeps the health response generic when the database is unavailable", async () => {
    const repository = new MemoryAuthRepository();
    const app = createApp(repository, config, async () => { throw new Error("database secret"); });
    const response = await request(app).get("/health/ready");
    expect(response.status).toBe(503);
    expect(response.body).toEqual({ status: "unavailable" });
    expect(JSON.stringify(response.body)).not.toContain("database secret");
  });
});
