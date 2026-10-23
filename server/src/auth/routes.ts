import { randomBytes } from "node:crypto";
import { Router, type Request, type Response } from "express";
import { z } from "zod";
import type { AppConfig } from "../config.js";
import { hashPassword, verifyPassword } from "../security/password.js";
import { hashToken, requireAuthentication, requireCsrf } from "./middleware.js";
import type { AuthRepository } from "./repository.js";

const loginSchema = z.object({
  email: z.string().trim().email().max(254),
  password: z.string().min(1).max(128),
}).strict();

function makeToken(): string {
  return randomBytes(32).toString("hex");
}

let dummyPasswordHash: Promise<string> | undefined;

function getDummyPasswordHash(): Promise<string> {
  dummyPasswordHash ??= hashPassword(randomBytes(32).toString("hex"));
  return dummyPasswordHash;
}

function setSessionCookie(response: Response, token: string, config: AppConfig, maxAge: number): void {
  response.cookie("tv_session", token, {
    httpOnly: true,
    secure: config.nodeEnv === "production",
    sameSite: "lax",
    path: "/",
    maxAge,
  });
}

export function createAuthRouter(repository: AuthRepository, config: AppConfig): Router {
  const router = Router();
  const authenticate = requireAuthentication(repository);
  const sessionTtlMs = config.sessionTtlHours * 60 * 60 * 1000;

  router.post("/login", async (request: Request, response: Response, next) => {
    const parsed = loginSchema.safeParse(request.body);
    if (!parsed.success) {
      response.status(400).json({ error: "Invalid email or password" });
      return;
    }
    try {
      const user = await repository.findUserByEmail(parsed.data.email.toLowerCase());
      const comparisonHash = user?.passwordHash ?? await getDummyPasswordHash();
      const valid = await verifyPassword(parsed.data.password, comparisonHash);
      if (!user || !valid) {
        response.status(401).json({ error: "Invalid email or password" });
        return;
      }

      const token = makeToken();
      const csrfToken = makeToken();
      const expiresAt = new Date(Date.now() + sessionTtlMs);
      await repository.createSession({
        tokenHash: hashToken(token),
        userId: user.id,
        csrfTokenHash: hashToken(csrfToken),
        expiresAt,
      });
      setSessionCookie(response, token, config, sessionTtlMs);
      response.status(200).json({
        user: { id: user.id, email: user.email, role: user.role },
        csrfToken,
      });
    } catch (error) {
      next(error);
    }
  });

  router.get("/me", authenticate, (request, response) => {
    response.json({ user: request.auth?.user });
  });

  router.get("/csrf", authenticate, async (request, response, next) => {
    try {
      const csrfToken = makeToken();
      await repository.updateCsrfToken(request.auth!.session.tokenHash, hashToken(csrfToken));
      response.json({ csrfToken });
    } catch (error) {
      next(error);
    }
  });

  router.post("/logout", authenticate, requireCsrf, async (request, response, next) => {
    try {
      await repository.deleteSession(request.auth!.session.tokenHash);
      response.clearCookie("tv_session", {
        httpOnly: true,
        secure: config.nodeEnv === "production",
        sameSite: "lax",
        path: "/",
      });
      response.status(204).end();
    } catch (error) {
      next(error);
    }
  });

  return router;
}
