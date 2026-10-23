import { createHash, timingSafeEqual } from "node:crypto";
import type { NextFunction, Request, Response } from "express";
import type { AuthRepository, AuthSession, AuthUser, UserRole } from "./repository.js";

declare global {
  namespace Express {
    interface Request {
      auth?: { user: AuthUser; session: AuthSession };
    }
  }
}

export function hashToken(token: string): string {
  return createHash("sha256").update(token).digest("hex");
}

export function requireAuthentication(repository: AuthRepository) {
  return async (request: Request, response: Response, next: NextFunction): Promise<void> => {
    const token = request.cookies?.tv_session as string | undefined;
    if (!token || !/^[a-f0-9]{64}$/.test(token)) {
      response.status(401).json({ error: "Authentication required" });
      return;
    }

    try {
      const result = await repository.findSession(hashToken(token));
      if (!result) {
        response.status(401).json({ error: "Authentication required" });
        return;
      }
      request.auth = result;
      next();
    } catch (error) {
      next(error);
    }
  };
}

export function requireRole(...allowedRoles: UserRole[]) {
  return (request: Request, response: Response, next: NextFunction): void => {
    if (!request.auth) {
      response.status(401).json({ error: "Authentication required" });
      return;
    }
    if (!allowedRoles.includes(request.auth.user.role)) {
      response.status(403).json({ error: "Forbidden" });
      return;
    }
    next();
  };
}

export function requireCsrf(request: Request, response: Response, next: NextFunction): void {
  const expected = request.auth?.session.csrfTokenHash;
  const presented = request.get("X-CSRF-Token");
  if (!expected || !presented || !/^[a-f0-9]{64}$/.test(presented)) {
    response.status(403).json({ error: "CSRF validation failed" });
    return;
  }
  const actualHash = Buffer.from(hashToken(presented), "hex");
  const expectedHash = Buffer.from(expected, "hex");
  if (actualHash.length !== expectedHash.length || !timingSafeEqual(actualHash, expectedHash)) {
    response.status(403).json({ error: "CSRF validation failed" });
    return;
  }
  next();
}
