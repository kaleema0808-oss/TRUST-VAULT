import express, { type ErrorRequestHandler } from "express";
import rateLimit from "express-rate-limit";
import helmet from "helmet";
import cookieParser from "cookie-parser";
import type { AppConfig } from "./config.js";
import { createAuthRouter } from "./auth/routes.js";
import { requireAuthentication, requireCsrf, requireRole } from "./auth/middleware.js";
import type { AuthRepository, DocumentRepository, RoleRequestRepository } from "./auth/repository.js";
import { createDocumentRouter } from "./documents/routes.js";
import { z } from "zod";

export type HealthCheck = () => Promise<void>;

export function createApp(
  repository: AuthRepository,
  config: AppConfig,
  checkDatabase: HealthCheck,
  documentRepository?: DocumentRepository,
  roleRequestRepository?: RoleRequestRepository,
) {
  const app = express();
  app.set("trust proxy", 1);
  app.disable("x-powered-by");
  app.use(helmet());
  app.use(cookieParser());
  app.use((request, response, next) => {
    const origin = request.get("Origin");

    if (origin && origin !== config.appOrigin) {
      response.status(403).json({ error: "Origin not allowed" });
      return;
    }

    if (origin === config.appOrigin) {
      response.setHeader("Access-Control-Allow-Origin", config.appOrigin);
      response.setHeader("Access-Control-Allow-Credentials", "true");
      response.setHeader("Vary", "Origin");
    }

    if (request.method === "OPTIONS") {
      if (origin !== config.appOrigin) {
        response.status(403).json({ error: "Origin not allowed" });
        return;
      }

      response.setHeader("Access-Control-Allow-Methods", "GET, POST, PUT, PATCH, DELETE, OPTIONS");
      response.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization, X-CSRF-Token");
      response.setHeader("Access-Control-Max-Age", "600");
      response.status(204).end();
      return;
    }

    if (["POST", "PUT", "PATCH", "DELETE"].includes(request.method) &&
        origin !== config.appOrigin) {
      response.status(403).json({ error: "Origin not allowed" });
      return;
    }

    next();
  });
  app.use(express.json({ limit: "16kb", type: "application/json" }));

  app.get("/health/live", (_request, response) => response.json({ status: "ok" }));
  app.get("/health/ready", async (_request, response) => {
    try {
      await checkDatabase();
      response.json({ status: "ok", database: "connected" });
    } catch (error) {
      console.error("Database readiness check failed:", error);
      response.status(503).json({ status: "unavailable" });
    }
  });

  app.use("/api/auth", rateLimit({
    windowMs: 15 * 60 * 1000,
    limit: 20,
    standardHeaders: true,
    legacyHeaders: false,
  }), createAuthRouter(repository, config, roleRequestRepository));

  if (documentRepository) {
    app.use("/api/documents", createDocumentRouter(repository, documentRepository));

    // Admin-only audit events endpoint
    const auditFilterSchema = z.object({
      actorUserId: z.coerce.number().int().positive().optional(),
      action: z.string().max(64).optional(),
      outcome: z.enum(["allowed", "denied"]).optional(),
      documentId: z.coerce.number().int().positive().optional(),
      limit: z.coerce.number().int().min(1).max(200).default(50),
      offset: z.coerce.number().int().min(0).default(0),
    });

    app.get(
      "/api/admin/audit",
      requireAuthentication(repository),
      requireRole("admin"),
      async (request, response, next) => {
        const parsed = auditFilterSchema.safeParse(request.query);
        if (!parsed.success) {
          response.status(400).json({ error: "Invalid filter parameters" });
          return;
        }
        try {
          const events = await documentRepository.listAuditEvents(parsed.data);
          response.json({ events });
        } catch (error) {
          next(error);
        }
      },
    );
  }

  if (roleRequestRepository) {
    const requestIdSchema = z.coerce.number().int().positive().safe();
    const rejectSchema = z.object({
      reason: z.string().trim().max(255).optional(),
    }).strict();

    // Helper for admin authorization with audit recording on unauthorized attempt
    const requireAdminWithAudit = (action: string) => async (
      request: express.Request,
      response: express.Response,
      next: express.NextFunction,
    ) => {
      if (!request.auth) {
        response.status(401).json({ error: "Authentication required" });
        return;
      }
      if (request.auth.user.role !== "admin") {
        await roleRequestRepository.appendAudit({
          actorUserId: request.auth.user.id,
          documentId: null,
          action,
          outcome: "denied",
          details: {
            reason: "unauthorized_role",
            requiredRole: "admin",
            actorRole: request.auth.user.role,
            requestId: request.params.id ? Number(request.params.id) : undefined,
          },
        });
        response.status(403).json({ error: "Forbidden" });
        return;
      }
      next();
    };

    app.get(
      "/api/admin/role-requests",
      requireAuthentication(repository),
      requireRole("admin"),
      async (request, response, next) => {
        try {
          const statusParam = request.query.status as string | undefined;
          const status = statusParam === "pending" || statusParam === "approved" || statusParam === "rejected"
            ? statusParam
            : undefined;
          const requests = await roleRequestRepository.listRoleRequests(status);
          response.json({ requests });
        } catch (error) {
          next(error);
        }
      },
    );

    app.post(
      "/api/admin/role-requests/:id/approve",
      requireAuthentication(repository),
      requireAdminWithAudit("role_request.approve"),
      requireCsrf,
      async (request, response, next) => {
        const parsedId = requestIdSchema.safeParse(request.params.id);
        if (!parsedId.success) {
          response.status(400).json({ error: "Invalid request ID" });
          return;
        }
        try {
          const result = await roleRequestRepository.approveRoleRequest(parsedId.data, request.auth!.user.id);
          if (!result.success) {
            const status = result.error === "Role request not found" ? 404 : 400;
            response.status(status).json({ error: result.error });
            return;
          }
          response.json({ message: "Owner access approved", request: result.request });
        } catch (error) {
          next(error);
        }
      },
    );

    app.post(
      "/api/admin/role-requests/:id/reject",
      requireAuthentication(repository),
      requireAdminWithAudit("role_request.reject"),
      requireCsrf,
      async (request, response, next) => {
        const parsedId = requestIdSchema.safeParse(request.params.id);
        if (!parsedId.success) {
          response.status(400).json({ error: "Invalid request ID" });
          return;
        }
        const parsedBody = rejectSchema.safeParse(request.body);
        if (!parsedBody.success) {
          response.status(400).json({ error: "Invalid rejection parameters" });
          return;
        }
        try {
          const result = await roleRequestRepository.rejectRoleRequest(
            parsedId.data,
            request.auth!.user.id,
            parsedBody.data.reason,
          );
          if (!result.success) {
            const status = result.error === "Role request not found" ? 404 : 400;
            response.status(status).json({ error: result.error });
            return;
          }
          response.json({ message: "Owner access rejected", request: result.request });
        } catch (error) {
          next(error);
        }
      },
    );
  }

  app.get("/api/admin/check", requireAuthentication(repository), requireRole("admin"), (_request, response) => {
    response.json({ allowed: true });
  });

  const errorHandler: ErrorRequestHandler = (error, _request, response, _next) => {
    if (typeof error === "object" && error !== null && "type" in error) {
      if (error.type === "entity.parse.failed") {
        response.status(400).json({ error: "Invalid JSON request body" });
        return;
      }
      if (error.type === "entity.too.large") {
        response.status(413).json({ error: "Request body is too large" });
        return;
      }
    }
    console.error("Request failed:", sanitizeErrorForLogging(error));
    response.status(500).json({ error: "Internal server error" });
  };
  app.use(errorHandler);
  return app;
}

export function sanitizeErrorForLogging(error: unknown): Record<string, unknown> | string {
  if (typeof error === "object" && error !== null) {
    const err = error as Error & { code?: string; errno?: number; sqlState?: string; sqlMessage?: string };
    const scrub = (str?: string) => {
      if (!str) return str;
      return str
        .replace(/:\/\/([^:@]+):([^@]+)@/g, "://$1:[REDACTED]@")
        .replace(/(password|token|secret|key|authorization|bearer)\s*[:=]\s*['"]?[^\s,'"]+/gi, "$1=[REDACTED]");
    };

    return {
      name: err.name ?? "Error",
      message: scrub(err.message),
      code: err.code,
      errno: err.errno,
      sqlState: err.sqlState,
      sqlMessage: scrub(err.sqlMessage),
      stack: scrub(err.stack),
    };
  }
  return typeof error === "string" ? error.replace(/:\/\/([^:@]+):([^@]+)@/g, "://$1:[REDACTED]@") : String(error);
}
