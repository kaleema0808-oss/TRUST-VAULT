import express, { type ErrorRequestHandler } from "express";
import rateLimit from "express-rate-limit";
import helmet from "helmet";
import cookieParser from "cookie-parser";
import type { AppConfig } from "./config.js";
import { createAuthRouter } from "./auth/routes.js";
import { requireAuthentication, requireRole } from "./auth/middleware.js";
import type { AuthRepository, DocumentRepository } from "./auth/repository.js";
import { createDocumentRouter } from "./documents/routes.js";
import { z } from "zod";

export type HealthCheck = () => Promise<void>;

export function createApp(
  repository: AuthRepository,
  config: AppConfig,
  checkDatabase: HealthCheck,
  documentRepository?: DocumentRepository,
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
      response.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization");
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
    } catch {
      console.error("Database readiness check failed");
      response.status(503).json({ status: "unavailable" });
    }
  });

  app.use("/api/auth", rateLimit({
    windowMs: 15 * 60 * 1000,
    limit: 20,
    standardHeaders: true,
    legacyHeaders: false,
  }), createAuthRouter(repository, config));

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
    console.error("Request failed");
    response.status(500).json({ error: "Internal server error" });
  };
  app.use(errorHandler);
  return app;
}
