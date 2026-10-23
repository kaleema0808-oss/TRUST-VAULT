import express, { type ErrorRequestHandler } from "express";
import rateLimit from "express-rate-limit";
import helmet from "helmet";
import cookieParser from "cookie-parser";
import type { AppConfig } from "./config.js";
import { createAuthRouter } from "./auth/routes.js";
import { requireAuthentication, requireRole } from "./auth/middleware.js";
import type { AuthRepository } from "./auth/repository.js";

export type HealthCheck = () => Promise<void>;

export function createApp(repository: AuthRepository, config: AppConfig, checkDatabase: HealthCheck) {
  const app = express();
  app.disable("x-powered-by");
  app.use(helmet());
  app.use(cookieParser());
  app.use((request, response, next) => {
    if (request.get("Origin") && request.get("Origin") !== config.appOrigin) {
      response.status(403).json({ error: "Origin not allowed" });
      return;
    }
    if (["POST", "PUT", "PATCH", "DELETE"].includes(request.method) &&
        request.get("Origin") !== config.appOrigin) {
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

  app.get("/api/admin/check", requireAuthentication(repository), requireRole("admin"), (_request, response) => {
    response.json({ allowed: true });
  });

  const errorHandler: ErrorRequestHandler = (error, _request, response, _next) => {
    console.error("Request failed");
    response.status(500).json({ error: "Internal server error" });
  };
  app.use(errorHandler);
  return app;
}
