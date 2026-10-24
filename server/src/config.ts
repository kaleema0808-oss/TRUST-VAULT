import "./load-env.js";
import { z } from "zod";

const environmentSchema = z.object({
  NODE_ENV: z.enum(["development", "test", "production"]).default("development"),
  API_PORT: z.coerce.number().int().min(1).max(65535).default(3001),
  PORT: z.coerce.number().int().min(1).max(65535).optional(),
  APP_ORIGIN: z.string().url().default("http://localhost:5173"),
  DATABASE_HOST: z.string().default("127.0.0.1"),
  DATABASE_PORT: z.coerce.number().int().min(1).max(65535).default(3306),
  DATABASE_NAME: z.string().regex(/^[A-Za-z0-9_]+$/).default("trustvault"),
  DATABASE_USER: z.string().default("trustvault_app"),
  DATABASE_PASSWORD: z.string().default(""),
  DATABASE_TLS: z.enum(["true", "false"]).default("false"),
  SESSION_TTL_HOURS: z.coerce.number().int().min(1).max(168).default(12),
});

export type AppConfig = {
  nodeEnv: "development" | "test" | "production";
  apiPort: number;
  appOrigin: string;
  sessionTtlHours: number;
};

export function loadConfig(source: NodeJS.ProcessEnv = process.env): AppConfig {
  const parsed = environmentSchema.safeParse(source);
  if (!parsed.success) {
    throw new Error(`Invalid environment configuration: ${parsed.error.issues.map((issue) => issue.path.join(".")).join(", ")}`);
  }

  if (parsed.data.NODE_ENV === "production") {
    const required = ["DATABASE_PASSWORD"];
    const missing = required.filter((key) => !source[key]);
    if (missing.length > 0) {
      throw new Error(`Missing required production environment variables: ${missing.join(", ")}`);
    }
    if (parsed.data.DATABASE_TLS !== "true") {
      throw new Error("DATABASE_TLS=true is required in production");
    }
    if (!parsed.data.APP_ORIGIN.startsWith("https://")) {
      throw new Error("APP_ORIGIN must use HTTPS in production");
    }
  }

  return {
    nodeEnv: parsed.data.NODE_ENV,
    apiPort: parsed.data.PORT ?? parsed.data.API_PORT,
    appOrigin: parsed.data.APP_ORIGIN,
    sessionTtlHours: parsed.data.SESSION_TTL_HOURS,
  };
}

export const databaseConfig = environmentSchema;
