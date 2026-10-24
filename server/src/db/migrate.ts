import "../load-env.js";
import { readdir, readFile, stat } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import mysql from "mysql2/promise";
import { databaseConfig } from "../config.js";

export async function findMigrationsDirectory(): Promise<string> {
  const currentDir = path.dirname(fileURLToPath(import.meta.url));
  const candidates = [
    path.join(currentDir, "migrations"),
    path.join(currentDir, "../../src/db/migrations"),
    path.join(process.cwd(), "server/src/db/migrations"),
    path.join(process.cwd(), "server/dist/db/migrations"),
    path.join(process.cwd(), "src/db/migrations"),
    path.join(process.cwd(), "dist/db/migrations"),
  ];

  for (const candidate of candidates) {
    try {
      const stats = await stat(candidate);
      if (stats.isDirectory()) {
        const files = await readdir(candidate);
        if (files.some((f) => f.endsWith(".sql"))) {
          return candidate;
        }
      }
    } catch {
      // try next
    }
  }
  throw new Error("Could not locate database migrations directory with .sql files");
}

export function createMigrationConnection(): Promise<mysql.Connection> {
  const parsed = databaseConfig.safeParse(process.env);
  if (!parsed.success) {
    throw new Error(`Invalid database configuration: ${parsed.error.issues.map((issue) => issue.path.join(".")).join(", ")}`);
  }
  const env = parsed.data;
  return mysql.createConnection({
    host: env.DATABASE_HOST,
    port: env.DATABASE_PORT,
    database: env.DATABASE_NAME,
    user: env.DATABASE_USER,
    password: env.DATABASE_PASSWORD,
    ...(env.DATABASE_TLS === "true"
      ? {
          ssl: {
            minVersion: "TLSv1.2",
            rejectUnauthorized: env.DATABASE_TLS_REJECT_UNAUTHORIZED !== "false",
            ...(env.DATABASE_TLS_CA ? { ca: env.DATABASE_TLS_CA } : {}),
          },
        }
      : {}),
  });
}

export async function runMigrations(customConnection?: mysql.Connection): Promise<string[]> {
  const connection = customConnection ?? (await createMigrationConnection());
  const appliedFiles: string[] = [];
  const ownConnection = !customConnection;

  try {
    await connection.query(`
      CREATE TABLE IF NOT EXISTS schema_migrations (
        version VARCHAR(255) PRIMARY KEY,
        applied_at TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3)
      ) ENGINE=InnoDB
    `);

    const directory = await findMigrationsDirectory();
    const files = (await readdir(directory)).filter((file) => file.endsWith(".sql")).sort();

    for (const file of files) {
      const [rows] = await connection.execute<mysql.RowDataPacket[]>(
        "SELECT version FROM schema_migrations WHERE version = ?",
        [file],
      );
      if (rows.length > 0) continue;

      const sql = await readFile(path.join(directory, file), "utf8");
      const statements = sql
        .split(/;\s*(?:\r?\n|$)/)
        .map((statement) => statement.trim())
        .filter(Boolean);

      for (const statement of statements) {
        await connection.query(statement);
      }

      await connection.execute("INSERT INTO schema_migrations (version) VALUES (?)", [file]);
      console.info(`Applied migration ${file}`);
      appliedFiles.push(file);
    }

    return appliedFiles;
  } finally {
    if (ownConnection) {
      await connection.end();
    }
  }
}

// Check if running as main entry point
const isMain = process.argv[1] && (
  fileURLToPath(import.meta.url) === path.resolve(process.argv[1]) ||
  import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href
);

if (isMain) {
  runMigrations()
    .then((applied) => {
      if (applied.length === 0) {
        console.info("Migrations are already up to date.");
      } else {
        console.info(`Successfully applied ${applied.length} migration(s).`);
      }
      process.exit(0);
    })
    .catch((err) => {
      console.error("Migration runner failed:", err);
      process.exit(1);
    });
}
