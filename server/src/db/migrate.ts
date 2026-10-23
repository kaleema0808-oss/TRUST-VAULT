import "../load-env.js";
import { readdir, readFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import mysql from "mysql2/promise";
import { databaseConfig } from "../config.js";

const parsed = databaseConfig.safeParse(process.env);
if (!parsed.success) {
  throw new Error(`Invalid database configuration: ${parsed.error.issues.map((issue) => issue.path.join(".")).join(", ")}`);
}
const env = parsed.data;
const connection = await mysql.createConnection({
  host: env.DATABASE_HOST,
  port: env.DATABASE_PORT,
  database: env.DATABASE_NAME,
  user: env.DATABASE_USER,
  password: env.DATABASE_PASSWORD,
  ...(env.DATABASE_TLS === "true" ? { ssl: { minVersion: "TLSv1.2" } } : {}),
});

try {
  await connection.query(`
    CREATE TABLE IF NOT EXISTS schema_migrations (
      version VARCHAR(255) PRIMARY KEY,
      applied_at TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3)
    ) ENGINE=InnoDB
  `);

  const directory = path.join(path.dirname(fileURLToPath(import.meta.url)), "migrations");
  const files = (await readdir(directory)).filter((file) => file.endsWith(".sql")).sort();
  for (const file of files) {
    const [rows] = await connection.execute<mysql.RowDataPacket[]>(
      "SELECT version FROM schema_migrations WHERE version = ?",
      [file],
    );
    if (rows.length > 0) continue;

    const sql = await readFile(path.join(directory, file), "utf8");
    const statements = sql.split(/;\s*(?:\r?\n|$)/).map((statement) => statement.trim()).filter(Boolean);
    for (const statement of statements) {
      await connection.query(statement);
    }
    await connection.execute("INSERT INTO schema_migrations (version) VALUES (?)", [file]);
    console.info(`Applied migration ${file}`);
  }
} finally {
  await connection.end();
}
