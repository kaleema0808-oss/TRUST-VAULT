import mysql, { type PoolOptions } from "mysql2/promise";
import { databaseConfig } from "../config.js";

const parsed = databaseConfig.safeParse(process.env);
if (!parsed.success) {
  throw new Error(`Invalid database configuration: ${parsed.error.issues.map((issue) => issue.path.join(".")).join(", ")}`);
}

const env = parsed.data;
const options: PoolOptions = {
  host: env.DATABASE_HOST,
  port: env.DATABASE_PORT,
  database: env.DATABASE_NAME,
  user: env.DATABASE_USER,
  password: env.DATABASE_PASSWORD,
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0,
  ...(env.DATABASE_TLS === "true"
    ? {
        ssl: {
          minVersion: "TLSv1.2",
          rejectUnauthorized: env.DATABASE_TLS_REJECT_UNAUTHORIZED !== "false",
          ...(env.DATABASE_TLS_CA ? { ca: env.DATABASE_TLS_CA } : {}),
        },
      }
    : {}),
};

export const pool = mysql.createPool(options);

export async function checkDatabaseConnection(): Promise<void> {
  const connection = await pool.getConnection();
  try {
    await connection.query("SELECT 1");
  } finally {
    connection.release();
  }
}
