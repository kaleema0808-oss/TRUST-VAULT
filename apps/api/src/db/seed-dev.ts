import "../load-env.js";
import { hashPassword } from "../security/password.js";
import { pool } from "./pool.js";

const accounts = [
  { email: "admin@trustvault.local", role: "admin", password: process.env.DEV_ADMIN_PASSWORD },
  { email: "owner@trustvault.local", role: "owner", password: process.env.DEV_OWNER_PASSWORD },
  { email: "viewer@trustvault.local", role: "viewer", password: process.env.DEV_VIEWER_PASSWORD },
] as const;

if (process.env.NODE_ENV === "production") {
  throw new Error("Development seed is disabled when NODE_ENV=production");
}
if (accounts.some((account) => !account.password || account.password.length < 12)) {
  throw new Error("Set DEV_ADMIN_PASSWORD, DEV_OWNER_PASSWORD, and DEV_VIEWER_PASSWORD to unique values of at least 12 characters");
}

try {
  for (const account of accounts) {
    const passwordHash = await hashPassword(account.password!);
    await pool.execute(
      "INSERT INTO users (email, password_hash, role) VALUES (?, ?, ?) ON DUPLICATE KEY UPDATE email = VALUES(email)",
      [account.email, passwordHash, account.role],
    );
  }
  console.info("Development accounts are ready. Passwords were read from environment variables.");
} finally {
  await pool.end();
}
