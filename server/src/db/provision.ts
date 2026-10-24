import "../load-env.js";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import type { Pool, Connection, RowDataPacket, ResultSetHeader } from "mysql2/promise";
import { hashPassword, verifyPassword } from "../security/password.js";
import { pool } from "./pool.js";

export type ProvisionResult = {
  provisioned: string[];
  updated: string[];
  skipped: string[];
};

function cleanPassword(val?: string): string | undefined {
  if (!val) return undefined;
  let p = val.trim();
  if ((p.startsWith('"') && p.endsWith('"')) || (p.startsWith("'") && p.endsWith("'"))) {
    p = p.slice(1, -1);
  }
  return p.trim();
}

export async function provisionDefaultAccounts(
  db: Pool | Connection,
): Promise<ProvisionResult> {
  const adminPassword = cleanPassword(
    process.env.ADMIN_PASSWORD ||
    process.env.DEV_ADMIN_PASSWORD ||
    process.env.INITIAL_ADMIN_PASSWORD ||
    process.env.TRUSTVAULT_ADMIN_PASSWORD ||
    process.env.ADMIN_PASS ||
    process.env.DEFAULT_ADMIN_PASSWORD,
  );

  const ownerPassword = cleanPassword(
    process.env.OWNER_PASSWORD ||
    process.env.DEV_OWNER_PASSWORD ||
    process.env.INITIAL_OWNER_PASSWORD ||
    process.env.TRUSTVAULT_OWNER_PASSWORD ||
    process.env.OWNER_PASS ||
    process.env.DEFAULT_OWNER_PASSWORD,
  );

  const viewerPassword = cleanPassword(
    process.env.VIEWER_PASSWORD ||
    process.env.DEV_VIEWER_PASSWORD ||
    process.env.INITIAL_VIEWER_PASSWORD ||
    process.env.TRUSTVAULT_VIEWER_PASSWORD ||
    process.env.VIEWER_PASS ||
    process.env.DEFAULT_VIEWER_PASSWORD,
  );

  const accounts = [
    { email: "admin@trustvault.local", role: "admin", password: adminPassword },
    { email: "owner@trustvault.local", role: "owner", password: ownerPassword },
    { email: "viewer@trustvault.local", role: "viewer", password: viewerPassword },
  ] as const;

  const result: ProvisionResult = {
    provisioned: [],
    updated: [],
    skipped: [],
  };

  for (const account of accounts) {
    if (!account.password || account.password.length < 12) {
      result.skipped.push(`${account.email} (password missing or < 12 chars)`);
      continue;
    }

    const [rows] = await db.execute<RowDataPacket[]>(
      "SELECT id, email, role, password_hash FROM users WHERE email = ? LIMIT 1",
      [account.email],
    );

    const existing = rows[0] as { id: number; email: string; role: string; password_hash: string } | undefined;

    if (!existing) {
      const passwordHash = await hashPassword(account.password);
      await db.execute<ResultSetHeader>(
        "INSERT INTO users (email, password_hash, role) VALUES (?, ?, ?)",
        [account.email, passwordHash, account.role],
      );
      result.provisioned.push(`${account.email} (${account.role})`);
    } else {
      const allowRotation = process.env.ROTATE_USER_PASSWORDS === "true";
      if (allowRotation) {
        const matches = await verifyPassword(account.password, existing.password_hash);
        if (!matches || existing.role !== account.role) {
          const passwordHash = await hashPassword(account.password);
          await db.execute(
            "UPDATE users SET password_hash = ?, role = ? WHERE id = ?",
            [passwordHash, account.role, existing.id],
          );
          result.updated.push(`${account.email} (${account.role})`);
        } else {
          result.skipped.push(`${account.email} (already exists with matching password)`);
        }
      } else {
        result.skipped.push(`${account.email} (already exists)`);
      }
    }
  }

  return result;
}

// Check if running directly as a CLI script
const isMain = process.argv[1] && (
  fileURLToPath(import.meta.url) === path.resolve(process.argv[1]) ||
  import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href
);

if (isMain) {
  provisionDefaultAccounts(pool)
    .then((result) => {
      if (result.provisioned.length > 0) {
        console.info(`Provisioned accounts: ${result.provisioned.join(", ")}`);
      }
      if (result.updated.length > 0) {
        console.info(`Updated accounts: ${result.updated.join(", ")}`);
      }
      if (result.skipped.length > 0) {
        console.info(`Skipped accounts: ${result.skipped.join(", ")}`);
      }
      if (result.provisioned.length === 0 && result.updated.length === 0) {
        console.info("All configured accounts are already up to date.");
      }
      process.exit(0);
    })
    .catch((err) => {
      console.error("Account provisioning failed:", err);
      process.exit(1);
    })
    .finally(() => {
      void pool.end();
    });
}
