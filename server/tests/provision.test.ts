import { describe, expect, it, vi } from "vitest";
import { provisionDefaultAccounts } from "../src/db/provision.js";
import { verifyPassword } from "../src/security/password.js";

describe("account provisioning", () => {
  it("provisions accounts with valid passwords and verifies scrypt hashing", async () => {
    const originalEnv = { ...process.env };
    process.env.ADMIN_PASSWORD = "production-admin-secure-pass";
    delete process.env.DEV_ADMIN_PASSWORD;
    delete process.env.OWNER_PASSWORD;
    delete process.env.DEV_OWNER_PASSWORD;
    delete process.env.VIEWER_PASSWORD;
    delete process.env.DEV_VIEWER_PASSWORD;

    const mockUsers: Array<{ id: number; email: string; role: string; password_hash: string }> = [];

    const mockDb = {
      execute: vi.fn(async (query: string, params: unknown[]) => {
        if (query.includes("SELECT id, email, role, password_hash FROM users WHERE email = ?")) {
          const email = params[0] as string;
          const found = mockUsers.filter((u) => u.email === email);
          return [found];
        }
        if (query.includes("INSERT INTO users")) {
          const [email, passwordHash, role] = params as [string, string, string];
          mockUsers.push({ id: mockUsers.length + 1, email, role, password_hash: passwordHash });
          return [{ insertId: mockUsers.length }];
        }
        if (query.includes("UPDATE users SET password_hash = ?")) {
          const [passwordHash, role, id] = params as [string, string, number];
          const user = mockUsers.find((u) => u.id === id);
          if (user) {
            user.password_hash = passwordHash;
            user.role = role;
          }
          return [{ affectedRows: 1 }];
        }
        return [[]];
      }),
    };

    try {
      const result = await provisionDefaultAccounts(mockDb as unknown as import("mysql2/promise").Pool);

      expect(result.provisioned).toEqual(["admin@trustvault.local (admin)"]);
      expect(result.skipped.length).toBe(2); // owner and viewer had no passwords
      expect(mockUsers.length).toBe(1);
      expect(mockUsers[0].email).toBe("admin@trustvault.local");
      expect(mockUsers[0].role).toBe("admin");

      const valid = await verifyPassword("production-admin-secure-pass", mockUsers[0].password_hash);
      expect(valid).toBe(true);

      // Re-running without rotation flag preserves existing user without updating
      process.env.ADMIN_PASSWORD = "updated-admin-new-secure-pass";
      const secondResult = await provisionDefaultAccounts(mockDb as unknown as import("mysql2/promise").Pool);
      expect(secondResult.provisioned).toEqual([]);
      expect(secondResult.updated).toEqual([]);
      expect(secondResult.skipped).toContain("admin@trustvault.local (already exists)");
      const stillOriginal = await verifyPassword("production-admin-secure-pass", mockUsers[0].password_hash);
      expect(stillOriginal).toBe(true);

      // Explicit rotation requires ROTATE_USER_PASSWORDS=true
      process.env.ROTATE_USER_PASSWORDS = "true";
      const updateResult = await provisionDefaultAccounts(mockDb as unknown as import("mysql2/promise").Pool);
      expect(updateResult.updated).toEqual(["admin@trustvault.local (admin)"]);
      const newValid = await verifyPassword("updated-admin-new-secure-pass", mockUsers[0].password_hash);
      expect(newValid).toBe(true);
    } finally {
      process.env = originalEnv;
    }
  });
});
