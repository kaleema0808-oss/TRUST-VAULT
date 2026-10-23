import "../src/load-env.js";
import mysql from "mysql2/promise";
import { afterAll, describe, expect, it } from "vitest";

const testDatabase = process.env.MYSQL_TEST_DATABASE;
const isSafeTestDatabase = Boolean(testDatabase && /^trustvault_test_[a-z0-9_]+$/.test(testDatabase));

describe.skipIf(!isSafeTestDatabase)("MySQL schema constraints (requires isolated MYSQL_TEST_DATABASE)", () => {
  const connectionPromise = mysql.createConnection({
    host: process.env.DATABASE_HOST ?? "127.0.0.1",
    port: Number(process.env.DATABASE_PORT ?? 3306),
    database: testDatabase,
    user: process.env.DATABASE_USER,
    password: process.env.DATABASE_PASSWORD,
  });

  afterAll(async () => {
    const connection = await connectionPromise;
    await connection.end();
  });

  it("enforces unique emails, foreign keys, unique grants and permission checks", async () => {
    const connection = await connectionPromise;
    const suffix = `${Date.now()}${Math.floor(Math.random() * 10000)}`;
    const ownerEmail = `owner-${suffix}@example.test`;
    const viewerEmail = `viewer-${suffix}@example.test`;
    let ownerId: number | undefined;
    let viewerId: number | undefined;
    let documentId: number | undefined;
    try {
      const [ownerResult] = await connection.execute<mysql.ResultSetHeader>(
        "INSERT INTO users (email, password_hash, role) VALUES (?, ?, 'owner')",
        [ownerEmail, "test-hash-only"],
      );
      ownerId = ownerResult.insertId;
      const [viewerResult] = await connection.execute<mysql.ResultSetHeader>(
        "INSERT INTO users (email, password_hash, role) VALUES (?, ?, 'viewer')",
        [viewerEmail, "test-hash-only"],
      );
      viewerId = viewerResult.insertId;

      await expect(connection.execute(
        "INSERT INTO users (email, password_hash, role) VALUES (?, ?, 'owner')",
        [ownerEmail, "another-hash"],
      )).rejects.toMatchObject({ code: "ER_DUP_ENTRY" });
      await expect(connection.execute(
        "INSERT INTO documents (owner_id, name, category, object_key) VALUES (?, ?, ?, ?)",
        ["999999999", "test", "test", `missing-${suffix}`],
      )).rejects.toMatchObject({ code: "ER_NO_REFERENCED_ROW_2" });

      const [documentResult] = await connection.execute<mysql.ResultSetHeader>(
        "INSERT INTO documents (owner_id, name, category, object_key) VALUES (?, ?, ?, ?)",
        [ownerId, "constraint test", "test", `constraint-${suffix}`],
      );
      documentId = documentResult.insertId;
      await connection.execute(
        `INSERT INTO document_permissions
          (document_id, user_id, can_read, can_edit, granted_by)
         VALUES (?, ?, TRUE, FALSE, ?)`,
        [documentId, viewerId, ownerId],
      );
      await expect(connection.execute(
        `INSERT INTO document_permissions
          (document_id, user_id, can_read, can_edit, granted_by)
         VALUES (?, ?, TRUE, FALSE, ?)`,
        [documentId, viewerId, ownerId],
      )).rejects.toMatchObject({ code: "ER_DUP_ENTRY" });
      await expect(connection.execute(
        `INSERT INTO document_permissions
          (document_id, user_id, can_read, can_edit, granted_by)
         VALUES (?, ?, FALSE, TRUE, ?)`,
        [documentId, ownerId, ownerId],
      )).rejects.toMatchObject({ code: "ER_CHECK_CONSTRAINT_VIOLATED" });
    } finally {
      if (documentId) await connection.execute("DELETE FROM documents WHERE id = ?", [documentId]);
      if (ownerId) await connection.execute("DELETE FROM users WHERE id = ?", [ownerId]);
      if (viewerId) await connection.execute("DELETE FROM users WHERE id = ?", [viewerId]);
    }
  });
});
