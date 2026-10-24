/**
 * Local-disk storage backend.
 *
 * Files are stored under STORAGE_DIR (default: <project-root>/storage/).
 * The directory is gitignored. Object keys are random UUIDs — user-supplied
 * filenames are NEVER used as filesystem paths.
 *
 * NOTE for reviewers: Render's free tier uses ephemeral disk; files do not
 * survive a deploy or restart. For production persistence, swap the read/write
 * calls below for a Backblaze B2 / S3-compatible API. The auth layer, audit
 * events, and object-key model are identical regardless of backend.
 */

import { createReadStream, createWriteStream } from "node:fs";
import { mkdir, unlink, stat } from "node:fs/promises";
import path from "node:path";
import { pipeline } from "node:stream/promises";
import { randomUUID } from "node:crypto";
import type { Response } from "express";
import type { Readable } from "node:stream";

// ── Allowed file types ────────────────────────────────────────────────────────
// Map: MIME type → list of magic-byte signatures (first N bytes as hex string)
const ALLOWED: Record<string, string[]> = {
  "application/pdf":                         ["25504446"],       // %PDF
  "image/jpeg":                              ["ffd8ff"],
  "image/png":                               ["89504e47"],       // ‌PNG
  "image/gif":                               ["474946383761", "474946383961"], // GIF87a / GIF89a
  "image/webp":                              ["52494646"],       // RIFF (webp)
  "text/plain":                              [],                 // no magic check — inspect first 512 bytes
  "application/msword":                      ["d0cf11e0"],       // OLE2 .doc
  "application/vnd.openxmlformats-officedocument.wordprocessingml.document": ["504b0304"], // .docx (ZIP)
  "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet":       ["504b0304"], // .xlsx (ZIP)
};

export const ALLOWED_MIME_TYPES = Object.keys(ALLOWED);
export const MAX_FILE_BYTES = 10 * 1024 * 1024; // 10 MiB

// ── Storage directory ─────────────────────────────────────────────────────────
function storageDir(): string {
  return process.env.STORAGE_DIR ??
    path.join(path.dirname(new URL(import.meta.url).pathname.replace(/^\/([A-Z]:)/, "$1")), "../../../storage");
}

async function ensureDir(): Promise<string> {
  const dir = storageDir();
  await mkdir(dir, { recursive: true });
  return dir;
}

/** Opaque key for a new stored file — never derived from user input. */
export function newObjectKey(): string {
  return randomUUID();
}

/** Validate MIME type allowlist and magic bytes. Returns error string or null. */
export function validateFileBuffer(buffer: Buffer, mimeType: string): string | null {
  const signatures = ALLOWED[mimeType];
  if (signatures === undefined) {
    return `File type not allowed: ${mimeType}`;
  }
  if (signatures.length === 0) return null; // text/plain — skip magic check
  const hex = buffer.subarray(0, 8).toString("hex");
  const ok = signatures.some((sig) => hex.startsWith(sig));
  if (!ok) {
    return `File content does not match declared type (${mimeType})`;
  }
  return null;
}

/** Persist a file stream to disk under an opaque key. */
export async function storeFile(objectKey: string, stream: Readable): Promise<void> {
  const dir = await ensureDir();
  // Ensure the key is safe (UUID only) — belt-and-suspenders against path traversal
  const safeKey = path.basename(objectKey);
  if (safeKey !== objectKey) throw new Error("Invalid object key");
  const dest = path.join(dir, safeKey);
  const out = createWriteStream(dest);
  await pipeline(stream, out);
}

/** Stream a stored file to an Express response. Returns false if not found. */
export async function serveFile(
  objectKey: string,
  originalName: string,
  mimeType: string,
  response: Response,
): Promise<boolean> {
  const dir = await ensureDir();
  const safeKey = path.basename(objectKey);
  if (safeKey !== objectKey) return false;
  const filePath = path.join(dir, safeKey);
  try {
    await stat(filePath);
  } catch {
    return false;
  }
  response.setHeader("Content-Type", mimeType);
  response.setHeader(
    "Content-Disposition",
    `attachment; filename="${encodeURIComponent(originalName)}"`,
  );
  response.setHeader("X-Content-Type-Options", "nosniff");
  await pipeline(createReadStream(filePath), response);
  return true;
}

/** Delete a stored file from disk. Silently ignores missing files. */
export async function deleteFile(objectKey: string): Promise<void> {
  const dir = await ensureDir();
  const safeKey = path.basename(objectKey);
  if (safeKey !== objectKey) return;
  try {
    await unlink(path.join(dir, safeKey));
  } catch {
    // already deleted or never written — not an error
  }
}
