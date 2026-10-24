import { Router, type Request, type Response } from "express";
import { z } from "zod";
import multer from "multer";
import { requireAuthentication, requireCsrf } from "../auth/middleware.js";
import type {
  AuditInput,
  DocumentRepository,
  DocumentRole,
} from "../auth/repository.js";
import type { AuthRepository } from "../auth/repository.js";
import {
  ALLOWED_MIME_TYPES,
  MAX_FILE_BYTES,
  newObjectKey,
  storeFile,
  serveFile,
  deleteFile,
  validateFileBuffer,
} from "../storage/local.js";

// Multer stores in memory so we can inspect the buffer before writing to disk
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: MAX_FILE_BYTES },
  fileFilter(_req, file, callback) {
    if (ALLOWED_MIME_TYPES.includes(file.mimetype)) {
      callback(null, true);
    } else {
      callback(new Error(`File type not allowed: ${file.mimetype}`));
    }
  },
});

const documentIdSchema = z.coerce.number().int().positive().safe();
const documentSchema = z.object({
  name: z.string().trim().min(1).max(255),
  category: z.string().trim().min(1).max(100),
}).strict();
const permissionSchema = z.object({
  canRead: z.boolean(),
  canEdit: z.boolean(),
}).strict().refine((value) => !value.canEdit || value.canRead);

function getActor(request: Request): { id: number; role: DocumentRole } {
  return { id: request.auth!.user.id, role: request.auth!.user.role };
}

function reject(response: Response): void {
  response.status(404).json({ error: "Document not found" });
}

async function auditDenied(
  documents: DocumentRepository,
  request: Request,
  documentId: number | null,
  action: string,
): Promise<void> {
  const event: AuditInput = {
    actorUserId: request.auth!.user.id,
    documentId: null,
    action,
    outcome: "denied",
    details: { reason: "authorization_denied", requestedDocumentId: documentId },
  };
  await documents.appendAudit(event);
}

export function createDocumentRouter(
  authRepository: AuthRepository,
  documentRepository: DocumentRepository,
): Router {
  const router = Router();
  const authenticate = requireAuthentication(authRepository);
  const canReadRole = (role: DocumentRole) => ["admin", "owner", "viewer"].includes(role);
  const canCreateRole = (role: DocumentRole) => role === "admin" || role === "owner";

  router.use(authenticate);

  router.get("/", async (request, response, next) => {
    try {
      const actor = getActor(request);
      if (!canReadRole(actor.role)) {
        response.status(403).json({ error: "Forbidden" });
        return;
      }
      const documents = await documentRepository.listAccessible(actor.id, actor.role);
      await documentRepository.appendAudit({
        actorUserId: actor.id,
        documentId: null,
        action: "document.list",
        outcome: "allowed",
        details: { resultCount: documents.length },
      });
      response.json({ documents });
    } catch (error) {
      next(error);
    }
  });

  router.post("/", requireCsrf, async (request, response, next) => {
    const parsed = documentSchema.safeParse(request.body);
    if (!parsed.success) {
      response.status(400).json({ error: "Invalid document metadata" });
      return;
    }
    try {
      const actor = getActor(request);
      if (!canCreateRole(actor.role)) {
        await auditDenied(documentRepository, request, null, "document.create");
        response.status(403).json({ error: "Forbidden" });
        return;
      }
      const document = await documentRepository.create(actor.id, parsed.data);
      response.status(201).json({ document });
    } catch (error) {
      next(error);
    }
  });

  router.get("/:documentId", async (request, response, next) => {
    const parsedId = documentIdSchema.safeParse(request.params.documentId);
    if (!parsedId.success) {
      reject(response);
      return;
    }
    try {
      const actor = getActor(request);
      const document = await documentRepository.getAccessible(parsedId.data, actor.id, actor.role);
      if (!document) {
        await auditDenied(documentRepository, request, parsedId.data, "document.read");
        reject(response);
        return;
      }
      await documentRepository.appendAudit({
        actorUserId: actor.id,
        documentId: document.id,
        action: "document.read",
        outcome: "allowed",
        details: { documentId: document.id },
      });
      response.json({ document });
    } catch (error) {
      next(error);
    }
  });

  router.patch("/:documentId", requireCsrf, async (request, response, next) => {
    const parsedId = documentIdSchema.safeParse(request.params.documentId);
    const parsedBody = documentSchema.safeParse(request.body);
    if (!parsedId.success || !parsedBody.success) {
      response.status(400).json({ error: "Invalid document request" });
      return;
    }
    try {
      const actor = getActor(request);
      const document = await documentRepository.update(parsedId.data, actor.id, actor.role, parsedBody.data);
      if (!document) {
        await auditDenied(documentRepository, request, parsedId.data, "document.edit");
        reject(response);
        return;
      }
      response.json({ document });
    } catch (error) {
      next(error);
    }
  });

  router.delete("/:documentId", requireCsrf, async (request, response, next) => {
    const parsedId = documentIdSchema.safeParse(request.params.documentId);
    if (!parsedId.success) {
      reject(response);
      return;
    }
    try {
      const actor = getActor(request);
      const deleted = await documentRepository.delete(parsedId.data, actor.id, actor.role);
      if (!deleted) {
        await auditDenied(documentRepository, request, parsedId.data, "document.delete");
        reject(response);
        return;
      }
      response.status(204).end();
    } catch (error) {
      next(error);
    }
  });

  // List permissions for a document (owner or admin can view)
  router.get("/:documentId/permissions", async (request, response, next) => {
    const parsedId = documentIdSchema.safeParse(request.params.documentId);
    if (!parsedId.success) {
      reject(response);
      return;
    }
    try {
      const actor = getActor(request);
      const permissions = await documentRepository.listPermissions(parsedId.data, actor.id, actor.role);
      response.json({ permissions });
    } catch (error) {
      next(error);
    }
  });

  router.put("/:documentId/permissions/:userId", requireCsrf, async (request, response, next) => {
    const parsedDocumentId = documentIdSchema.safeParse(request.params.documentId);
    const parsedUserId = documentIdSchema.safeParse(request.params.userId);
    const parsedPermission = permissionSchema.safeParse(request.body);
    if (!parsedDocumentId.success || !parsedUserId.success || !parsedPermission.success) {
      response.status(400).json({ error: "Invalid permission request" });
      return;
    }
    try {
      const actor = getActor(request);
      const granted = await documentRepository.grant(
        parsedDocumentId.data,
        actor.id,
        actor.role,
        parsedUserId.data,
        parsedPermission.data,
      );
      if (!granted) {
        await auditDenied(documentRepository, request, parsedDocumentId.data, "permission.grant");
        reject(response);
        return;
      }
      response.status(204).end();
    } catch (error) {
      next(error);
    }
  });

  router.delete("/:documentId/permissions/:userId", requireCsrf, async (request, response, next) => {
    const parsedDocumentId = documentIdSchema.safeParse(request.params.documentId);
    const parsedUserId = documentIdSchema.safeParse(request.params.userId);
    if (!parsedDocumentId.success || !parsedUserId.success) {
      response.status(400).json({ error: "Invalid permission request" });
      return;
    }
    try {
      const actor = getActor(request);
      const revoked = await documentRepository.revoke(
        parsedDocumentId.data,
        actor.id,
        actor.role,
        parsedUserId.data,
      );
      if (!revoked) {
        await auditDenied(documentRepository, request, parsedDocumentId.data, "permission.revoke");
        reject(response);
        return;
      }
      response.status(204).end();
    } catch (error) {
      next(error);
    }
  });

  // ── Upload a file to a document record ──────────────────────────────────
  // Requires CSRF + edit permission (owner, admin, or explicit edit grant)
  router.post(
    "/:documentId/upload",
    requireCsrf,
    (req, res, next) => {
      upload.single("file")(req, res, (err) => {
        if (err instanceof multer.MulterError && err.code === "LIMIT_FILE_SIZE") {
          res.status(413).json({ error: `File must be ≤ ${MAX_FILE_BYTES / 1024 / 1024} MiB` });
          return;
        }
        if (err) {
          res.status(400).json({ error: err instanceof Error ? err.message : "Upload error" });
          return;
        }
        next();
      });
    },
    async (request, response, next) => {
      const parsedId = documentIdSchema.safeParse(request.params.documentId);
      if (!parsedId.success) { reject(response); return; }
      if (!request.file) {
        response.status(400).json({ error: "No file provided" });
        return;
      }
      try {
        const actor = getActor(request);
        const { buffer, mimetype, originalname, size } = request.file;

        // Magic-byte validation
        const validationError = validateFileBuffer(buffer, mimetype);
        if (validationError) {
          await documentRepository.appendAudit({
            actorUserId: actor.id,
            documentId: parsedId.data,
            action: "document.upload",
            outcome: "denied",
            details: { reason: validationError, documentId: parsedId.data },
          });
          response.status(415).json({ error: validationError });
          return;
        }

        const objectKey = newObjectKey();
        // Stream from buffer
        const { Readable } = await import("node:stream");
        await storeFile(objectKey, Readable.from(buffer));

        const saved = await documentRepository.updateFileMetadata(
          parsedId.data, actor.id, actor.role,
          { objectKey, originalName: originalname, mimeType: mimetype, fileSize: size },
        );
        if (!saved) {
          // No permission — clean up the orphaned file
          await deleteFile(objectKey);
          await documentRepository.appendAudit({
            actorUserId: actor.id,
            documentId: parsedId.data,
            action: "document.upload",
            outcome: "denied",
            details: { reason: "authorization_denied", requestedDocumentId: parsedId.data },
          });
          reject(response);
          return;
        }
        response.status(204).end();
      } catch (error) {
        next(error);
      }
    },
  );

  // ── Download a file ────────────────────────────────────────────────────────
  // Requires read permission (owner, admin, or explicit read grant)
  router.get("/:documentId/download", async (request, response, next) => {
    const parsedId = documentIdSchema.safeParse(request.params.documentId);
    if (!parsedId.success) { reject(response); return; }
    try {
      const actor = getActor(request);
      const fileInfo = await documentRepository.getObjectKeyForDownload(
        parsedId.data, actor.id, actor.role,
      );
      if (!fileInfo) {
        await documentRepository.appendAudit({
          actorUserId: actor.id,
          documentId: parsedId.data,
          action: "document.download",
          outcome: "denied",
          details: { reason: "authorization_denied", requestedDocumentId: parsedId.data },
        });
        reject(response);
        return;
      }
      await documentRepository.appendAudit({
        actorUserId: actor.id,
        documentId: parsedId.data,
        action: "document.download",
        outcome: "allowed",
        details: { documentId: parsedId.data },
      });
      const served = await serveFile(
        fileInfo.objectKey, fileInfo.originalName, fileInfo.mimeType, response,
      );
      if (!served) {
        response.status(404).json({ error: "File not found on storage" });
      }
    } catch (error) {
      next(error);
    }
  });

  return router;
}
