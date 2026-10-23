import { Router, type Request, type Response } from "express";
import { z } from "zod";
import { requireAuthentication, requireCsrf } from "../auth/middleware.js";
import type {
  AuditInput,
  DocumentRepository,
  DocumentRole,
} from "../auth/repository.js";
import type { AuthRepository } from "../auth/repository.js";

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

  return router;
}
