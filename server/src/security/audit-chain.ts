import { createHash } from "node:crypto";

export type ChainAuditEvent = {
  actorUserId: number | null;
  documentId: number | null;
  action: string;
  outcome: "allowed" | "denied";
  details: Record<string, unknown>;
  createdAt: string;
  previousHash: string | null;
  eventHash: string;
};

type HashableAuditEvent = Omit<ChainAuditEvent, "previousHash" | "eventHash">;

function stableValue(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(stableValue);
  if (value !== null && typeof value === "object") {
    return Object.fromEntries(
      Object.entries(value).sort(([left], [right]) => left.localeCompare(right))
        .map(([key, nested]) => [key, stableValue(nested)]),
    );
  }
  return value;
}

export function createAuditEventHash(event: HashableAuditEvent, previousHash: string | null): string {
  return createHash("sha256")
    .update(JSON.stringify(stableValue({ ...event, previousHash })))
    .digest("hex");
}

export function verifyAuditChain(events: readonly ChainAuditEvent[]): boolean {
  let previousHash: string | null = null;
  for (const event of events) {
    if (event.previousHash !== previousHash) return false;
    const expectedHash = createAuditEventHash({
      actorUserId: event.actorUserId,
      documentId: event.documentId,
      action: event.action,
      outcome: event.outcome,
      details: event.details,
      createdAt: event.createdAt,
    }, previousHash);
    if (event.eventHash !== expectedHash) return false;
    previousHash = event.eventHash;
  }
  return true;
}
