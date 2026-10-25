// API client — all server communication goes through here.
// Credentials (session cookie) are included automatically.
// The CSRF token is stored in module state and sent on mutating requests.

const BASE = (import.meta.env.VITE_API_BASE_URL ?? "").replace(/\/$/, "");
let csrfToken = "";

export function setCsrfToken(token: string) { csrfToken = token; }

type Opts = { method?: string; body?: unknown; signal?: AbortSignal };

async function request<T>(path: string, opts: Opts = {}): Promise<T> {
  const method = opts.method ?? "GET";
  const headers: Record<string, string> = { "Content-Type": "application/json" };
  if (csrfToken && ["POST", "PUT", "PATCH", "DELETE"].includes(method)) {
    headers["X-CSRF-Token"] = csrfToken;
  }
  const res = await fetch(`${BASE}${path}`, {
    method,
    headers,
    credentials: "include",
    ...(opts.body !== undefined ? { body: JSON.stringify(opts.body) } : {}),
    ...(opts.signal ? { signal: opts.signal } : {}),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({ error: "Request failed" }));
    throw Object.assign(new Error(err.error ?? "Request failed"), { status: res.status, data: err });
  }
  if (res.status === 204) return undefined as T;
  return res.json() as Promise<T>;
}

// ---- Types --------------------------------------------------------
export type UserRole = "admin" | "owner" | "viewer";
export type User = { id: number; email: string; role: UserRole };
export type Document = {
  id: number; ownerId: number; name: string; category: string;
  originalName?: string | null; mimeType?: string | null; fileSize?: number | null;
  createdAt: string; updatedAt: string;
};
export type Permission = {
  userId: number; email: string; canRead: boolean; canEdit: boolean; grantedBy: number;
};
export type AuditEvent = {
  id: number; actorUserId: number | null; actorEmail?: string;
  documentId: number | null; action: string; outcome: "allowed" | "denied";
  details: Record<string, unknown>; createdAt: string;
};
export type RoleRequestStatus = "pending" | "approved" | "rejected";
export type RoleRequest = {
  id: number;
  userId: number;
  userEmail: string;
  requestedRole: "owner";
  status: RoleRequestStatus;
  reason: string | null;
  reviewedBy: number | null;
  reviewedByEmail?: string | null;
  reviewedAt: string | null;
  createdAt: string;
  updatedAt: string;
};

// ---- Auth ---------------------------------------------------------
export const auth = {
  async register(email: string, password: string, requestOwner?: boolean, reason?: string) {
    return request<{ user: User; csrfToken: string; pendingRoleRequest?: boolean }>("/api/auth/register", {
      method: "POST", body: { email, password, ...(requestOwner ? { requestOwner: true, reason } : {}) },
    });
  },
  async login(email: string, password: string) {
    return request<{ user: User; csrfToken: string }>("/api/auth/login", {
      method: "POST", body: { email, password },
    });
  },
  async me() {
    return request<{ user: User; pendingOwnerRequest?: boolean }>("/api/auth/me");
  },
  async requestOwner(reason?: string) {
    return request<{ request: RoleRequest }>("/api/auth/role-requests", {
      method: "POST", body: { reason },
    });
  },
  async myRoleRequest() {
    return request<{ request: RoleRequest | null }>("/api/auth/role-requests/mine");
  },
  async logout() {
    await request<void>("/api/auth/logout", { method: "POST", body: {} });
  },
  async users() {
    return request<{ users: User[] }>("/api/auth/users");
  },
};

// ---- Documents ----------------------------------------------------
export const docs = {
  async list() {
    return request<{ documents: Document[] }>("/api/documents");
  },
  async get(id: number) {
    return request<{ document: Document }>(`/api/documents/${id}`);
  },
  async create(name: string, category: string) {
    return request<{ document: Document }>("/api/documents", {
      method: "POST", body: { name, category },
    });
  },
  async update(id: number, name: string, category: string) {
    return request<{ document: Document }>(`/api/documents/${id}`, {
      method: "PATCH", body: { name, category },
    });
  },
  async delete(id: number) {
    await request<void>(`/api/documents/${id}`, { method: "DELETE" });
  },
  async listPermissions(id: number) {
    return request<{ permissions: Permission[] }>(`/api/documents/${id}/permissions`);
  },
  async grant(documentId: number, userId: number, canRead: boolean, canEdit: boolean) {
    await request<void>(`/api/documents/${documentId}/permissions/${userId}`, {
      method: "PUT", body: { canRead, canEdit },
    });
  },
  async revoke(documentId: number, userId: number) {
    await request<void>(`/api/documents/${documentId}/permissions/${userId}`, {
      method: "DELETE",
    });
  },
  async upload(documentId: number, file: File) {
    const formData = new FormData();
    formData.append("file", file);
    const headers: Record<string, string> = {};
    if (csrfToken) {
      headers["X-CSRF-Token"] = csrfToken;
    }
    const res = await fetch(`${BASE}/api/documents/${documentId}/upload`, {
      method: "POST",
      headers,
      credentials: "include",
      body: formData,
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({ error: "Upload failed" }));
      throw Object.assign(new Error(err.error ?? "Upload failed"), { status: res.status, data: err });
    }
    return res.json() as Promise<{ document: Document }>;
  },
  async download(documentId: number, filename?: string) {
    const res = await fetch(`${BASE}/api/documents/${documentId}/download`, {
      method: "GET",
      credentials: "include",
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({ error: "Download failed" }));
      throw Object.assign(new Error(err.error ?? "Download failed"), { status: res.status, data: err });
    }
    const blob = await res.blob();
    const url = window.URL.createObjectURL(blob);
    const a = window.document.createElement("a");
    a.href = url;
    a.download = filename || `document-${documentId}`;
    window.document.body.appendChild(a);
    a.click();
    window.document.body.removeChild(a);
    window.URL.revokeObjectURL(url);
  },
};

// ---- Admin --------------------------------------------------------
export const admin = {
  async auditEvents(params: {
    actorUserId?: number; action?: string; outcome?: "allowed" | "denied";
    limit?: number; offset?: number;
  } = {}) {
    const qs = new URLSearchParams();
    if (params.actorUserId) qs.set("actorUserId", String(params.actorUserId));
    if (params.action) qs.set("action", params.action);
    if (params.outcome) qs.set("outcome", params.outcome);
    if (params.limit) qs.set("limit", String(params.limit));
    if (params.offset) qs.set("offset", String(params.offset));
    const q = qs.toString();
    return request<{ events: AuditEvent[] }>(`/api/admin/audit${q ? `?${q}` : ""}`);
  },
  async listRoleRequests(status?: RoleRequestStatus) {
    const qs = status ? `?status=${status}` : "";
    return request<{ requests: RoleRequest[] }>(`/api/admin/role-requests${qs}`);
  },
  async approveRoleRequest(id: number) {
    return request<{ message: string; request: RoleRequest }>(`/api/admin/role-requests/${id}/approve`, {
      method: "POST", body: {},
    });
  },
  async rejectRoleRequest(id: number, reason?: string) {
    return request<{ message: string; request: RoleRequest }>(`/api/admin/role-requests/${id}/reject`, {
      method: "POST", body: { reason },
    });
  },
};
