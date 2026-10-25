
import { useCallback, useEffect, useState } from "react";
import React from "react";
import ReactDOM from "react-dom/client";
import { AuthPage } from "./AuthPage";
import {
  admin,
  auth,
  docs,
  setCsrfToken,
  type AuditEvent,
  type Document,
  type User,
  type Permission,
  type RoleRequest,
} from "./api";
import "./style.css";

type View = "documents" | "audit" | "role-requests";

function App() {
  const [user, setUser] = useState<User | null>(null);
  const [view, setView] = useState<View>("documents");
  const [documents, setDocuments] = useState<Document[]>([]);
  const [events, setEvents] = useState<AuditEvent[]>([]);
  const [roleRequests, setRoleRequests] = useState<RoleRequest[]>([]);
  const [myPendingRequest, setMyPendingRequest] = useState<RoleRequest | null>(null);
  const [search, setSearch] = useState("");
  const [name, setName] = useState("");
  const [category, setCategory] = useState("General");
  const [editing, setEditing] = useState<number | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const [shareDocumentId, setShareDocumentId] = useState<number | null>(null);
  const [availableUsers, setAvailableUsers] = useState<User[]>([]);
  const [permissions, setPermissions] = useState<Record<number, Permission[]>>({});
  const [shareUserId, setShareUserId] = useState("");
  const [shareCanRead, setShareCanRead] = useState(true);
  const [shareCanEdit, setShareCanEdit] = useState(false);
  const [uploadingId, setUploadingId] = useState<number | null>(null);
  const [actionLoadingId, setActionLoadingId] = useState<number | null>(null);
  const [submittingRequest, setSubmittingRequest] = useState(false);
  const [requestReason, setRequestReason] = useState("");

  const loadDocuments = useCallback(async () => {
    setLoading(true);
    setError("");
    try {
      const result = await docs.list();
      setDocuments(result.documents);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Could not load documents.");
    } finally {
      setLoading(false);
    }
  }, []);

  const loadAudit = useCallback(async () => {
    setLoading(true);
    setError("");
    try {
      const result = await admin.auditEvents({ limit: 100 });
      setEvents(result.events);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Could not load audit events.");
    } finally {
      setLoading(false);
    }
  }, []);

  const loadRoleRequests = useCallback(async () => {
    setLoading(true);
    setError("");
    try {
      const result = await admin.listRoleRequests();
      setRoleRequests(result.requests);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Could not load role requests.");
    } finally {
      setLoading(false);
    }
  }, []);

  const checkMyRoleRequest = useCallback(async () => {
    try {
      const result = await auth.myRoleRequest();
      setMyPendingRequest(result.request);
    } catch {
      // ignore
    }
  }, []);

  useEffect(() => {
    if (user) {
      void loadDocuments();
      if (user.role === "viewer") {
        void checkMyRoleRequest();
      }
      if (user.role === "admin") {
        void loadRoleRequests();
      }
    }
  }, [user, loadDocuments, checkMyRoleRequest, loadRoleRequests]);

  useEffect(() => {
    if (user?.role === "admin" && view === "audit") void loadAudit();
    if (user?.role === "admin" && view === "role-requests") void loadRoleRequests();
  }, [user, view, loadAudit, loadRoleRequests]);

  async function handleApprove(requestId: number) {
    setError("");
    setNotice("");
    setActionLoadingId(requestId);
    try {
      await admin.approveRoleRequest(requestId);
      setNotice("Owner access approved successfully.");
      await loadRoleRequests();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to approve request.");
    } finally {
      setActionLoadingId(null);
    }
  }

  async function handleReject(requestId: number) {
    const reason = window.prompt("Reason for rejection (optional):") ?? undefined;
    setError("");
    setNotice("");
    setActionLoadingId(requestId);
    try {
      await admin.rejectRoleRequest(requestId, reason);
      setNotice("Owner access request rejected.");
      await loadRoleRequests();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to reject request.");
    } finally {
      setActionLoadingId(null);
    }
  }

  async function handleRequestOwner() {
    setError("");
    setNotice("");
    setSubmittingRequest(true);
    try {
      await auth.requestOwner(requestReason.trim() || undefined);
      setNotice("Owner access request submitted! An administrator will review your request.");
      setRequestReason("");
      await checkMyRoleRequest();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to submit owner request.");
    } finally {
      setSubmittingRequest(false);
    }
  }

  if (!user) {
    return (
      <AuthPage
        onAuth={(signedInUser, csrf) => {
          setCsrfToken(csrf);
          setUser(signedInUser);
          setNotice("");
          setError("");
        }}
      />
    );
  }

  const canCreate = user.role === "admin" || user.role === "owner";

  const visibleDocuments = documents.filter((document) =>
    `${document.name} ${document.category}`
      .toLowerCase()
      .includes(search.toLowerCase())
  );

  async function saveDocument(event: React.FormEvent) {
    event.preventDefault();
    setError("");
    setNotice("");

    try {
      if (editing === null) {
        await docs.create(name, category);
        setNotice("Document created successfully.");
      } else {
        await docs.update(editing, name, category);
        setNotice("Document updated successfully.");
      }

      setName("");
      setCategory("General");
      setEditing(null);
      await loadDocuments();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Could not save document.");
    }
  }

  function startEdit(document: Document) {
    setEditing(document.id);
    setName(document.name);
    setCategory(document.category);
    setNotice("");
    setError("");
    window.scrollTo({ top: 0, behavior: "smooth" });
  }

  async function deleteDocument(document: Document) {
    if (!window.confirm(`Delete "${document.name}"? This cannot be undone.`)) {
      return;
    }

    setError("");
    setNotice("");

    try {
      await docs.delete(document.id);
      setNotice("Document deleted.");
      if (editing === document.id) {
        setEditing(null);
        setName("");
        setCategory("General");
      }
      await loadDocuments();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Could not delete document.");
    }
  }

  async function uploadFile(docId: number, file: File) {
    setError("");
    setNotice("");
    setUploadingId(docId);
    try {
      const result = await docs.upload(docId, file);
      setDocuments((prev) => prev.map((doc) => (doc.id === docId ? result.document : doc)));
      setNotice(`File "${file.name}" uploaded successfully.`);
    } catch (err) {
      setError(err instanceof Error ? err.message : "File upload failed.");
    } finally {
      setUploadingId(null);
    }
  }

  async function downloadFile(document: Document) {
    setError("");
    try {
      await docs.download(document.id, document.originalName || `${document.name}.bin`);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Download failed.");
    }
  }
  async function openSharing(document: Document) {
    setError("");
    setNotice("");
    try {
      const [userResult, permissionResult] = await Promise.all([
        auth.users(),
        docs.listPermissions(document.id),
      ]);
      setAvailableUsers(userResult.users.filter((candidate) => candidate.id !== user?.id));
      setPermissions((current) => ({
        ...current,
        [document.id]: permissionResult.permissions,
      }));
      setShareDocumentId(document.id);
      setShareUserId("");
      setShareCanRead(true);
      setShareCanEdit(false);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Could not load sharing settings.");
    }
  }

  async function refreshPermissions(documentId: number) {
    const result = await docs.listPermissions(documentId);
    setPermissions((current) => ({
      ...current,
      [documentId]: result.permissions,
    }));
  }

  async function saveSharing() {
    if (shareDocumentId === null || !shareUserId) {
      setError("Select a user first.");
      return;
    }
    setError("");
    setNotice("");
    try {
      await docs.grant(
        shareDocumentId,
        Number(shareUserId),
        shareCanRead,
        shareCanEdit
      );
      await refreshPermissions(shareDocumentId);
      setNotice("Document access updated successfully.");
      setShareUserId("");
      setShareCanRead(true);
      setShareCanEdit(false);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Could not grant document access.");
    }
  }

  async function revokeSharing(documentId: number, targetUserId: number) {
    setError("");
    setNotice("");
    try {
      await docs.revoke(documentId, targetUserId);
      await refreshPermissions(documentId);
      setNotice("Document access revoked.");
    } catch (err) {
      setError(err instanceof Error ? err.message : "Could not revoke document access.");
    }
  }
  async function logout() {
    setError("");
    try {
      await auth.logout();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Logout failed.");
      return;
    }

    setCsrfToken("");
    setUser(null);
    setDocuments([]);
    setEvents([]);
    setView("documents");
  }

  return (
    <div className="app-shell">
      <header className="app-topbar">
        <a className="brand" href="#" onClick={(event) => event.preventDefault()}>
          <span className="brand-icon">T</span>
          TrustVault
        </a>
        <span className="topbar-spacer" />
        <div className="topbar-user">
          <span>{user.email}</span>
          <span className={`role-badge ${user.role}`}>{user.role}</span>
          <button className="btn btn-secondary btn-sm" onClick={logout}>
            Sign out
          </button>
        </div>
      </header>

      <aside className="app-sidebar">
        <div className="nav-section-label">Workspace</div>
        <button
          className={`nav-item ${view === "documents" ? "active" : ""}`}
          onClick={() => setView("documents")}
        >
          <span className="nav-icon">📄</span> Documents
        </button>
        {user.role === "admin" && (
          <>
            <div className="nav-section-label">Administration</div>
            <button
              className={`nav-item ${view === "role-requests" ? "active" : ""}`}
              onClick={() => setView("role-requests")}
            >
              <span className="nav-icon">👤</span> Owner requests
              {roleRequests.filter((r) => r.status === "pending").length > 0 && (
                <span className="tag" style={{ marginLeft: "auto", background: "rgba(245,165,36,.2)", color: "var(--accent-warn)" }}>
                  {roleRequests.filter((r) => r.status === "pending").length}
                </span>
              )}
            </button>
            <button
              className={`nav-item ${view === "audit" ? "active" : ""}`}
              onClick={() => setView("audit")}
            >
              <span className="nav-icon">📜</span> Audit log
            </button>
          </>
        )}
      </aside>

      <main className="app-content">
        <div className="page-header">
          <div className="page-header-text">
            <h1 className="page-title">
              {view === "audit" ? "Audit log" : view === "role-requests" ? "Owner access requests" : "Your documents"}
            </h1>
            <p className="page-subtitle">
              {view === "audit"
                ? "Review recorded document and security activity."
                : view === "role-requests"
                ? "Review and approve or reject user requests for Owner privileges."
                : "Create, organize, search, and manage document records."}
            </p>
          </div>
          <button
            className="btn btn-secondary"
            onClick={() => {
              if (view === "audit") void loadAudit();
              else if (view === "role-requests") void loadRoleRequests();
              else void loadDocuments();
            }}
            disabled={loading}
          >
            Refresh
          </button>
        </div>

        {error && <div className="alert alert-error" role="alert">{error}</div>}
        {notice && <div className="alert alert-success" role="status">{notice}</div>}

        {view === "documents" && (
          <>
            {user.role === "viewer" && (
              myPendingRequest ? (
                <div className="alert alert-info" style={{ display: "flex", alignItems: "center", gap: "var(--sp-3)" }}>
                  <span style={{ fontSize: "1.2rem" }}>⏳</span>
                  <div>
                    <strong>Owner Access Pending Approval</strong>
                    <p style={{ margin: 0, fontSize: "var(--text-xs)", opacity: 0.85 }}>
                      Your request for Owner privileges has been submitted and is awaiting administrator review. As a Viewer, you can view documents shared with you.
                    </p>
                  </div>
                </div>
              ) : (
                <div className="card" style={{ padding: "var(--sp-4)", display: "flex", alignItems: "center", justifyContent: "space-between", gap: "var(--sp-4)", flexWrap: "wrap" }}>
                  <div>
                    <strong style={{ fontSize: "var(--text-sm)" }}>Want to create and upload documents?</strong>
                    <p style={{ margin: 0, fontSize: "var(--text-xs)", color: "var(--text-muted)" }}>
                      Request Owner privileges to create private documents. Requests require Administrator approval.
                    </p>
                  </div>
                  <div style={{ display: "flex", gap: "var(--sp-2)", alignItems: "center" }}>
                    <input
                      type="text"
                      placeholder="Optional reason note"
                      value={requestReason}
                      onChange={(e) => setRequestReason(e.target.value)}
                      maxLength={255}
                      style={{ fontSize: "var(--text-xs)", padding: "6px 10px", width: "180px" }}
                    />
                    <button
                      className="btn btn-primary btn-sm"
                      type="button"
                      onClick={() => void handleRequestOwner()}
                      disabled={submittingRequest}
                    >
                      {submittingRequest ? "Submitting…" : "Request Owner Access"}
                    </button>
                  </div>
                </div>
              )
            )}
            <div className="stats-grid">
              <div className="stat-card">
                <span className="stat-label">Accessible documents</span>
                <span className="stat-value">{documents.length}</span>
                <span className="stat-desc">Records available to your account</span>
              </div>
              <div className="stat-card">
                <span className="stat-label">Account role</span>
                <span className="stat-value" style={{ fontSize: "var(--text-2xl)" }}>
                  {user.role}
                </span>
                <span className="stat-desc">Access is enforced by the server</span>
              </div>
            </div>

            {canCreate && (
              <section className="card">
                <div className="card-header">
                  <h2 className="card-title">
                    {editing === null ? "Create a document record" : "Edit document record"}
                  </h2>
                </div>
                <div className="card-body">
                  <form onSubmit={saveDocument} className="flex-col gap-4">
                    <div className="form-group">
                      <label htmlFor="document-name">Document name</label>
                      <input
                        id="document-name"
                        type="text"
                        maxLength={255}
                        value={name}
                        onChange={(event) => setName(event.target.value)}
                        placeholder="e.g. Project proposal"
                        required
                      />
                    </div>
                    <div className="form-group">
                      <label htmlFor="document-category">Category</label>
                      <input
                        id="document-category"
                        type="text"
                        maxLength={100}
                        value={category}
                        onChange={(event) => setCategory(event.target.value)}
                        placeholder="e.g. Work, Personal, Finance"
                        required
                      />
                    </div>
                    <div className="toolbar">
                      <button className="btn btn-primary" type="submit">
                        {editing === null ? "Create record" : "Save changes"}
                      </button>
                      {editing !== null && (
                        <button
                          className="btn btn-secondary"
                          type="button"
                          onClick={() => {
                            setEditing(null);
                            setName("");
                            setCategory("General");
                          }}
                        >
                          Cancel edit
                        </button>
                      )}
                    </div>
                  </form>
                </div>
              </section>
            )}

            <section className="card">
              <div className="card-header">
                <h2 className="card-title">Document library</h2>
                <span className="tag">{visibleDocuments.length} records</span>
              </div>
              <div className="card-body">
                <div className="toolbar">
                  <div className="search-bar">
                    <span className="search-icon">âŒ•</span>
                    <input
                      type="text"
                      aria-label="Search documents"
                      placeholder="Search by name or category..."
                      value={search}
                      onChange={(event) => setSearch(event.target.value)}
                    />
                  </div>
                </div>

                {loading ? (
                  <div className="empty-state">
                    <span className="spinner spinner-lg" />
                    <p>Loading documents...</p>
                  </div>
                ) : visibleDocuments.length === 0 ? (
                  <div className="empty-state">
                    <span className="empty-icon">â–¤</span>
                    <h3>{search ? "No matching records" : "No documents yet"}</h3>
                    <p>
                      {search
                        ? "Try a different search term."
                        : "Create a document record above to get started."}
                    </p>
                  </div>
                ) : (
                  <div className="document-grid">
                    {visibleDocuments.map((document) => (
                      <article className="document-card" key={document.id}>
                        <div className="document-card-icon">â–¤</div>
                        <h3 className="document-card-name">{document.name}</h3>
                        <span className="document-card-category">{document.category}</span>
                        <div className="document-card-meta">
                          <span>Record #{document.id}</span>
                          <span>
                            {document.updatedAt
                              ? new Date(document.updatedAt).toLocaleDateString()
                              : ""}
                          </span>
                        </div>
                        {document.originalName && (
                          <div style={{ marginTop: "6px", fontSize: "var(--text-xs)", color: "var(--accent-success)" }}>
                            Attached: {document.originalName}{" "}
                            {document.fileSize ? `(${Math.round(document.fileSize / 1024)} KB)` : ""}
                          </div>
                        )}
                        <div className="toolbar" style={{ flexWrap: "wrap", gap: "8px" }}>
                          {document.originalName && (
                            <button
                              className="btn btn-secondary btn-sm"
                              onClick={() => void downloadFile(document)}
                            >
                              Download
                            </button>
                          )}
                          <label className="btn btn-secondary btn-sm" style={{ cursor: "pointer", margin: 0 }}>
                            {uploadingId === document.id ? "Uploading..." : document.originalName ? "Replace file" : "Upload file"}
                            <input
                              type="file"
                              style={{ display: "none" }}
                              disabled={uploadingId === document.id}
                              onChange={(e) => {
                                const file = e.target.files?.[0];
                                if (file) {
                                  void uploadFile(document.id, file);
                                }
                                e.target.value = "";
                              }}
                            />
                          </label>
                          <button
                            className="btn btn-secondary btn-sm"
                            onClick={() => startEdit(document)}
                          >
                            Edit
                          </button>
                          <button
                            className="btn btn-danger btn-sm"
                            onClick={() => void deleteDocument(document)}
                          >
                            Delete
                          </button>
                        </div>
                        {canCreate && (
                          <div className="share-panel" style={{ marginTop: "16px", paddingTop: "12px", borderTop: "1px solid var(--border)" }}>
                            <button
                              className="btn btn-secondary btn-sm"
                              type="button"
                              onClick={() => {
                                if (shareDocumentId === document.id) {
                                  setShareDocumentId(null);
                                } else {
                                  void openSharing(document);
                                }
                              }}
                            >
                              {shareDocumentId === document.id ? "Close sharing" : "Share / Manage access"}
                            </button>

                            {shareDocumentId === document.id && (
                              <div style={{ marginTop: "12px" }}>
                                <div className="form-group">
                                  <label htmlFor={`share-user-${document.id}`}>Grant access to user</label>
                                  <select
                                    id={`share-user-${document.id}`}
                                    value={shareUserId}
                                    onChange={(event) => setShareUserId(event.target.value)}
                                  >
                                    <option value="">Select a user...</option>
                                    {availableUsers.map((candidate) => (
                                      <option key={candidate.id} value={candidate.id}>
                                        {candidate.email} ({candidate.role})
                                      </option>
                                    ))}
                                  </select>
                                </div>

                                <label style={{ display: "block", margin: "8px 0" }}>
                                  <input
                                    type="checkbox"
                                    checked={shareCanRead}
                                    onChange={(event) => {
                                      setShareCanRead(event.target.checked);
                                      if (!event.target.checked) setShareCanEdit(false);
                                    }}
                                  />{" "}
                                  Read access
                                </label>
                                <label style={{ display: "block", margin: "8px 0" }}>
                                  <input
                                    type="checkbox"
                                    checked={shareCanEdit}
                                    onChange={(event) => {
                                      setShareCanEdit(event.target.checked);
                                      if (event.target.checked) setShareCanRead(true);
                                    }}
                                  />{" "}
                                  Edit access (includes read access)
                                </label>

                                <button
                                  className="btn btn-primary btn-sm"
                                  type="button"
                                  disabled={!shareUserId || (!shareCanRead && !shareCanEdit)}
                                  onClick={() => void saveSharing()}
                                >
                                  Grant access
                                </button>

                                <h4 style={{ marginTop: "16px" }}>Users with access</h4>
                                {(permissions[document.id] ?? []).length === 0 ? (
                                  <p className="page-subtitle">No explicit permissions are listed.</p>
                                ) : (
                                  (permissions[document.id] ?? []).map((permission) => (
                                    <div
                                      key={permission.userId}
                                      style={{ display: "flex", alignItems: "center", justifyContent: "space-between", gap: "8px", marginTop: "8px" }}
                                    >
                                      <span>
                                        {permission.email}
                                        {" — "}
                                        {permission.canEdit ? "Read + edit" : permission.canRead ? "Read only" : "No access"}
                                      </span>
                                      <button
                                        className="btn btn-danger btn-sm"
                                        type="button"
                                        onClick={() => void revokeSharing(document.id, permission.userId)}
                                      >
                                        Revoke
                                      </button>
                                    </div>
                                  ))
                                )}
                              </div>
                            )}
                          </div>
                        )}
                      </article>
                    ))}
                  </div>
                )}
              </div>
            </section>
            <p className="page-subtitle">
              These are document records, not uploaded file contents. File storage and
              download are not implemented by this screen.
            </p>
          </>
        )}

        {view === "audit" && user.role === "admin" && (
          <section className="card">
            <div className="card-header">
              <h2 className="card-title">Recent activity</h2>
              <span className="tag">{events.length} events</span>
            </div>
            <div className="card-body">
              {loading ? (
                <div className="empty-state"><span className="spinner spinner-lg" /></div>
              ) : events.length === 0 ? (
                <div className="empty-state">
                  <span className="empty-icon">📜</span>
                  <h3>No activity recorded yet</h3>
                  <p>Document actions will appear here when recorded by the server.</p>
                </div>
              ) : (
                events.map((event) => (
                  <div className="audit-item" key={event.id}>
                    <span className={`audit-dot ${event.outcome}`} />
                    <div className="audit-content">
                      <div className="audit-action">{event.action}</div>
                      <div className="audit-meta">
                        {event.actorEmail ?? `User #${event.actorUserId ?? "unknown"}`}
                        {" · "}
                        {new Date(event.createdAt).toLocaleString()}
                        {event.documentId !== null && ` · Document #${event.documentId}`}
                      </div>
                      <span className={`outcome-badge ${event.outcome}`}>
                        {event.outcome}
                      </span>
                    </div>
                  </div>
                ))
              )}
            </div>
          </section>
        )}

        {view === "role-requests" && user.role === "admin" && (
          <section className="card">
            <div className="card-header">
              <h2 className="card-title">Owner access requests</h2>
              <span className="tag">
                {roleRequests.filter((r) => r.status === "pending").length} pending
              </span>
            </div>
            <div className="card-body">
              {loading ? (
                <div className="empty-state"><span className="spinner spinner-lg" /></div>
              ) : roleRequests.length === 0 ? (
                <div className="empty-state">
                  <span className="empty-icon">👥</span>
                  <h3>No role requests found</h3>
                  <p>When viewers request Owner privileges, their requests will appear here for review.</p>
                </div>
              ) : (
                <div className="flex-col gap-4">
                  {roleRequests.map((req) => (
                    <div
                      key={req.id}
                      className="card"
                      style={{
                        padding: "var(--sp-4)",
                        background: "var(--bg-overlay)",
                        display: "flex",
                        alignItems: "center",
                        justifyContent: "space-between",
                        flexWrap: "wrap",
                        gap: "var(--sp-4)",
                      }}
                    >
                      <div style={{ flex: 1, minWidth: "220px" }}>
                        <div style={{ display: "flex", alignItems: "center", gap: "var(--sp-2)", flexWrap: "wrap" }}>
                          <span style={{ fontWeight: 600, fontSize: "var(--text-base)" }}>{req.userEmail}</span>
                          <span className={`status-badge ${req.status}`}>{req.status}</span>
                          <span className="tag" style={{ textTransform: "capitalize" }}>Target: {req.requestedRole}</span>
                        </div>
                        <div style={{ fontSize: "var(--text-xs)", color: "var(--text-muted)", marginTop: "4px" }}>
                          Requested: {new Date(req.createdAt).toLocaleString()}
                          {req.reason && ` · Note: "${req.reason}"`}
                        </div>
                        {req.status !== "pending" && (
                          <div style={{ fontSize: "var(--text-xs)", color: "var(--text-secondary)", marginTop: "2px" }}>
                            {req.status === "approved" ? "Approved" : "Rejected"} by: {req.reviewedByEmail ?? `Admin #${req.reviewedBy}`}
                            {req.reviewedAt && ` on ${new Date(req.reviewedAt).toLocaleString()}`}
                          </div>
                        )}
                      </div>

                      {req.status === "pending" && (
                        <div style={{ display: "flex", gap: "var(--sp-2)" }}>
                          <button
                            id={`approve-request-${req.id}`}
                            className="btn btn-primary btn-sm"
                            type="button"
                            disabled={actionLoadingId === req.id}
                            onClick={() => void handleApprove(req.id)}
                          >
                            {actionLoadingId === req.id ? "Processing…" : "✓ Approve"}
                          </button>
                          <button
                            id={`reject-request-${req.id}`}
                            className="btn btn-danger btn-sm"
                            type="button"
                            disabled={actionLoadingId === req.id}
                            onClick={() => void handleReject(req.id)}
                          >
                            ✕ Reject
                          </button>
                        </div>
                      )}
                    </div>
                  ))}
                </div>
              )}
            </div>
          </section>
        )}
      </main>
    </div>
  );
}

ReactDOM.createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>
);


