
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
} from "./api";
import "./style.css";

type View = "documents" | "audit";

function App() {
  const [user, setUser] = useState<User | null>(null);
  const [view, setView] = useState<View>("documents");
  const [documents, setDocuments] = useState<Document[]>([]);
  const [events, setEvents] = useState<AuditEvent[]>([]);
  const [search, setSearch] = useState("");
  const [name, setName] = useState("");
  const [category, setCategory] = useState("General");
  const [editing, setEditing] = useState<number | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");

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

  useEffect(() => {
    if (user) void loadDocuments();
  }, [user, loadDocuments]);

  useEffect(() => {
    if (user?.role === "admin" && view === "audit") void loadAudit();
  }, [user, view, loadAudit]);

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
          <span className="nav-icon">▤</span> Documents
        </button>
        {user.role === "admin" && (
          <>
            <div className="nav-section-label">Administration</div>
            <button
              className={`nav-item ${view === "audit" ? "active" : ""}`}
              onClick={() => setView("audit")}
            >
              <span className="nav-icon">◷</span> Audit log
            </button>
          </>
        )}
      </aside>

      <main className="app-content">
        <div className="page-header">
          <div className="page-header-text">
            <h1 className="page-title">
              {view === "audit" ? "Audit log" : "Your documents"}
            </h1>
            <p className="page-subtitle">
              {view === "audit"
                ? "Review recorded document and security activity."
                : "Create, organize, search, and manage document records."}
            </p>
          </div>
          <button
            className="btn btn-secondary"
            onClick={() => view === "audit" ? void loadAudit() : void loadDocuments()}
            disabled={loading}
          >
            Refresh
          </button>
        </div>

        {error && <div className="alert alert-error" role="alert">{error}</div>}
        {notice && <div className="alert alert-success" role="status">{notice}</div>}

        {view === "documents" && (
          <>
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
                    <span className="search-icon">⌕</span>
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
                    <span className="empty-icon">▤</span>
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
                        <div className="document-card-icon">▤</div>
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
                        <div className="toolbar">
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
                  <span className="empty-icon">◷</span>
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
      </main>
    </div>
  );
}

ReactDOM.createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>
);
