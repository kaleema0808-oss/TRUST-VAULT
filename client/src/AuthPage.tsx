import React, { useState } from "react";
import { auth, setCsrfToken, type User } from "./api";

type Props = {
  onAuth: (user: User, csrf: string) => void;
};

export function AuthPage({ onAuth }: Props) {
  const [mode, setMode] = useState<"login" | "register">("login");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [requestOwner, setRequestOwner] = useState(false);
  const [requestReason, setRequestReason] = useState("");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    setError("");
    setLoading(true);
    try {
      const result = mode === "login"
        ? await auth.login(email, password)
        : await auth.register(email, password, requestOwner, requestReason);
      setCsrfToken(result.csrfToken);
      onAuth(result.user, result.csrfToken);
    } catch (err: unknown) {
      const e = err as { message?: string };
      setError(e.message ?? "Something went wrong. Please try again.");
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="auth-page">
      <div className="auth-card">
        <div className="auth-logo">
          <div className="brand-icon">🔐</div>
          <h1>TrustVault</h1>
          <p>Secure private document sharing</p>
        </div>

        <form onSubmit={handleSubmit} className="flex-col gap-4" noValidate>
          {error && (
            <div className="alert alert-error" role="alert">
              <span>⚠</span> {error}
            </div>
          )}

          <div className="form-group">
            <label htmlFor="auth-email">Email address</label>
            <input
              id="auth-email"
              type="email"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              placeholder="you@example.com"
              autoComplete={mode === "login" ? "email" : "email"}
              required
            />
          </div>

          <div className="form-group">
            <label htmlFor="auth-password">Password</label>
            <input
              id="auth-password"
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              placeholder={mode === "register" ? "At least 12 characters" : "Your password"}
              autoComplete={mode === "login" ? "current-password" : "new-password"}
              required
            />
          </div>

          {mode === "register" && (
            <div className="flex-col gap-2" style={{ marginTop: "var(--sp-2)" }}>
              <label style={{ display: "flex", alignItems: "flex-start", gap: "var(--sp-2)", cursor: "pointer" }}>
                <input
                  id="auth-request-owner"
                  type="checkbox"
                  checked={requestOwner}
                  onChange={(e) => setRequestOwner(e.target.checked)}
                  style={{ marginTop: "3px", width: "auto" }}
                />
                <span style={{ fontSize: "var(--text-xs)", color: "var(--text-secondary)" }}>
                  Request <strong>Owner</strong> privileges (requires Admin review &amp; approval)
                </span>
              </label>
              {requestOwner && (
                <input
                  id="auth-owner-reason"
                  type="text"
                  value={requestReason}
                  onChange={(e) => setRequestReason(e.target.value)}
                  placeholder="Reason for owner access (optional)"
                  maxLength={255}
                  style={{ fontSize: "var(--text-xs)", padding: "6px 10px" }}
                />
              )}
            </div>
          )}

          <button
            id="auth-submit"
            type="submit"
            className="btn btn-primary btn-lg btn-full mt-4"
            disabled={loading}
          >
            {loading ? (
              <><span className="spinner" /> {mode === "login" ? "Signing in…" : "Creating account…"}</>
            ) : (
              mode === "login" ? "Sign in" : "Create account"
            )}
          </button>
        </form>

        <div className="divider" style={{ marginTop: "var(--sp-6)" }} />

        <p style={{ textAlign: "center", fontSize: "var(--text-sm)", color: "var(--text-muted)" }}>
          {mode === "login" ? "New to TrustVault? " : "Already have an account? "}
          <button
            className="link-text"
            onClick={() => { setMode(mode === "login" ? "register" : "login"); setError(""); }}
          >
            {mode === "login" ? "Create an account" : "Sign in instead"}
          </button>
        </p>
      </div>
    </div>
  );
}
