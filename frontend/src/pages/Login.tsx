import { type FormEvent, useState } from "react";
import { Navigate, useLocation } from "react-router-dom";

import { ApiError } from "../api/client";
import { useAuth } from "../auth/AuthContext";

export function Login() {
  const { user, loading, login, register } = useAuth();
  const location = useLocation();
  const [mode, setMode] = useState<"login" | "register">("login");
  const [tenantId, setTenantId] = useState("demo-bank");
  const [email, setEmail] = useState("");
  const [displayName, setDisplayName] = useState("");
  const [password, setPassword] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  if (!loading && user) {
    const target = (location.state as { from?: { pathname?: string } } | null)?.from?.pathname;
    return <Navigate to={target ?? "/"} replace />;
  }

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setSubmitting(true);
    setError(null);
    try {
      if (mode === "register") {
        await register({ tenant_id: tenantId, email, display_name: displayName, password });
      } else {
        await login({ tenant_id: tenantId, email, password });
      }
    } catch (caught) {
      setError(caught instanceof ApiError ? caught.message : "Unable to reach AegisGraph API");
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <main className="login-page">
      <section className="login-hero">
        <div className="brand brand--large">
          <span className="brand__mark">AG</span>
          <span><strong>AegisGraph AI</strong><small>Fraud Intelligence Platform</small></span>
        </div>
        <div className="login-hero__copy">
          <p className="eyebrow">Privacy-preserving risk operations</p>
          <h1>Detect payment fraud before it becomes a loss.</h1>
          <p>
            Investigate explainable signals from deterministic rules, anomaly models,
            identity intelligence and transaction graphs in one secure console.
          </p>
        </div>
        <div className="signal-grid" aria-hidden="true">
          {Array.from({ length: 20 }, (_, index) => <span key={index} />)}
        </div>
      </section>

      <section className="login-panel">
        <div className="login-card">
          <p className="eyebrow">Secure analyst access</p>
          <h2>{mode === "login" ? "Welcome back" : "Create tenant workspace"}</h2>
          <p className="muted">
            {mode === "login"
              ? "Use your tenant-qualified AegisGraph account."
              : "The first account created for a tenant becomes its administrator."}
          </p>
          <form onSubmit={(event) => void submit(event)}>
            <label>
              Tenant ID
              <input
                autoComplete="organization"
                minLength={3}
                required
                value={tenantId}
                onChange={(event) => setTenantId(event.target.value.toLowerCase())}
              />
            </label>
            {mode === "register" && (
              <label>
                Display name
                <input
                  autoComplete="name"
                  minLength={2}
                  required
                  value={displayName}
                  onChange={(event) => setDisplayName(event.target.value)}
                />
              </label>
            )}
            <label>
              Email
              <input
                type="email"
                autoComplete="email"
                required
                value={email}
                onChange={(event) => setEmail(event.target.value)}
              />
            </label>
            <label>
              Password
              <input
                type="password"
                autoComplete={mode === "login" ? "current-password" : "new-password"}
                minLength={mode === "register" ? 12 : 1}
                required
                value={password}
                onChange={(event) => setPassword(event.target.value)}
              />
            </label>
            {error && <div className="error-banner" role="alert">{error}</div>}
            <button className="button button--primary button--full" disabled={submitting}>
              {submitting ? "Securing session…" : mode === "login" ? "Sign in" : "Create account"}
            </button>
          </form>
          <button
            className="text-button"
            type="button"
            onClick={() => {
              setMode(mode === "login" ? "register" : "login");
              setError(null);
            }}
          >
            {mode === "login" ? "Create the first tenant account" : "Return to sign in"}
          </button>
        </div>
      </section>
    </main>
  );
}
