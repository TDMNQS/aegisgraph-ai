import { useCallback, useEffect, useMemo, useState } from "react";
import { Link, useParams } from "react-router-dom";

import { ApiError, api } from "../api/client";
import { RiskGauge } from "../components/RiskGauge";
import { StatusBadge } from "../components/StatusBadge";
import type { Alert, AlertStatus } from "../types";

interface Action {
  label: string;
  status: AlertStatus;
  tone: "primary" | "danger" | "secondary";
  needsResolution?: boolean;
}

const ACTIONS: Partial<Record<AlertStatus, Action[]>> = {
  open: [
    { label: "Begin investigation", status: "investigating", tone: "primary" },
    { label: "Mark false positive", status: "false_positive", tone: "secondary", needsResolution: true },
  ],
  assigned: [
    { label: "Begin investigation", status: "investigating", tone: "primary" },
    { label: "Return to queue", status: "open", tone: "secondary" },
  ],
  investigating: [
    { label: "Confirm fraud", status: "confirmed_fraud", tone: "danger", needsResolution: true },
    { label: "Mark false positive", status: "false_positive", tone: "secondary", needsResolution: true },
  ],
  confirmed_fraud: [
    { label: "Close case", status: "closed", tone: "primary", needsResolution: true },
    { label: "Reopen investigation", status: "investigating", tone: "secondary" },
  ],
  false_positive: [
    { label: "Close case", status: "closed", tone: "primary", needsResolution: true },
    { label: "Reopen investigation", status: "investigating", tone: "secondary" },
  ],
};

function labelFor(key: string): string {
  return key.replaceAll("_", " ").replace(/\b\w/g, (letter) => letter.toUpperCase());
}

function displayValue(value: unknown): string {
  if (value === null || value === undefined) return "—";
  if (typeof value === "boolean") return value ? "Yes" : "No";
  if (typeof value === "object") return JSON.stringify(value);
  return String(value);
}

export function Investigation() {
  const { alertId } = useParams<{ alertId: string }>();
  const [alert, setAlert] = useState<Alert | null>(null);
  const [loading, setLoading] = useState(true);
  const [submitting, setSubmitting] = useState<AlertStatus | null>(null);
  const [resolution, setResolution] = useState("");
  const [pendingAction, setPendingAction] = useState<Action | null>(null);
  const [message, setMessage] = useState<{ tone: "error" | "success"; text: string } | null>(null);

  const load = useCallback(async () => {
    if (!alertId) return;
    setLoading(true);
    setMessage(null);
    try {
      setAlert(await api.getAlert(alertId));
    } catch (caught) {
      setMessage({ tone: "error", text: caught instanceof ApiError ? caught.message : "Unable to load alert" });
    } finally {
      setLoading(false);
    }
  }, [alertId]);

  useEffect(() => {
    void load();
  }, [load]);

  const evidence = useMemo(() => Object.entries(alert?.evidence ?? {}), [alert]);

  async function transition(action: Action) {
    if (!alertId || !alert) return;
    if (action.needsResolution && resolution.trim().length < 3) {
      setPendingAction(action);
      setMessage({ tone: "error", text: "Add a resolution note of at least 3 characters." });
      return;
    }
    setSubmitting(action.status);
    setMessage(null);
    try {
      const updated = await api.updateAlert(alertId, {
        status: action.status,
        expected_version: alert.version,
        ...(action.needsResolution ? { resolution: resolution.trim() } : {}),
      });
      setAlert(updated);
      setPendingAction(null);
      setResolution("");
      setMessage({ tone: "success", text: `Alert moved to ${labelFor(updated.status)}.` });
    } catch (caught) {
      const text = caught instanceof ApiError ? caught.message : "Unable to update this investigation";
      setMessage({ tone: "error", text });
      if (caught instanceof ApiError && caught.status === 409) await load();
    } finally {
      setSubmitting(null);
    }
  }

  if (loading) return <main className="center-stage"><span className="spinner" />Loading investigation…</main>;

  if (!alert) {
    return (
      <main className="page"><div className="empty-state empty-state--large"><h1>Alert unavailable</h1><p>{message?.text ?? "This alert could not be found."}</p><Link className="button button--primary" to="/">Return to command center</Link></div></main>
    );
  }

  const actions = ACTIONS[alert.status] ?? [];

  return (
    <main className="page">
      <Link className="back-link" to="/">← Back to command center</Link>
      <section className="investigation-heading">
        <div>
          <div className="heading-status"><StatusBadge value={alert.severity} /><StatusBadge value={alert.status} /></div>
          <h1>{alert.title}</h1>
          <p>{alert.summary}</p>
        </div>
        <RiskGauge score={alert.risk_score} label="Composite risk" />
      </section>

      {message && <div className={`${message.tone === "error" ? "error" : "success"}-banner`} role="status">{message.text}</div>}

      <section className="investigation-grid">
        <div className="investigation-main">
          <article className="panel">
            <div className="panel__heading"><div><p className="eyebrow">Explainability</p><h2>Triggered signals</h2></div><span>{alert.reason_codes.length} signals</span></div>
            <div className="reason-grid">
              {alert.reason_codes.length ? alert.reason_codes.map((code) => (
                <div className="reason-card" key={code}><span aria-hidden="true">⌁</span><div><strong>{labelFor(code)}</strong><small>Contributed to the hybrid risk decision</small></div></div>
              )) : <div className="empty-state">No reason codes were attached.</div>}
            </div>
          </article>

          <article className="panel">
            <div className="panel__heading"><div><p className="eyebrow">Evidence snapshot</p><h2>Decision context</h2></div><small>Immutable at alert creation</small></div>
            <dl className="evidence-grid">
              {evidence.length ? evidence.map(([key, value]) => (
                <div key={key}><dt>{labelFor(key)}</dt><dd>{displayValue(value)}</dd></div>
              )) : <div className="empty-state">No supplementary evidence is available.</div>}
            </dl>
          </article>
        </div>

        <aside className="case-sidebar">
          <article className="panel case-card">
            <p className="eyebrow">Case details</p>
            <dl className="case-facts">
              <div><dt>Alert ID</dt><dd title={alert.id}>{alert.id.slice(0, 8)}…</dd></div>
              <div><dt>Transaction</dt><dd title={alert.transaction_id}>{alert.transaction_id.slice(0, 8)}…</dd></div>
              <div><dt>Version</dt><dd>{alert.version}</dd></div>
              <div><dt>Created</dt><dd>{new Date(alert.created_at).toLocaleString()}</dd></div>
              <div><dt>Assignee</dt><dd>{alert.assigned_to_id ? `${alert.assigned_to_id.slice(0, 8)}…` : "Unassigned"}</dd></div>
            </dl>
          </article>

          <article className="panel decision-card">
            <p className="eyebrow">Analyst decision</p>
            <h2>Resolve investigation</h2>
            {actions.some((action) => action.needsResolution) && (
              <label>Resolution note<textarea rows={5} maxLength={4000} placeholder="Record evidence, rationale and next steps…" value={resolution} onChange={(event) => setResolution(event.target.value)} /></label>
            )}
            <div className="decision-actions">
              {actions.map((action) => (
                <button key={action.status} className={`button button--${action.tone}`} disabled={submitting !== null} onClick={() => { setPendingAction(action); void transition(action); }}>
                  {submitting === action.status ? "Updating…" : action.label}
                </button>
              ))}
              {actions.length === 0 && <p className="muted">This case is closed. Its outcome remains available for audit.</p>}
            </div>
            {pendingAction?.needsResolution && resolution.trim().length < 3 && <small className="field-hint">A resolution note is required for this outcome.</small>}
          </article>
        </aside>
      </section>
    </main>
  );
}

