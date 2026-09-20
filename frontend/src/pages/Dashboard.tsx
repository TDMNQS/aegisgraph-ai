import { useCallback, useEffect, useMemo, useState } from "react";
import { Link } from "react-router-dom";

import { ApiError, api } from "../api/client";
import { RiskGauge } from "../components/RiskGauge";
import { StatusBadge } from "../components/StatusBadge";
import type { Alert, AlertStatus, Transaction } from "../types";

type QueueFilter = "active" | AlertStatus | "all";

const ACTIVE_ALERTS = new Set<AlertStatus>(["open", "assigned", "investigating"]);

function numberOf(value: number | string): number {
  const parsed = typeof value === "number" ? value : Number.parseFloat(value);
  return Number.isFinite(parsed) ? parsed : 0;
}

function formatMoney(amount: number | string, currency: string): string {
  try {
    return new Intl.NumberFormat("en-US", {
      style: "currency",
      currency,
      maximumFractionDigits: 2,
    }).format(numberOf(amount));
  } catch {
    return `${currency} ${numberOf(amount).toFixed(2)}`;
  }
}

function formatTime(value: string): string {
  return new Intl.DateTimeFormat("en", {
    month: "short",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
  }).format(new Date(value));
}

export function Dashboard() {
  const [transactions, setTransactions] = useState<Transaction[]>([]);
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [filter, setFilter] = useState<QueueFilter>("active");
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [simulating, setSimulating] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [updatedAt, setUpdatedAt] = useState<Date | null>(null);

  const load = useCallback(async (quiet = false) => {
    quiet ? setRefreshing(true) : setLoading(true);
    setError(null);
    try {
      const [transactionData, alertData] = await Promise.all([
        api.getTransactions(100),
        api.getAlerts(undefined, 100),
      ]);
      setTransactions(transactionData);
      setAlerts(alertData);
      setUpdatedAt(new Date());
    } catch (caught) {
      setError(caught instanceof ApiError ? caught.message : "Unable to load fraud telemetry");
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  const simulateFraud = useCallback(async () => {
    setSimulating(true);
    setError(null);
    try {
      await api.simulateFraud("account_takeover");
      await load(true);
    } catch (caught) {
      setError(caught instanceof ApiError ? caught.message : "Unable to run fraud simulation");
    } finally {
      setSimulating(false);
    }
  }, [load]);

  const metrics = useMemo(() => {
    const scores = transactions.map((transaction) => numberOf(transaction.risk_score));
    return {
      volume: transactions.length,
      challenged: transactions.filter(
        (transaction) => transaction.decision === "review" || transaction.decision === "block",
      ).length,
      activeAlerts: alerts.filter((alert) => ACTIVE_ALERTS.has(alert.status)).length,
      averageRisk: scores.length
        ? scores.reduce((total, score) => total + score, 0) / scores.length
        : 0,
    };
  }, [alerts, transactions]);

  const filteredAlerts = useMemo(() => {
    if (filter === "all") return alerts;
    if (filter === "active") return alerts.filter((alert) => ACTIVE_ALERTS.has(alert.status));
    return alerts.filter((alert) => alert.status === filter);
  }, [alerts, filter]);

  if (loading) {
    return <main className="center-stage"><span className="spinner" />Loading risk operations…</main>;
  }

  return (
    <main className="page">
      <section className="page-heading">
        <div>
          <p className="eyebrow">Live risk operations</p>
          <h1>Fraud command center</h1>
          <p className="muted">Prioritize payment risk and move alerts through a traceable investigation.</p>
        </div>
        <div className="heading-actions">
          {updatedAt && <small>Updated {updatedAt.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })}</small>}
          <button className="button" disabled={simulating} onClick={() => void simulateFraud()}>
            {simulating ? "Scoring payment…" : "Simulate fraud"}
          </button>
          <button className="button button--secondary" disabled={refreshing} onClick={() => void load(true)}>
            {refreshing ? "Refreshing…" : "Refresh data"}
          </button>
        </div>
      </section>

      {error && (
        <div className="error-banner error-banner--row" role="alert">
          <span>{error}</span>
          <button className="text-button" type="button" onClick={() => void load()}>Try again</button>
        </div>
      )}

      <section className="metrics-grid" aria-label="Risk overview">
        <article className="metric-card metric-card--gauge">
          <RiskGauge score={metrics.averageRisk} label="Average portfolio risk" size={132} />
        </article>
        <article className="metric-card">
          <span className="metric-card__icon metric-card__icon--blue">↗</span>
          <p>Observed transactions</p>
          <strong>{metrics.volume.toLocaleString()}</strong>
          <small>Latest bounded API window</small>
        </article>
        <article className="metric-card">
          <span className="metric-card__icon metric-card__icon--amber">!</span>
          <p>Challenged payments</p>
          <strong>{metrics.challenged.toLocaleString()}</strong>
          <small>Review or block decisions</small>
        </article>
        <article className="metric-card">
          <span className="metric-card__icon metric-card__icon--red">◆</span>
          <p>Active alerts</p>
          <strong>{metrics.activeAlerts.toLocaleString()}</strong>
          <small>Awaiting analyst resolution</small>
        </article>
      </section>

      <section className="dashboard-grid">
        <article className="panel panel--alerts">
          <div className="panel__heading">
            <div><p className="eyebrow">Work queue</p><h2>Priority alerts</h2></div>
            <select value={filter} onChange={(event) => setFilter(event.target.value as QueueFilter)} aria-label="Filter alerts">
              <option value="active">Active</option>
              <option value="open">Open</option>
              <option value="investigating">Investigating</option>
              <option value="confirmed_fraud">Confirmed fraud</option>
              <option value="false_positive">False positive</option>
              <option value="closed">Closed</option>
              <option value="all">All</option>
            </select>
          </div>
          <div className="alert-list">
            {filteredAlerts.length === 0 ? (
              <div className="empty-state"><strong>Queue is clear</strong><p>No alerts match this filter.</p></div>
            ) : filteredAlerts.slice(0, 10).map((alert) => (
              <Link className="alert-row" to={`/alerts/${alert.id}`} key={alert.id}>
                <span className={`severity-dot severity-dot--${alert.severity}`} title={`${alert.severity} severity`} />
                <span className="alert-row__body">
                  <span className="alert-row__title"><strong>{alert.title}</strong><StatusBadge value={alert.status} /></span>
                  <span>{alert.summary}</span>
                  <small>{formatTime(alert.created_at)} · {alert.reason_codes.length} signals</small>
                </span>
                <span className="alert-row__score"><strong>{Math.round(alert.risk_score * 100)}</strong><small>risk</small></span>
                <span className="chevron" aria-hidden="true">›</span>
              </Link>
            ))}
          </div>
        </article>

        <article className="panel panel--transactions">
          <div className="panel__heading">
            <div><p className="eyebrow">Event stream</p><h2>Recent transactions</h2></div>
            <span className="live-label"><span className="live-dot" /> Live</span>
          </div>
          <div className="table-wrap">
            <table>
              <thead><tr><th>Payment</th><th>Amount</th><th>Decision</th><th>Risk</th><th>Time</th></tr></thead>
              <tbody>
                {transactions.slice(0, 12).map((transaction) => (
                  <tr key={transaction.id}>
                    <td><strong>{transaction.external_id}</strong><small>{transaction.merchant_id}</small></td>
                    <td>{formatMoney(transaction.amount, transaction.currency)}</td>
                    <td><StatusBadge value={transaction.decision ?? transaction.status} /></td>
                    <td><span className={`risk-number risk-number--${numberOf(transaction.risk_score) >= 0.7 ? "high" : numberOf(transaction.risk_score) >= 0.4 ? "medium" : "low"}`}>{Math.round(numberOf(transaction.risk_score) * 100)}</span></td>
                    <td>{formatTime(transaction.occurred_at)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
            {transactions.length === 0 && <div className="empty-state"><strong>No transactions yet</strong><p>Tokenized payment events will appear here.</p></div>}
          </div>
        </article>
      </section>
    </main>
  );
}
