import type { AlertSeverity, AlertStatus, PaymentDecision, PaymentStatus } from "../types";

type BadgeValue = AlertSeverity | AlertStatus | PaymentDecision | PaymentStatus | null;

function tone(value: BadgeValue): string {
  if (!value) return "neutral";
  if (["critical", "block", "confirmed_fraud", "failed", "error"].includes(value)) {
    return "danger";
  }
  if (["high", "review", "investigating", "scoring"].includes(value)) return "warning";
  if (["allow", "closed", "false_positive", "decided"].includes(value)) return "success";
  return "neutral";
}

export function StatusBadge({ value }: { value: BadgeValue }) {
  const text = value?.replaceAll("_", " ") ?? "pending";
  return <span className={`badge badge--${tone(value)}`}>{text}</span>;
}
