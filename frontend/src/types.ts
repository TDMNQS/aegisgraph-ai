export type UserRole =
  | "viewer"
  | "analyst"
  | "senior_analyst"
  | "admin"
  | "service";

export type AlertStatus =
  | "open"
  | "assigned"
  | "investigating"
  | "confirmed_fraud"
  | "false_positive"
  | "closed";

export type AlertSeverity = "low" | "medium" | "high" | "critical";
export type PaymentStatus = "received" | "scoring" | "decided" | "failed";
export type PaymentDecision = "allow" | "review" | "block" | "error";
export type Numeric = number | string;

export interface TokenPair {
  access_token: string;
  refresh_token: string;
  token_type: "bearer";
  expires_in: number;
}

export interface User {
  id: string;
  tenant_id: string;
  email: string;
  display_name: string;
  role: UserRole;
  status: "active" | "locked" | "disabled";
  is_service_account: boolean;
  created_at: string;
  last_login_at: string | null;
}

export interface LoginPayload {
  tenant_id: string;
  email: string;
  password: string;
}

export interface RegisterPayload extends LoginPayload {
  display_name: string;
}

export interface Transaction {
  id: string;
  tenant_id: string;
  external_id: string;
  amount: Numeric;
  currency: string;
  merchant_id: string;
  merchant_category_code: string | null;
  channel: string;
  occurred_at: string;
  customer_token: string;
  device_token: string | null;
  country_code: string | null;
  status: PaymentStatus;
  decision: PaymentDecision | null;
  risk_score: Numeric;
  reason_codes: string[];
  explanation: Record<string, unknown>;
  created_at: string;
  decided_at: string | null;
}

export interface Alert {
  id: string;
  tenant_id: string;
  transaction_id: string;
  severity: AlertSeverity;
  status: AlertStatus;
  risk_score: number;
  title: string;
  summary: string;
  reason_codes: string[];
  evidence: Record<string, unknown>;
  assigned_to_id: string | null;
  assigned_at: string | null;
  resolution: string | null;
  resolved_at: string | null;
  version: number;
  created_at: string;
  updated_at: string;
}

export interface AlertStatusUpdate {
  status: AlertStatus;
  expected_version: number;
  resolution?: string;
}
