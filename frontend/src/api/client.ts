import type {
  Alert,
  AlertStatus,
  AlertStatusUpdate,
  LoginPayload,
  RegisterPayload,
  TokenPair,
  Transaction,
  User,
} from "../types";

const API_BASE_URL = (
  import.meta.env.VITE_API_BASE_URL ?? "http://localhost:8000/api/v1"
).replace(/\/$/, "");
const REFRESH_TOKEN_KEY = "aegisgraph.refresh-token";

let accessToken: string | null = null;
let refreshPromise: Promise<string | null> | null = null;

export class ApiError extends Error {
  readonly status: number;
  readonly detail: unknown;

  constructor(status: number, message: string, detail?: unknown) {
    super(message);
    this.name = "ApiError";
    this.status = status;
    this.detail = detail;
  }
}

function saveTokens(tokens: TokenPair): void {
  accessToken = tokens.access_token;
  sessionStorage.setItem(REFRESH_TOKEN_KEY, tokens.refresh_token);
}

function clearTokens(): void {
  accessToken = null;
  sessionStorage.removeItem(REFRESH_TOKEN_KEY);
}

async function parseError(response: Response): Promise<ApiError> {
  let detail: unknown;
  try {
    detail = (await response.json()) as unknown;
  } catch {
    detail = undefined;
  }
  const candidate =
    typeof detail === "object" && detail !== null && "detail" in detail
      ? (detail as { detail: unknown }).detail
      : detail;
  const message = typeof candidate === "string" ? candidate : `Request failed (${response.status})`;
  return new ApiError(response.status, message, candidate);
}

async function refreshAccessToken(): Promise<string | null> {
  const refreshToken = sessionStorage.getItem(REFRESH_TOKEN_KEY);
  if (!refreshToken) return null;

  const response = await fetch(`${API_BASE_URL}/auth/refresh`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ refresh_token: refreshToken }),
  });
  if (!response.ok) {
    clearTokens();
    return null;
  }
  const pair = (await response.json()) as TokenPair;
  saveTokens(pair);
  return pair.access_token;
}

async function restoreAccessToken(): Promise<string | null> {
  if (accessToken) return accessToken;
  refreshPromise ??= refreshAccessToken().finally(() => {
    refreshPromise = null;
  });
  return refreshPromise;
}

async function request<T>(
  path: string,
  init: RequestInit = {},
  retryAfterRefresh = true,
): Promise<T> {
  const token = accessToken ?? (await restoreAccessToken());
  const headers = new Headers(init.headers);
  headers.set("Accept", "application/json");
  if (init.body && !headers.has("Content-Type")) {
    headers.set("Content-Type", "application/json");
  }
  if (token) headers.set("Authorization", `Bearer ${token}`);

  const response = await fetch(`${API_BASE_URL}${path}`, { ...init, headers });
  if (response.status === 401 && retryAfterRefresh) {
    accessToken = null;
    const renewed = await restoreAccessToken();
    if (renewed) return request<T>(path, init, false);
  }
  if (!response.ok) throw await parseError(response);
  if (response.status === 204) return undefined as T;
  return (await response.json()) as T;
}

export const api = {
  async login(payload: LoginPayload): Promise<User> {
    const response = await fetch(`${API_BASE_URL}/auth/login`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });
    if (!response.ok) throw await parseError(response);
    saveTokens((await response.json()) as TokenPair);
    return request<User>("/auth/me", {}, false);
  },

  async register(payload: RegisterPayload): Promise<User> {
    const response = await fetch(`${API_BASE_URL}/auth/register`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });
    if (!response.ok) throw await parseError(response);
    await response.json();
    return this.login({
      tenant_id: payload.tenant_id,
      email: payload.email,
      password: payload.password,
    });
  },

  async restoreSession(): Promise<User | null> {
    const token = await restoreAccessToken();
    if (!token) return null;
    try {
      return await request<User>("/auth/me", {}, false);
    } catch {
      clearTokens();
      return null;
    }
  },

  async logout(): Promise<void> {
    const refreshToken = sessionStorage.getItem(REFRESH_TOKEN_KEY);
    try {
      if (refreshToken) {
        await request<void>(
          "/auth/logout",
          { method: "POST", body: JSON.stringify({ refresh_token: refreshToken }) },
          false,
        );
      }
    } finally {
      clearTokens();
    }
  },

  getTransactions(limit = 100): Promise<Transaction[]> {
    return request<Transaction[]>(`/transactions?limit=${limit}`);
  },

  simulateFraud(
    scenario: "normal" | "account_takeover" | "fraud_ring" = "account_takeover",
  ): Promise<Transaction> {
    return request<Transaction>("/transactions/demo", {
      method: "POST",
      body: JSON.stringify({ scenario }),
    });
  },

  getAlerts(status?: AlertStatus, limit = 100): Promise<Alert[]> {
    const params = new URLSearchParams({ limit: String(limit) });
    if (status) params.set("alert_status", status);
    return request<Alert[]>(`/alerts?${params}`);
  },

  getAlert(alertId: string): Promise<Alert> {
    return request<Alert>(`/alerts/${encodeURIComponent(alertId)}`);
  },

  updateAlert(alertId: string, payload: AlertStatusUpdate): Promise<Alert> {
    return request<Alert>(`/alerts/${encodeURIComponent(alertId)}/status`, {
      method: "PATCH",
      body: JSON.stringify(payload),
    });
  },
};
