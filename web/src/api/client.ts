// Тонкий клиент REST API сканера: Bearer-токен, разбор ошибок FastAPI.

import type {
  AllowlistIn,
  AssetBulkIn,
  AssetFilters,
  AssetGroupOut,
  AssetIn,
  AssetOut,
  AssetTagOut,
  AssetUpdate,
  AllowlistOut,
  AuditExportFormat,
  AuditFilters,
  AuditOut,
  ComplianceProfileDef,
  ComplianceProfileIn,
  ComplianceProfileOut,
  ComplianceSummary,
  CredentialIn,
  CredentialOut,
  CredSetIn,
  CredSetOut,
  EngagementIn,
  EngagementOut,
  FeedOut,
  FeedScheduleIn,
  FindingOut,
  InventoryHostOut,
  MeOut,
  PackageOut,
  ReachabilityIn,
  ReachabilityOut,
  ReportFormat,
  ReportVariant,
  RunCreate,
  RunCreated,
  RunOut,
  ScheduleIn,
  ScheduleOut,
  ServiceOut,
  TokenOut,
  UserCreate,
  UserOut,
  UserUpdate,
} from "./types";

export const API_BASE: string = (import.meta.env.VITE_API_BASE as string | undefined) ?? "/api";

const TOKEN_KEY = "scanner.token";

export class ApiError extends Error {
  constructor(
    public status: number,
    message: string,
    public detail?: unknown,
  ) {
    super(message);
    this.name = "ApiError";
  }
}

let token: string | null = readToken();
let onUnauthorized: (() => void) | null = null;

function readToken(): string | null {
  try {
    return sessionStorage.getItem(TOKEN_KEY);
  } catch {
    return null;
  }
}

export function getToken(): string | null {
  return token;
}

export function setToken(value: string | null): void {
  token = value;
  try {
    if (value) sessionStorage.setItem(TOKEN_KEY, value);
    else sessionStorage.removeItem(TOKEN_KEY);
  } catch {
    /* хранилище недоступно — токен живёт до перезагрузки вкладки */
  }
}

export function setUnauthorizedHandler(fn: (() => void) | null): void {
  onUnauthorized = fn;
}

/** Человекочитаемый текст из ответа FastAPI ({detail: str | [{msg}] | {message}}). */
export function errorText(detail: unknown, fallback: string): string {
  if (typeof detail === "string") return detail;
  if (Array.isArray(detail)) {
    return detail
      .map((d) => (d && typeof d === "object" && "msg" in d ? String((d as { msg: unknown }).msg) : String(d)))
      .join("; ");
  }
  if (detail && typeof detail === "object" && "message" in detail) {
    return String((detail as { message: unknown }).message);
  }
  return fallback;
}

async function request(path: string, init: RequestInit = {}): Promise<Response> {
  const headers = new Headers(init.headers);
  if (token) headers.set("Authorization", `Bearer ${token}`);
  if (init.body && !headers.has("Content-Type")) headers.set("Content-Type", "application/json");
  let res: Response;
  try {
    res = await fetch(`${API_BASE}${path}`, { ...init, headers });
  } catch {
    throw new ApiError(0, "Сервер API недоступен");
  }
  if (res.ok) return res;
  let detail: unknown;
  try {
    detail = (await res.json()).detail;
  } catch {
    detail = undefined;
  }
  if (res.status === 401 && token) {
    setToken(null);
    onUnauthorized?.();
  }
  throw new ApiError(res.status, errorText(detail, `Ошибка ${res.status}`), detail);
}

async function json<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await request(path, init);
  return (await res.json()) as T;
}

/** Query-строка: массивы — повтором параметра (?action=a&action=b), пустое опускается. */
export function auditQuery(params: object): string {
  const q = new URLSearchParams();
  for (const [k, v] of Object.entries(params)) {
    if (k === "actions") for (const a of (v as string[] | undefined) ?? []) q.append("action", a);
    else if (v !== undefined && v !== null && v !== "") q.set(k, String(v));
  }
  const qs = q.toString();
  return qs ? `?${qs}` : "";
}

const body = (data: unknown): RequestInit => ({ body: JSON.stringify(data) });

export const api = {
  login: (username: string, password: string) =>
    json<TokenOut>("/auth/token", { method: "POST", ...body({ username, password }) }),
  me: () => json<MeOut>("/me"),

  users: () => json<UserOut[]>("/users"),
  createUser: (data: UserCreate) => json<UserOut>("/users", { method: "POST", ...body(data) }),
  updateUser: (id: number, data: UserUpdate) =>
    json<UserOut>(`/users/${id}`, { method: "PATCH", ...body(data) }),
  setRoles: (id: number, roles: string[]) =>
    json<UserOut>(`/users/${id}/roles`, { method: "PUT", ...body({ roles }) }),

  engagements: () => json<EngagementOut[]>("/engagements"),
  engagement: (id: number) => json<EngagementOut>(`/engagements/${id}`),
  createEngagement: (data: EngagementIn) =>
    json<EngagementOut>("/engagements", { method: "POST", ...body(data) }),
  updateEngagement: (id: number, data: Partial<EngagementIn>) =>
    json<EngagementOut>(`/engagements/${id}`, { method: "PATCH", ...body(data) }),
  deleteEngagement: (id: number) => request(`/engagements/${id}`, { method: "DELETE" }).then(() => undefined),

  allowlist: (engagementId: number) => json<AllowlistOut[]>(`/engagements/${engagementId}/allowlist`),
  addAllowlist: (engagementId: number, data: AllowlistIn) =>
    json<AllowlistOut>(`/engagements/${engagementId}/allowlist`, { method: "POST", ...body(data) }),
  removeAllowlist: (engagementId: number, entryId: number) =>
    request(`/engagements/${engagementId}/allowlist/${entryId}`, { method: "DELETE" }).then(() => undefined),

  credentials: (engagementId: number) => json<CredentialOut[]>(`/engagements/${engagementId}/credentials`),
  createCredential: (engagementId: number, data: CredentialIn) =>
    json<CredentialOut>(`/engagements/${engagementId}/credentials`, { method: "POST", ...body(data) }),
  deleteCredential: (engagementId: number, credentialId: number) =>
    request(`/engagements/${engagementId}/credentials/${credentialId}`, { method: "DELETE" }).then(() => undefined),

  assets: (engagementId: number, f: AssetFilters = {}) => {
    const p = new URLSearchParams();
    if (f.tag) p.set("tag", f.tag);
    if (f.group_id !== undefined) p.set("group_id", String(f.group_id));
    if (f.criticality) p.set("criticality", f.criticality);
    if (f.q) p.set("q", f.q);
    const qs = p.toString();
    return json<AssetOut[]>(`/engagements/${engagementId}/assets${qs ? `?${qs}` : ""}`);
  },
  createAsset: (engagementId: number, data: AssetIn) =>
    json<AssetOut>(`/engagements/${engagementId}/assets`, { method: "POST", ...body(data) }),
  updateAsset: (engagementId: number, id: number, data: AssetUpdate) =>
    json<AssetOut>(`/engagements/${engagementId}/assets/${id}`, { method: "PATCH", ...body(data) }),
  deleteAsset: (engagementId: number, id: number) =>
    request(`/engagements/${engagementId}/assets/${id}`, { method: "DELETE" }).then(() => undefined),
  bulkAssets: (engagementId: number, data: AssetBulkIn) =>
    json<AssetOut[]>(`/engagements/${engagementId}/assets/bulk`, { method: "POST", ...body(data) }),
  importAssets: (engagementId: number) =>
    json<AssetOut[]>(`/engagements/${engagementId}/assets/import-discovered`, { method: "POST" }),
  complianceCatalog: () => json<ComplianceProfileDef[]>("/compliance/profiles"),
  complianceProfiles: (engagementId: number) =>
    json<ComplianceProfileOut[]>(`/engagements/${engagementId}/compliance-profiles`),
  saveComplianceProfile: (engagementId: number, profile: string, data: ComplianceProfileIn) =>
    json<ComplianceProfileOut>(`/engagements/${engagementId}/compliance-profiles/${encodeURIComponent(profile)}`, {
      method: "PUT",
      ...body(data),
    }),
  deleteComplianceProfile: (engagementId: number, profile: string) =>
    request(`/engagements/${engagementId}/compliance-profiles/${encodeURIComponent(profile)}`, { method: "DELETE" }).then(
      () => undefined,
    ),
  runCompliance: (runId: number, profile: string, level?: string | null, groupId?: number | null) => {
    const p = new URLSearchParams({ profile });
    if (level) p.set("level", level);
    if (groupId != null) p.set("group_id", String(groupId));
    return json<ComplianceSummary>(`/runs/${runId}/compliance?${p.toString()}`);
  },
  recomputeCompliance: (runId: number) => json<{ rows: number }>(`/runs/${runId}/compliance/recompute`, { method: "POST" }),
  assetTags: (engagementId: number) => json<AssetTagOut[]>(`/engagements/${engagementId}/asset-tags`),
  assetGroups: (engagementId: number) => json<AssetGroupOut[]>(`/engagements/${engagementId}/asset-groups`),
  createAssetGroup: (engagementId: number, name: string) =>
    json<AssetGroupOut>(`/engagements/${engagementId}/asset-groups`, { method: "POST", ...body({ name }) }),
  renameAssetGroup: (engagementId: number, id: number, name: string) =>
    json<AssetGroupOut>(`/engagements/${engagementId}/asset-groups/${id}`, { method: "PATCH", ...body({ name }) }),
  deleteAssetGroup: (engagementId: number, id: number) =>
    request(`/engagements/${engagementId}/asset-groups/${id}`, { method: "DELETE" }).then(() => undefined),
  credSets: (engagementId: number) => json<CredSetOut[]>(`/engagements/${engagementId}/cred-sets`),
  createCredSet: (engagementId: number, data: CredSetIn) =>
    json<CredSetOut>(`/engagements/${engagementId}/cred-sets`, { method: "POST", ...body(data) }),
  deleteCredSet: (engagementId: number, setId: number) =>
    request(`/engagements/${engagementId}/cred-sets/${setId}`, { method: "DELETE" }).then(() => undefined),

  runs: (engagementId: number) => json<RunOut[]>(`/engagements/${engagementId}/runs`),
  run: (id: number) => json<RunOut>(`/runs/${id}`),
  startRun: (engagementId: number, data: RunCreate) =>
    json<RunCreated>(`/engagements/${engagementId}/runs`, { method: "POST", ...body(data) }),
  schedules: (engagementId: number) => json<ScheduleOut[]>(`/engagements/${engagementId}/schedules`),
  createSchedule: (engagementId: number, data: ScheduleIn) =>
    json<ScheduleOut>(`/engagements/${engagementId}/schedules`, { method: "POST", ...body(data) }),
  updateSchedule: (id: number, data: ScheduleIn) => json<ScheduleOut>(`/schedules/${id}`, { method: "PUT", ...body(data) }),
  toggleSchedule: (id: number, enabled: boolean) => json<ScheduleOut>(`/schedules/${id}`, { method: "PATCH", ...body({ enabled }) }),
  feeds: () => json<FeedOut[]>("/feeds"),
  updateFeed: (source: string, data: FeedScheduleIn) => json<FeedOut>(`/feeds/${source}`, { method: "PUT", ...body(data) }),
  runFeedNow: (source: string) => json<FeedOut>(`/feeds/${source}/run`, { method: "POST" }),
  runScheduleNow: (id: number) => json<ScheduleOut>(`/schedules/${id}/run`, { method: "POST" }),
  deleteSchedule: (id: number) => request(`/schedules/${id}`, { method: "DELETE" }).then(() => undefined),
  checkReachability: (engagementId: number, data: ReachabilityIn) =>
    json<ReachabilityOut>(`/engagements/${engagementId}/reachability`, { method: "POST", ...body(data) }),
  stopRun: (id: number) => json<RunOut>(`/runs/${id}/stop`, { method: "POST" }),
  findings: (runId: number) => json<FindingOut[]>(`/runs/${runId}/findings`),
  /** Отметить находку хоста как ложное срабатывание (действует и в следующих прогонах). */
  markFalsePositive: (findingId: number, reason: string | null) =>
    json<FindingOut>(`/findings/${findingId}/false-positive`, { method: "PUT", ...body({ reason }) }),
  unmarkFalsePositive: (findingId: number) => json<FindingOut>(`/findings/${findingId}/false-positive`, { method: "DELETE" }),
  services: (runId: number) => json<ServiceOut[]>(`/runs/${runId}/services`),
  /** Пакеты, собранные инвентаризацией по учётной записи. */
  packages: (runId: number, host?: string) =>
    json<PackageOut[]>(`/runs/${runId}/packages${host ? `?host=${encodeURIComponent(host)}` : ""}`),
  /** Инвентарь договора — не зависит от прогона. */
  hosts: (engagementId: number) => json<InventoryHostOut[]>(`/engagements/${engagementId}/hosts`),

  /** Отчёт как Blob: эндпоинт требует Bearer, поэтому обычная ссылка не подходит. */
  report: async (
    runId: number,
    format: ReportFormat,
    variant: ReportVariant = "full",
    compareTo: number | null = null,
    groupId: number | null = null,
  ): Promise<Blob> => {
    const cmp = compareTo === null ? "" : `&compare_to=${compareTo}`;
    const grp = groupId === null ? "" : `&group_id=${groupId}`;
    const res = await request(`/runs/${runId}/report?format=${format}&variant=${variant}${cmp}${grp}`);
    return res.blob();
  },

  audit: (params: { limit?: number; before_id?: number } & AuditFilters = {}) =>
    json<AuditOut[]>(`/audit${auditQuery(params)}`),
  auditActions: () => json<string[]>("/audit/actions"),
  /** Выгрузка журнала: файл через fetch с Bearer, как и отчёты. */
  auditExport: async (format: AuditExportFormat, filters: AuditFilters): Promise<Blob> => {
    const res = await request(`/audit/export${auditQuery({ format, ...filters })}`);
    return res.blob();
  },
};
