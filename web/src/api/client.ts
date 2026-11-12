// Тонкий клиент REST API сканера: Bearer-токен, разбор ошибок FastAPI.

import type {
  CredentialCheckIn,
  CredentialCheckOut,
  AllowlistBulkIn,
  AllowlistBulkOut,
  AllowlistIn,
  ReportSections,
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
  ChannelIn,
  ChannelOut,
  ScanNode,
  SystemHealth,
  ScanNodeCreated,
  ScanNodeIn,
  ScanNodeUpdate,
  ChannelUpdate,
  DeliveryOut,

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
  FeedReadiness,
  RunProfile,
  RunPlan,
  CoverageOut,
  FeedScheduleIn,
  FindingOut,
  FindingQuery,
  FindingsSummary,
  RunEventOut,
  TrendRunOut,
  FixPlanOut,
  SearchOut,
  FixQuery,
  TableFormat,
  HostLatestOut,
  InventoryHostOut,
  MeOut,
  PackageOut,
  Page,
  PortScanCreated,
  PortScanDetail,
  PortScanIn,
  PortScanOut,
  ReachabilityIn,
  ReachabilityOut,
  ReportFormat,
  ReportVariant,
  RunCreate,
  RunCreated,
  RunOut,
  RunQuery,
  ScheduleIn,
  ScheduleOut,
  ServiceOut,
  SoftwareFalsePositiveIn,
  SoftwareFalsePositiveOut,
  TokenOut,
  AuthConfigOut,
  MfaSetupOut,
  MfaStatusOut,
  UserCreate,
  UserOut,
  UserUpdate,
  OfflineImportOut,
  OfflineJobOut,
  OfflineKeyOut,
  OfflineResultHeader,
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

/** Страница списка: тело — элементы, общее число — заголовок X-Total-Count. */
async function page<T>(path: string): Promise<Page<T>> {
  const res = await request(path);
  const items = (await res.json()) as T[];
  const total = Number(res.headers.get("X-Total-Count") ?? items.length);
  return { items, total: Number.isFinite(total) ? total : items.length };
}

/** Query-строка для списков: массивы — повтором параметра, пустое опускается. */
export function listQuery(params: object): string {
  const q = new URLSearchParams();
  for (const [k, v] of Object.entries(params)) {
    if (Array.isArray(v)) for (const x of v) q.append(k, String(x));
    else if (v !== undefined && v !== null && v !== "") q.set(k, String(v));
  }
  const qs = q.toString();
  return qs ? `?${qs}` : "";
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

/** Файл из ответа: тело и имя из Content-Disposition (filename* — UTF-8). */
export async function fileOf(res: Response): Promise<{ blob: Blob; name: string }> {
  const cd = res.headers.get("Content-Disposition") ?? "";
  const star = /filename\*=UTF-8''([^;]+)/i.exec(cd);
  const plain = /filename="([^"]+)"/i.exec(cd);
  let name = "download";
  if (star) {
    try {
      name = decodeURIComponent(star[1]);
    } catch {
      name = star[1];
    }
  } else if (plain) name = plain[1];
  return { blob: await res.blob(), name };
}

export const api = {
  login: (username: string, password: string) =>
    json<TokenOut>("/auth/token", { method: "POST", ...body({ username, password }) }),
  me: () => json<MeOut>("/me"),
  authConfig: () => json<AuthConfigOut>("/auth/config"),
  // второй шаг входа (2FA): mfa_token из /auth/token + код из приложения
  mfaVerify: (mfa_token: string, code: string) =>
    json<TokenOut>("/auth/mfa", { method: "POST", ...body({ mfa_token, code }) }),
  mfaEnrollStart: (mfa_token: string) =>
    json<MfaSetupOut>("/auth/mfa/enroll", { method: "POST", ...body({ mfa_token }) }),
  mfaEnrollConfirm: (mfa_token: string, code: string) =>
    json<TokenOut>("/auth/mfa/enroll/confirm", { method: "POST", ...body({ mfa_token, code }) }),
  // своя 2FA в профиле
  myMfa: () => json<MfaStatusOut>("/me/mfa"),
  myMfaSetup: () => json<MfaSetupOut>("/me/mfa/setup", { method: "POST" }),
  myMfaConfirm: (code: string) =>
    json<{ recovery_codes: string[] }>("/me/mfa/confirm", { method: "POST", ...body({ code }) }),
  myMfaRecoveryCodes: (code: string) =>
    json<{ recovery_codes: string[] }>("/me/mfa/recovery-codes", { method: "POST", ...body({ code }) }),
  myMfaDisable: (code: string) => json<MfaStatusOut>("/me/mfa/disable", { method: "POST", ...body({ code }) }),

  users: () => json<UserOut[]>("/users"),
  createUser: (data: UserCreate) => json<UserOut>("/users", { method: "POST", ...body(data) }),
  updateUser: (id: number, data: UserUpdate) =>
    json<UserOut>(`/users/${id}`, { method: "PATCH", ...body(data) }),
  setRoles: (id: number, roles: string[]) =>
    json<UserOut>(`/users/${id}/roles`, { method: "PUT", ...body({ roles }) }),
  resetUserMfa: (id: number) => json<UserOut>(`/users/${id}/mfa`, { method: "DELETE" }),

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
  addAllowlistBulk: (engagementId: number, data: AllowlistBulkIn) =>
    json<AllowlistBulkOut>(`/engagements/${engagementId}/allowlist/bulk`, { method: "POST", ...body(data) }),
  removeAllowlist: (engagementId: number, entryId: number, wholeRange = false) =>
    request(`/engagements/${engagementId}/allowlist/${entryId}${wholeRange ? "?whole_range=true" : ""}`, { method: "DELETE" }).then(() => undefined),

  credentials: (engagementId: number) => json<CredentialOut[]>(`/engagements/${engagementId}/credentials`),
  createCredential: (engagementId: number, data: CredentialIn) =>
    json<CredentialOut>(`/engagements/${engagementId}/credentials`, { method: "POST", ...body(data) }),
  updateCredential: (engagementId: number, credentialId: number, data: CredentialIn) =>
    json<CredentialOut>(`/engagements/${engagementId}/credentials/${credentialId}`, { method: "PUT", ...body(data) }),
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
  runsPage: (engagementId: number, params: RunQuery) => page<RunOut>(`/engagements/${engagementId}/runs${listQuery(params)}`),
  run: (id: number) => json<RunOut>(`/runs/${id}`),
  startRun: (engagementId: number, data: RunCreate) =>
    json<RunCreated>(`/engagements/${engagementId}/runs`, { method: "POST", ...body(data) }),
  schedules: (engagementId: number) => json<ScheduleOut[]>(`/engagements/${engagementId}/schedules`),
  createSchedule: (engagementId: number, data: ScheduleIn) =>
    json<ScheduleOut>(`/engagements/${engagementId}/schedules`, { method: "POST", ...body(data) }),
  updateSchedule: (id: number, data: ScheduleIn) => json<ScheduleOut>(`/schedules/${id}`, { method: "PUT", ...body(data) }),
  toggleSchedule: (id: number, enabled: boolean) => json<ScheduleOut>(`/schedules/${id}`, { method: "PATCH", ...body({ enabled }) }),
  nodes: () => json<ScanNode[]>("/nodes"),
  createNode: (data: ScanNodeIn) => json<ScanNodeCreated>("/nodes", { method: "POST", ...body(data) }),
  updateNode: (id: number, data: ScanNodeUpdate) => json<ScanNode>(`/nodes/${id}`, { method: "PATCH", ...body(data) }),
  rotateNodeToken: (id: number) => json<ScanNodeCreated>(`/nodes/${id}/token`, { method: "POST" }),
  deleteNode: (id: number) => request(`/nodes/${id}`, { method: "DELETE" }).then(() => undefined),

  channels: () => json<ChannelOut[]>("/integrations/channels"),
  createChannel: (data: ChannelIn) => json<ChannelOut>("/integrations/channels", { method: "POST", ...body(data) }),
  updateChannel: (id: number, data: ChannelUpdate) => json<ChannelOut>(`/integrations/channels/${id}`, { method: "PATCH", ...body(data) }),
  deleteChannel: (id: number) => request(`/integrations/channels/${id}`, { method: "DELETE" }).then(() => undefined),
  testChannel: (id: number) => json<DeliveryOut>(`/integrations/channels/${id}/test`, { method: "POST" }),
  deliveries: (limit = 50) => json<DeliveryOut[]>(`/integrations/log?limit=${limit}`),
  retryDelivery: (id: number) => json<DeliveryOut>(`/integrations/log/${id}/retry`, { method: "POST" }),
  feeds: () => json<FeedOut[]>("/feeds"),
  updateFeed: (source: string, data: FeedScheduleIn) => json<FeedOut>(`/feeds/${source}`, { method: "PUT", ...body(data) }),
  runFeedNow: (source: string) => json<FeedOut>(`/feeds/${source}/run`, { method: "POST" }),
  feedReadiness: () => json<FeedReadiness>("/feeds/readiness"),
  /** Загрузить бюллетени одного выпуска ОС (например debian:trixie). */
  loadRelease: (family: string, release: string) =>
    json<FeedOut>("/feeds/advisories/releases", { method: "POST", ...body({ family, release }) }),
  /** Загрузить выгрузку БДУ (vullist.xlsx) из браузера. */
  uploadBdu: (file: Blob) =>
    json<FeedOut>("/feeds/bdu/upload", { method: "POST", body: file, headers: { "Content-Type": "application/octet-stream" } }),
  runProfiles: () => json<RunProfile[]>("/run-profiles"),
  planRun: (engagementId: number, data: RunCreate) =>
    json<RunPlan>(`/engagements/${engagementId}/runs/plan`, { method: "POST", ...body(data) }),
  runCoverage: (runId: number) => json<CoverageOut>(`/runs/${runId}/coverage`),
  runScheduleNow: (id: number) => json<ScheduleOut>(`/schedules/${id}/run`, { method: "POST" }),
  deleteSchedule: (id: number) => request(`/schedules/${id}`, { method: "DELETE" }).then(() => undefined),
  checkReachability: (engagementId: number, data: ReachabilityIn) =>
    json<ReachabilityOut>(`/engagements/${engagementId}/reachability`, { method: "POST", ...body(data) }),
  startPortScan: (engagementId: number, data: PortScanIn) =>
    json<PortScanCreated>(`/engagements/${engagementId}/port-scans`, { method: "POST", ...body(data) }),
  portScans: (engagementId: number) => json<PortScanOut[]>(`/engagements/${engagementId}/port-scans`),
  portScan: (id: number) => json<PortScanDetail>(`/port-scans/${id}`),
  stopPortScan: (id: number) => json<PortScanOut>(`/port-scans/${id}/stop`, { method: "POST" }),
  checkCredentials: (engagementId: number, data: CredentialCheckIn) =>
    json<CredentialCheckOut>(`/engagements/${engagementId}/credential-check`, { method: "POST", ...body(data) }),
  stopRun: (id: number) => json<RunOut>(`/runs/${id}/stop`, { method: "POST" }),
  retryRun: (id: number) => json<RunCreated>(`/runs/${id}/retry`, { method: "POST" }),
  findings: (runId: number, params: FindingQuery = {}) => json<FindingOut[]>(`/runs/${runId}/findings${listQuery(params)}`),
  findingsPage: (runId: number, params: FindingQuery) => page<FindingOut>(`/runs/${runId}/findings${listQuery(params)}`),
  findingsSummary: (runId: number) => json<FindingsSummary>(`/runs/${runId}/findings/summary`),
  /** Лента прогона, новые сверху. */
  runEvents: (runId: number, limit = 50) => json<RunEventOut[]>(`/runs/${runId}/events?limit=${limit}`),
  /** Открытые по уровням в каждом прогоне проекта за N дней (или последние limit прогонов). */
  trend: (engagementId: number, params: { days?: number; limit?: number } = {}) =>
    json<TrendRunOut[]>(`/engagements/${engagementId}/trend${listQuery(params)}`),
  /** План исправлений: находки, собранные в действия с командами по ОС хостов. */
  fixes: (runId: number, params: FixQuery = {}) => json<FixPlanOut>(`/runs/${runId}/fixes${listQuery(params)}`),
  /** План исправлений актива по последним известным данным хоста (без выбранного прогона). */
  hostFixes: (engagementId: number, host: string, params: FixQuery = {}) =>
    json<FixPlanOut>(`/engagements/${engagementId}/hosts/${encodeURIComponent(host)}/fixes${listQuery(params)}`),
  /** «Все находки» файлом CSV/Excel — с фильтрами и сортировкой списка, без страниц. */
  exportFindings: (runId: number, format: TableFormat, params: Omit<FindingQuery, "limit" | "offset"> = {}) =>
    request(`/runs/${runId}/findings/export${listQuery({ ...params, format })}`).then(fileOf),
  /** «Что исправить» файлом; sheet=hosts — CSV по строке на действие × хост. */
  exportFixes: (runId: number, format: TableFormat, params: Omit<FixQuery, "limit" | "offset"> & { sheet?: "tasks" | "hosts" } = {}) =>
    request(`/runs/${runId}/fixes/export${listQuery({ ...params, format })}`).then(fileOf),
  exportHostFixes: (
    engagementId: number,
    host: string,
    format: TableFormat,
    params: Omit<FixQuery, "limit" | "offset" | "os" | "host"> & { sheet?: "tasks" | "hosts" } = {},
  ) => request(`/engagements/${engagementId}/hosts/${encodeURIComponent(host)}/fixes/export${listQuery({ ...params, format })}`).then(fileOf),
  finding: (id: number) => json<FindingOut>(`/findings/${id}`),
  /** Отметить находку хоста как ложное срабатывание (действует и в следующих прогонах). */
  markFalsePositive: (findingId: number, reason: string | null) =>
    json<FindingOut>(`/findings/${findingId}/false-positive`, { method: "PUT", ...body({ reason }) }),
  unmarkFalsePositive: (findingId: number) => json<FindingOut>(`/findings/${findingId}/false-positive`, { method: "DELETE" }),
  /** Все уязвимости ПО на хосте (или на всех хостах прогона) — в ложные срабатывания; dry_run — только посчитать. */
  markSoftwareFalsePositive: (runId: number, data: SoftwareFalsePositiveIn) =>
    json<SoftwareFalsePositiveOut>(`/runs/${runId}/false-positives/by-software`, { method: "POST", ...body(data) }),
  unmarkSoftwareFalsePositive: (runId: number, data: SoftwareFalsePositiveIn) =>
    json<SoftwareFalsePositiveOut>(`/runs/${runId}/false-positives/by-software/unmark`, { method: "POST", ...body(data) }),
  services: (runId: number) => json<ServiceOut[]>(`/runs/${runId}/services`),
  /** Пакеты, собранные инвентаризацией по учётной записи. */
  packages: (runId: number, host?: string) =>
    json<PackageOut[]>(`/runs/${runId}/packages${host ? `?host=${encodeURIComponent(host)}` : ""}`),
  /** Инвентарь договора — не зависит от прогона. */
  hosts: (engagementId: number) => json<InventoryHostOut[]>(`/engagements/${engagementId}/hosts`),
  /** Быстрый поиск по проекту: хосты, ПО, CVE/БДУ, действия и команды плана исправлений. */
  search: (engagementId: number, q: string, init?: RequestInit) =>
    json<SearchOut>(`/engagements/${engagementId}/search${listQuery({ q, limit: 5 })}`, init),
  hostLatest: (engagementId: number, host: string) =>
    json<HostLatestOut>(`/engagements/${engagementId}/hosts/${encodeURIComponent(host)}/latest`),

  /** Автономный узел: задание прогона (404 — задание не выгружалось). */
  offlineJob: (runId: number) => json<OfflineJobOut>(`/runs/${runId}/offline`),
  /** «Выгрузить задание»: файл .scnjob (прогон переходит в «Выполняется»). */
  exportOfflineJob: (runId: number, validDays: number) =>
    request(`/runs/${runId}/offline/export?valid_days=${validDays}`, { method: "POST" }).then(fileOf),
  /** Скачать выгруженное задание ещё раз (тот же файл). */
  downloadOfflineJob: (runId: number) => request(`/runs/${runId}/offline/job`).then(fileOf),
  cancelOfflineJob: (runId: number) => json<{ run_id: number }>(`/runs/${runId}/offline/cancel`, { method: "POST" }),
  previewOfflineResult: (file: Blob) =>
    json<OfflineResultHeader>("/offline/results/preview", { method: "POST", body: file, headers: { "Content-Type": "application/octet-stream" } }),
  /** «Загрузить результат» с носителя (.scnres). */
  importOfflineResult: (file: Blob) =>
    json<OfflineImportOut>("/offline/results", { method: "POST", body: file, headers: { "Content-Type": "application/octet-stream" } }),
  centerKey: () => json<OfflineKeyOut>("/offline/center-key"),
  centerKeyFile: () => request("/offline/center-key?format=file").then(fileOf),
  nodeKey: (nodeId: number) => json<OfflineKeyOut>(`/nodes/${nodeId}/public-key`),
  setNodeKey: (nodeId: number, publicKey: string) =>
    json<OfflineKeyOut>(`/nodes/${nodeId}/public-key`, { method: "PUT", ...body({ public_key: publicKey }) }),
  nodeOfflineJobs: (nodeId: number) => json<OfflineJobOut[]>(`/nodes/${nodeId}/offline-jobs`),
  /** Отчёт как Blob: эндпоинт требует Bearer, поэтому обычная ссылка не подходит. */
  report: async (
    runId: number,
    format: ReportFormat,
    variant: ReportVariant = "full",
    compareTo: number | null = null,
    groupId: number | null = null,
    sections: ReportSections = {},
  ): Promise<Blob> => {
    const cmp = compareTo === null ? "" : `&compare_to=${compareTo}`;
    const grp = groupId === null ? "" : `&group_id=${groupId}`;
    // Разделы-опции: без плана — plan=false; профили соответствия — списком (none — без раздела).
    const plan = sections.plan === false ? "&plan=false" : "";
    const det = sections.details === false ? "&details=false" : "";
    const cmpl =
      sections.compliance === undefined ? "" : `&compliance=${encodeURIComponent(sections.compliance.join(",") || "none")}`;
    const res = await request(`/runs/${runId}/report?format=${format}&variant=${variant}${cmp}${grp}${plan}${det}${cmpl}`);
    return res.blob();
  },

  /** Состояние самого сканера; refresh — проверить заново, минуя кэш сервера. */
  systemHealth: (refresh = false) => json<SystemHealth>(`/system/health${refresh ? "?refresh=true" : ""}`),

  audit: (params: { limit?: number; before_id?: number } & AuditFilters = {}) =>
    json<AuditOut[]>(`/audit${auditQuery(params)}`),
  auditActions: () => json<string[]>("/audit/actions"),
  /** Выгрузка журнала: файл через fetch с Bearer, как и отчёты. */
  auditExport: async (format: AuditExportFormat, filters: AuditFilters): Promise<Blob> => {
    const res = await request(`/audit/export${auditQuery({ format, ...filters })}`);
    return res.blob();
  },
};
