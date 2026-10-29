// Типы ответов API — зеркало scanner/api/schemas.py.

export type Severity = "info" | "low" | "medium" | "high" | "critical";
export type FindingStatus = "open" | "fixed" | "new" | "regression";
export type RunStatus = "pending" | "running" | "done" | "failed" | "stopped";
export type ReportFormat = "html" | "pdf" | "docx" | "json";
/** full — полный отчёт; brief — без плана устранения, по находкам только ссылки на устранение. */
export type ReportVariant = "full" | "brief";

export interface TokenOut {
  access_token: string;
  token_type: string;
  expires_in: number;
}

export interface UserOut {
  id: number;
  username: string;
  display_name: string | null;
  is_active: boolean;
  roles: string[];
}

export interface MeOut extends UserOut {
  permissions: string[];
}

export interface UserCreate {
  username: string;
  password: string;
  display_name?: string | null;
  roles: string[];
}

export interface UserUpdate {
  display_name?: string | null;
  is_active?: boolean;
  password?: string;
}

export interface EngagementIn {
  name: string;
  client?: string | null;
  contract_ref?: string | null;
}

export interface EngagementOut {
  id: number;
  name: string;
  client: string | null;
  contract_ref: string | null;
  created_by: number | null;
  created_at: string | null;
}

export interface AllowlistIn {
  cidr: string;
  note?: string | null;
}

export interface AllowlistOut {
  id: number;
  cidr: string;
  note: string | null;
  added_by: number | null;
  added_at: string | null;
}

/** Движок поиска уязвимостей: сетевые проверки Nuclei и/или пакеты по учётной записи. */
export type VulnEngine = "nuclei" | "credentialed" | "both";

export interface RunCreate {
  targets: string[];
  modules: string[];
  rate_profile: string;
  vuln_engine?: VulnEngine;
  credential_ids?: number[];
}

export type CredentialAuth = "password" | "key";

/** Учётка актива на вход. Секреты API принимает, но никогда не отдаёт. */
export interface CredentialIn {
  name: string;
  username: string;
  auth: CredentialAuth;
  port?: number;
  password?: string;
  private_key?: string;
  passphrase?: string;
  targets?: string[];
}

export interface CredentialOut {
  id: number;
  engagement_id: number;
  name: string;
  username: string;
  auth: CredentialAuth;
  port: number;
  /** CIDR области действия; пусто — все цели прогона. */
  targets: string[];
  key_fingerprint: string | null;
  created_by: number | null;
  created_at: string | null;
}

export interface PackageOut {
  host: string;
  manager: string;
  name: string;
  version: string;
  arch: string | null;
}

export interface DeniedTarget {
  target: string;
  reason: string;
  count: number;
}

export interface RunOut {
  id: number;
  engagement_id: number;
  modules: string[];
  rate_profile: string;
  credential_ids: number[];
  status: RunStatus;
  started_by: number | null;
  started_at: string | null;
  finished_at: string | null;
  created_at: string | null;
}

export interface RunCreated extends RunOut {
  accepted_targets: number;
  denied_targets: DeniedTarget[];
}

export interface FindingOut {
  module: string;
  host: string;
  port: number | null;
  finding_type: string;
  title: string;
  severity: Severity;
  vuln_id: string | null;
  cve_ids: string[];
  bdu_ids: string[];
  cvss: number | null;
  evidence: string | null;
  status: FindingStatus | null;
  detected_at: string;
}

export interface ServiceOut {
  host: string;
  port: number;
  protocol: string;
  service: string | null;
  product: string | null;
  version: string | null;
  cpe: string | null;
}

/** Хост инвентаря договора (по всем прогонам). */
export interface InventoryHostOut {
  host: string;
  os_guess: string | null;
  /** Прогоны, в которых хост встречался, по возрастанию. */
  run_ids: number[];
  /** Прогон, из которого взяты сервисы (последний, где они были). */
  services_run_id: number | null;
  services: ServiceOut[];
  /** Последний прогон с инвентаризацией по учётной записи и число пакетов хоста. */
  packages_run_id: number | null;
  package_count: number;
}

export type AuditExportFormat = "csv" | "json";

/** Фильтр журнала: since/until — ISO 8601 с зоной, полуинтервал [since, until). */
export interface AuditFilters {
  subject?: string;
  actions?: string[];
  since?: string;
  until?: string;
}

export interface AuditOut {
  id: number;
  ts: string;
  subject: string;
  action: string;
  target: string | null;
  result: string | null;
  details: Record<string, unknown> | null;
}

export type PortState = "open" | "closed" | "filtered";

export interface ReachabilityIn {
  target: string;
  ports?: number[];
}

export interface ReachabilityOut {
  target: string;
  reachable: boolean;
  methods: ("icmp" | "tcp")[];
  icmp_available: boolean;
  icmp_alive: boolean;
  icmp_rtt_ms: number | null;
  ports: { port: number; state: PortState; rtt_ms: number | null }[];
  elapsed_ms: number;
  checked_at: string;
}
