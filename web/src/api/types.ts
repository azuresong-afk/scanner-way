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

export interface RunCreate {
  targets: string[];
  modules: string[];
  rate_profile: string;
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
