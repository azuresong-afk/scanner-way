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
  /** Своё имя; пусто — имя по выбранным опциям. */
  name?: string;
}

export type ScheduleKind = "once" | "daily" | "weekly" | "monthly";

/** Прогон по расписанию: параметры прогона + когда запускать. */
export interface ScheduleIn extends RunCreate {
  kind: ScheduleKind;
  /** ЧЧ:ММ в timezone — для daily/weekly/monthly. */
  time_of_day?: string;
  /** 0 — понедельник … 6 — воскресенье. */
  weekdays?: number[];
  month_day?: number;
  /** Момент разового запуска (ISO). */
  run_at?: string;
  /** IANA-пояс; по умолчанию — пояс браузера. */
  timezone?: string;
  enabled?: boolean;
}

export interface ScheduleOut {
  id: number;
  engagement_id: number;
  name: string | null;
  /** name или имя по опциям. */
  title: string;
  targets: string[];
  modules: string[];
  rate_profile: string;
  credential_ids: number[];
  kind: ScheduleKind;
  time_of_day: string | null;
  weekdays: number[];
  month_day: number | null;
  run_at: string | null;
  timezone: string;
  enabled: boolean;
  next_run_at: string | null;
  last_run_at: string | null;
  /** queued | skipped_overlap | skipped_no_rights | error: … */
  last_result: string | null;
  last_run_id: number | null;
  owner_id: number | null;
  created_at: string | null;
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
  /** Имя по выбранным опциям (модули и цели) или заданное оператором. */
  name: string;
  targets: string[];
  /** Расписание, по которому поставлен прогон. */
  schedule_id: number | null;
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

/** Отметка «ложное срабатывание» (действует во всех прогонах договора). */
export interface FalsePositiveMark {
  reason: string | null;
  marked_by: string | null;
  marked_at: string | null;
}

export interface FindingOut {
  id: number;
  dedup_key: string;
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
  false_positive: FalsePositiveMark | null;
  /** ПО находки: продукт сервиса на порту или ПО установленного пакета; null — не определено. */
  software?: string | null;
  software_version?: string | null;
  software_source?: "service" | "package" | null;
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
  /** Семейство ОС: astra, redos, alt, ubuntu, debian, windows, linux…; null — не определена. */
  os_family?: string | null;
  os_family_label?: string;
  /** Откуда ОС: nmap (-O), banner (баннеры сервисов), ssh (/etc/os-release по учётной записи). */
  os_source?: "nmap" | "banner" | "ssh" | null;
  /** Точность nmap, %; 100 — прочитано на хосте. */
  os_accuracy?: number | null;
  os_run_id?: number | null;
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
