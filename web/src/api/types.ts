// Типы ответов API — зеркало scanner/api/schemas.py.

export type Severity = "info" | "low" | "medium" | "high" | "critical";
export type FindingStatus = "open" | "fixed" | "new" | "regression";
/** partial — «Частично»: прогон завершён, но часть хостов/модулей не проверена (см. покрытие). */
export type RunStatus = "pending" | "running" | "done" | "partial" | "failed" | "stopped" | "interrupted";
export type ReportFormat = "html" | "pdf" | "docx" | "json";
/** full — полный отчёт; brief — без плана устранения, по находкам только ссылки на устранение. */
export type ReportVariant = "full" | "brief";

/** Необязательные разделы отчёта. plan=false — без «Плана устранения»; compliance —
 * профили соответствия в отчёте ([] — без раздела; не задано — по настройкам договора). */
export interface ReportSections {
  plan?: boolean;
  compliance?: string[];
}

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
  /** Диапазон «начало-конец», частью которого является подсеть; null — обычная запись. */
  range_spec?: string | null;
}

/** Несколько целей сразу: адреса, подсети CIDR, диапазоны «начало-конец». */
export interface AllowlistBulkIn {
  items: string[];
  note?: string | null;
}

export interface AllowlistBulkOut {
  added: AllowlistOut[];
  /** Уже целиком в allowlist — не добавлены. */
  skipped: { item: string; reason: string; existing_cidr: string | null }[];
  /** Диапазоны, часть подсетей которых уже была в allowlist. */
  partial: { item: string; covered_parts: number }[];
}

/** Движок поиска уязвимостей: сетевые проверки Nuclei и/или пакеты по учётной записи. */
export type VulnEngine = "nuclei" | "credentialed" | "both";

export interface RunCreate {
  targets: string[];
  modules: string[];
  rate_profile: string;
  vuln_engine?: VulnEngine;
  credential_ids?: number[];
  /** Наборы проверки учёток для модуля cred_audit (аудит паролей). */
  cred_set_ids?: number[];
  /** Своё имя; пусто — имя по выбранным опциям. */
  name?: string;
  /** Сканировать хосты, не отвечающие на ping (nmap -Pn). */
  no_ping?: boolean;
  /** Готовый профиль проверки (GET /run-profiles). */
  profile?: string;
}

/** Готовый профиль проверки («Полная проверка Linux» и др.). */
export interface RunProfile {
  id: string;
  title: string;
  description: string;
  modules: string[];
  /** Протоколы учёток, без которых профиль неполон: ssh | winrm. */
  needs: string[];
}

export interface PlannedModule {
  name: string;
  title: string;
  /** Добавлен автоматически как спутник другого модуля. */
  companion: boolean;
  note: string | null;
}

/** Итоговый состав прогона до запуска (POST /engagements/{id}/runs/plan). */
export interface RunPlan {
  modules: PlannedModule[];
  removed: PlannedModule[];
  warnings: string[];
  full_check: boolean;
  accepted_targets: number;
  denied_targets: DeniedTarget[];
}

export type CoverageStatus = "completed" | "not_applicable" | "skipped" | "unreachable" | "no_credentials" | "timeout" | "error";
export type HostCoverageStatus = "checked" | "partial" | "unreachable" | "not_checked";

export interface CoverageEntry {
  host: string;
  module: string;
  status: CoverageStatus;
  label: string;
  reason: string | null;
}

export interface CoverageSummary {
  hosts: number;
  hosts_checked: number;
  hosts_partial: number;
  hosts_unreachable: number;
  hosts_not_checked: number;
  counts: Record<CoverageStatus, number>;
  gaps: number;
  auth_gaps: number;
}

/** Что реально проверено в прогоне: хост × модуль. */
export interface CoverageOut {
  scan_run_id: number;
  status: RunStatus;
  summary: CoverageSummary;
  hosts: { host: string; status: HostCoverageStatus; modules: Record<string, { status: CoverageStatus; label: string; reason: string | null }> }[];
  entries: CoverageEntry[];
  /** Прогон до обновления: покрытие оценено по модулям и найденным хостам. */
  legacy: boolean;
}

/** Предупреждение прогона (например «Бэкпорты не учтены»). */
export interface RunWarning {
  kind: string;
  message: string;
  family?: string;
  release?: string;
  os?: string;
  hosts?: string[];
  loadable?: boolean;
}

/** Сопоставимость прогона с базовым: same | partial | none. */
export interface Comparability {
  level: "same" | "partial" | "none";
  common_hosts: string[];
  common_modules: string[];
  only_baseline_hosts: string[];
  only_current_hosts: string[];
  only_baseline_modules: string[];
  only_current_modules: string[];
  warnings: string[];
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
  cred_set_ids: number[];
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

export type FeedKind = "daily" | "weekly" | "monthly";

/** Справочник (БДУ, NVD, шаблоны Nuclei) и его автообновление. */
export interface FeedOut {
  source: string;
  title: string;
  description: string;
  kind: FeedKind;
  time_of_day: string;
  weekdays: number[];
  month_day: number | null;
  timezone: string;
  enabled: boolean;
  next_run_at: string | null;
  last_run_at: string | null;
  last_success_at: string | null;
  /** ok | unchanged | error */
  last_result: string | null;
  last_count: number | null;
  message: string | null;
  /** Обновление идёт прямо сейчас. */
  running: boolean;
  /** Прогресс текущей загрузки (null — не идёт). */
  progress?: FeedProgress | null;
  /** message — итог ПРОШЛОЙ попытки (идёт новая). */
  message_is_previous?: boolean;
  last_error_at?: string | null;
}

export interface FeedProgress {
  stage: string | null;
  done: number | null;
  total: number | null;
  percent: number | null;
  rate_per_sec: number | null;
  eta_seconds: number | null;
  elapsed_seconds: number;
  started_at: string;
  updated_at: string | null;
}

export type FeedState = "ready" | "missing" | "running" | "error" | "stale";

export interface FeedReadinessItem {
  source: string;
  title: string;
  purpose: string;
  required: boolean;
  state: FeedState;
  records: number | null;
  progress: FeedProgress | null;
  auto_update: boolean;
  last_success_at: string | null;
  last_result: string | null;
  message: string | null;
  message_is_previous: boolean;
  last_error_at: string | null;
  hint: string | null;
}

export interface MissingRelease {
  family: string;
  release: string;
  os: string | null;
  hosts: string[];
  runs: number[];
}

/** Мастер настройки справочников: готовность каждого источника. */
export interface FeedReadiness {
  ready: boolean;
  sources: FeedReadinessItem[];
  releases: { family: string; release: string; records: number; loaded_at: string | null }[];
  missing_releases: MissingRelease[];
}

export interface FeedScheduleIn {
  enabled: boolean;
  kind: FeedKind;
  time_of_day: string;
  weekdays?: number[];
  month_day?: number;
  timezone?: string;
}

export type CredentialAuth = "password" | "key";

/** Повышение прав для аудита конфигураций: sudo (пароль учётки / NOPASSWD) или без него. */
export type CredentialBecome = "sudo" | "none";

/** Способ входа: SSH (Linux) или WinRM (Windows, только пароль). */
export type CredentialProtocol = "ssh" | "winrm";

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
  become?: CredentialBecome;
  protocol?: CredentialProtocol;
  /** Домен Windows для WinRM: логин сохраняется как ДОМЕН\user. */
  domain?: string;
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
  become: CredentialBecome;
  protocol: CredentialProtocol;
}

export interface PackageOut {
  host: string;
  manager: string;
  name: string;
  version: string;
  arch: string | null;
}

/** Одна проверяемая пара логин/секрет. Пустой секрет — проверка пустого пароля. */
export interface CredSetEntry {
  username: string;
  secret: string;
}

/** Набор проверки учёток на вход. Секреты API принимает, но никогда не отдаёт. */
export interface CredSetIn {
  name: string;
  /** Сервисы, к которым применять набор; пусто — все поддерживаемые. */
  services?: string[];
  entries: CredSetEntry[];
}

export interface CredSetOut {
  id: number;
  engagement_id: number;
  name: string;
  services: string[];
  entry_count: number;
  /** Маскированные логины (секреты не раскрываются). */
  masked_usernames: string[];
  created_by: number | null;
  created_at: string | null;
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
  cred_set_ids: number[];
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
  /** Причина ошибки или прерывания — для пользователя. */
  error_message?: string | null;
  /** Прогон, который повторяет этот («Повторить»). */
  retry_of?: number | null;
  /** Опции запуска: no_ping, profile. */
  options?: { no_ping?: boolean; profile?: string };
  /** Предупреждения о неполноте результата («Бэкпорты не учтены» и др.). */
  warnings?: RunWarning[];
}

/** Страница списка: элементы и общее число по фильтру (X-Total-Count). */
export interface Page<T> {
  items: T[];
  total: number;
}

export type FindingSort = "severity" | "priority" | "cvss" | "host" | "title" | "module" | "id";

/** Параметры серверной выборки находок прогона (GET /runs/{id}/findings). */
export interface FindingQuery {
  severity?: Severity[];
  module?: string[];
  status?: string[];
  host?: string;
  q?: string;
  bdu_only?: boolean;
  include_info?: boolean;
  false_positives?: "include" | "exclude" | "only";
  sort?: FindingSort;
  order?: "asc" | "desc";
  limit?: number;
  offset?: number;
}

export interface RunQuery {
  status?: RunStatus[];
  q?: string;
  sort?: "id" | "created_at" | "started_at" | "finished_at" | "status" | "name";
  order?: "asc" | "desc";
  limit?: number;
  offset?: number;
}

export interface HostCountsOut {
  host: string;
  counts: Record<Severity, number>;
  total: number;
}

/** Сводка прогона с сервера (ложные срабатывания в счётчиках не участвуют). */
export interface FindingsSummary {
  counts: Record<Severity, number>;
  open: number;
  hosts: number;
  new: number;
  regression: number;
  fixed: number;
  false_positives: number;
  bdu_share: number | null;
  modules: string[];
  statuses: Record<string, number>;
  previous_run_id: number | null;
  host_counts: HostCountsOut[];
  /** Находки базового прогона на хостах/модулях, не проверенных в этом прогоне. */
  unverified?: number;
  comparability?: Comparability | null;
  coverage?: CoverageSummary | null;
}

export interface RunCreated extends RunOut {
  accepted_targets: number;
  denied_targets: DeniedTarget[];
}

/** Отметка «ложное срабатывание» (действует во всех прогонах договора). */
/** Массовая отметка «ложное срабатывание» всех уязвимостей ПО. */
export interface SoftwareFalsePositiveIn {
  software: string;
  version: string | null;
  host?: string | null;
  all_hosts?: boolean;
  reason?: string | null;
  dry_run?: boolean;
}

export interface SoftwareFalsePositiveOut {
  matched: number;
  changed: number;
  hosts: number;
  dry_run: boolean;
}

export interface FalsePositiveMark {
  reason: string | null;
  marked_by: string | null;
  marked_at: string | null;
}

export type PriorityLabel = "critical" | "high" | "medium" | "low";

/** Приоритет исправления (R6): ранг в прогоне, балл 0–100 и факторы, из которых он сложился. */
export interface PriorityOut {
  rank: number;
  score: number;
  label: PriorityLabel;
  label_ru: string;
  reasons: string[];
  factors: {
    cvss: number | null;
    in_kev: boolean;
    epss: number | null;
    epss_percentile: number | null;
    exploit_available: boolean;
    asset_criticality: string;
  };
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
  /** null — информационная находка или ложное срабатывание. */
  priority?: PriorityOut | null;
  /** Уверенность: high — пакет/бюллетень вендора, low — только баннер. */
  confidence?: "high" | "medium" | "low" | null;
  /** Источник: authenticated_package | vendor_advisory | banner | nuclei | … */
  source?: string | null;
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

// ---- проверка входа по учётным записям активов ----
export type CredLoginStatus = "ok" | "auth_failed" | "timeout" | "unreachable" | "host_key_mismatch" | "error";
export type CredHostStatus = CredLoginStatus | "partial" | "no_credential" | "not_in_allowlist";

export interface CredentialCheckIn {
  hosts: string[];
  credential_ids?: number[];
}

export interface CredentialLoginOut {
  credential_id: number;
  credential: string;
  protocol: "ssh" | "winrm";
  username: string;
  port: number;
  status: CredLoginStatus;
  message: string;
  elapsed_ms: number;
}

export interface CredentialHostCheckOut {
  host: string;
  status: CredHostStatus;
  message: string;
  results: CredentialLoginOut[];
  elapsed_ms: number;
}

export interface CredentialCheckOut {
  hosts: CredentialHostCheckOut[];
  checked_at: string;
}

// ---- активы (R7) ----
export type Criticality = "low" | "medium" | "high" | "critical";

export interface AssetGroupRef {
  id: number;
  name: string;
}

export interface AssetOut {
  id: number;
  engagement_id: number;
  address: string;
  hostname: string | null;
  owner: string | null;
  criticality: Criticality;
  notes: string | null;
  tags: string[];
  groups: AssetGroupRef[];
  created_at: string | null;
  /** Из последних прогонов; null — хост в прогонах не встречался. */
  os_guess: string | null;
  os_family: string | null;
  os_family_label: string | null;
  last_run_id: number | null;
  finding_counts: Partial<Record<Severity, number>>;
  findings_total: number;
}

export interface AssetIn {
  address: string;
  hostname?: string | null;
  owner?: string | null;
  criticality?: Criticality;
  notes?: string | null;
  tags?: string[];
  group_ids?: number[];
}

export type AssetUpdate = Partial<AssetIn>;

export interface AssetBulkIn {
  asset_ids: number[];
  add_tags?: string[];
  remove_tags?: string[];
  add_group_ids?: number[];
  remove_group_ids?: number[];
  criticality?: Criticality;
  owner?: string | null;
}

export interface AssetGroupOut {
  id: number;
  engagement_id: number;
  name: string;
  asset_count: number;
  created_at: string | null;
}

export interface AssetTagOut {
  tag: string;
  count: number;
}

export interface AssetFilters {
  tag?: string;
  group_id?: number;
  criticality?: Criticality;
  q?: string;
}

export type ChannelType = "smtp" | "telegram" | "syslog_cef" | "jira";
export type NotifyEvent = "run_finished" | "new_critical" | "feed_stale";

export interface ChannelFilters {
  min_severity: Severity | null;
  min_priority: "critical" | "high" | "medium" | "low" | null;
  groups: string[];
  owners: string[];
  engagements: number[];
}

/** Канал уведомлений. Секреты API принимает, но никогда не отдаёт (только has_secret). */
export interface ChannelOut {
  id: number;
  name: string;
  type: ChannelType;
  enabled: boolean;
  config: Record<string, unknown>;
  events: NotifyEvent[];
  filters: ChannelFilters;
  has_secret: boolean;
  created_at: string;
  updated_at: string;
}

export interface ChannelIn {
  name: string;
  type: ChannelType;
  enabled: boolean;
  config: Record<string, unknown>;
  secrets: Record<string, string>;
  events: NotifyEvent[];
  filters: ChannelFilters;
}

export type ChannelUpdate = Partial<Omit<ChannelIn, "type">>;

export interface DeliveryOut {
  id: number;
  channel_id: number;
  channel_name: string | null;
  event: NotifyEvent | "test";
  /** pending | retry | sent | failed */
  status: string;
  attempts: number;
  next_attempt_at: string | null;
  last_error: string | null;
  engagement_id: number | null;
  scan_run_id: number | null;
  external_ref: string | null;
  summary: string;
  created_at: string;
  sent_at: string | null;
}

// ---------- Соответствие (R5) ----------
export type ComplianceStatus = "passed" | "failed" | "manual" | "na";

export interface ComplianceControlDef {
  id: string;
  title: string;
  group: string;
  levels: string[];
  checks: string[];
  manual: boolean;
}

export interface ComplianceProfileDef {
  id: string;
  title: string;
  short: string;
  document: string;
  url: string;
  level_label: string;
  levels: string[];
  default_level: string | null;
  dynamic: string | null;
  groups: { code: string; title: string }[];
  controls: ComplianceControlDef[];
}

export interface ComplianceProfileOut {
  profile: string;
  level: string | null;
  excluded: string[];
  added: string[];
  in_report: boolean;
  updated_at?: string | null;
}

export interface ComplianceProfileIn {
  level: string | null;
  excluded: string[];
  added: string[];
  in_report: boolean;
}

export interface ComplianceFailure {
  kind: "finding" | "fact";
  key?: string;
  vuln_id?: string | null;
  title: string;
  severity?: string;
}

export interface ComplianceRecommendation {
  check: string;
  title: string;
  remediation: string;
  doc: string | null;
}

export interface ComplianceControl {
  id: string;
  title: string;
  group: string;
  group_title: string;
  status: ComplianceStatus;
  hosts: Record<ComplianceStatus, number>;
  added: boolean;
  failed_hosts?: { host: string; checks: { id: string; failures: ComplianceFailure[]; more: number }[] }[];
  recommendations?: ComplianceRecommendation[];
}

export interface ComplianceBreakdown {
  passed: number;
  failed: number;
  na?: number;
  percent: number | null;
}

export interface ComplianceSummary {
  run_id: number;
  has_results: boolean;
  profile: { id: string; title: string; short: string; document: string; url: string; level_label: string; levels: string[] };
  level: string | null;
  adapted: { excluded: string[]; added: string[] };
  percent: number | null;
  counts: Record<ComplianceStatus, number>;
  evaluated: number;
  automated: number;
  hosts: (ComplianceBreakdown & { host: string })[];
  groups: (ComplianceBreakdown & { group: string; hosts: number })[];
  controls: ComplianceControl[];
  failures: ComplianceControl[];
  manual: { id: string; title: string; group: string; group_title: string }[];
}

// ---------- План исправлений («Находки» → «Что исправить») ----------

export type FixKind =
  | "package"
  | "package_nofix"
  | "package_upgrade"
  | "kernel"
  | "software"
  | "config"
  | "cred"
  | "vuln"
  | "other";

export interface FixHostOut {
  host: string;
  /** Установленная версия пакета / работающее ядро / версия ПО. */
  installed: string | null;
  note: string | null;
  ports: number[];
  findings: { id: number; label: string; severity: Severity }[];
}

export interface FixTaskOut {
  key: string;
  kind: FixKind;
  kind_label: string;
  title: string;
  os: string | null;
  os_family: string | null;
  manager: string | null;
  packages: string[];
  fixed_version: string | null;
  software: string | null;
  steps: string[];
  commands: string[];
  verify: string[];
  reboot: boolean;
  details: string | null;
  details_source: string | null;
  severity: Severity;
  priority: { score: number; label: PriorityOut["label"]; label_ru: string; rank: number | null } | null;
  cves: string[];
  bdu_ids: string[];
  advisories: string[];
  references: string[];
  hosts: FixHostOut[];
  host_count: number;
  finding_count: number;
}

export interface FixPlanOut {
  total: number;
  items: FixTaskOut[];
  tasks: number;
  hosts: number;
  findings: number;
  false_positives: number;
  kinds: Partial<Record<FixKind, number>>;
  os: Record<string, number>;
  severities: Partial<Record<Severity, number>>;
}

export interface FixQuery {
  severity?: Severity[];
  kind?: string[];
  os?: string[];
  host?: string;
  q?: string;
  limit?: number;
  offset?: number;
}
