// Русские подписи для значений API и справочники модулей/профилей.

import type { Criticality, FindingStatus, RunOut, RunStatus, ScheduleOut, Severity, VulnEngine } from "../api/types";

export const SEVERITIES: Severity[] = ["critical", "high", "medium", "low", "info"];

export const SEVERITY_LABEL: Record<Severity, string> = {
  critical: "Критический",
  high: "Высокий",
  medium: "Средний",
  low: "Низкий",
  info: "Информационный",
};

export const SEVERITY_SHORT: Record<Severity, string> = {
  critical: "Крит.",
  high: "Выс.",
  medium: "Сред.",
  low: "Низк.",
  info: "Инфо",
};

export const STATUS_LABEL: Record<FindingStatus, string> = {
  new: "Новая",
  open: "Открыта",
  regression: "Регрессия",
  fixed: "Устранена",
};

export const RUN_STATUS_LABEL: Record<RunStatus, string> = {
  pending: "В очереди",
  running: "Выполняется",
  done: "Завершён",
  failed: "Ошибка",
  stopped: "Остановлен",
};

export const FINISHED: RunStatus[] = ["done", "failed", "stopped"];
export const isFinished = (s: RunStatus) => FINISHED.includes(s);

export interface ModuleInfo {
  id: string;
  label: string;
  description: string;
  /** Право сверх run_scan, без которого модуль не показывается. */
  permission?: string;
}

// Совпадает с default_module_registry() и MODULE_PERMISSIONS на бэкенде.
export const MODULES: ModuleInfo[] = [
  { id: "discovery", label: "Обнаружение и инвентаризация", description: "Хосты, порты, сервисы, версии, ОС (nmap)" },
  { id: "vuln", label: "Поиск уязвимостей", description: "CVE/NVD и БДУ ФСТЭК (Nuclei)" },
  {
    id: "auth_inventory",
    label: "Уязвимости по учётной записи",
    description: "Пакеты и версии ПО на хосте (SSH) → БДУ ФСТЭК и CVE/NVD",
    permission: "host_credentials",
  },
  {
    id: "config_audit",
    label: "Аудит конфигураций",
    description: "CIS, требования ФСТЭК/ГОСТ (OpenSCAP, Lynis) по учётной записи с sudo",
    permission: "host_credentials",
  },
  {
    id: "cred_audit",
    label: "Аудит учётных данных",
    description: "Проверка слабых и стандартных паролей по договору, с лимитами попыток",
    permission: "cred_audit",
  },
];

export const MODULE_LABEL: Record<string, string> = Object.fromEntries(MODULES.map((m) => [m.id, m.label]));

/** Модули поиска уязвимостей — выбираются движком, а не флажками. */
export const ENGINE_MODULES = ["vuln", "auth_inventory"];

/** Модули, которые входят на хосты по учётным записям договора (CREDENTIAL_MODULES на бэкенде). */
export const CREDENTIAL_MODULES = ["auth_inventory", "config_audit"];

export interface EngineInfo {
  id: VulnEngine | "none";
  label: string;
  description: string;
  modules: string[];
  /** Нужна учётная запись (и право host_credentials). */
  credentials: boolean;
}

// Совпадает с VULN_ENGINES на бэкенде.
export const VULN_ENGINES: EngineInfo[] = [
  { id: "nuclei", label: "Nuclei", description: "Сетевые проверки снаружи, без учётной записи", modules: ["vuln"], credentials: false },
  {
    id: "credentialed",
    label: "По учётной записи",
    description: "Вход по SSH, пакеты и версии ПО → БДУ/CVE",
    modules: ["auth_inventory"],
    credentials: true,
  },
  { id: "both", label: "Оба движка", description: "Nuclei и инвентаризация по учётной записи", modules: ["vuln", "auth_inventory"], credentials: true },
  { id: "none", label: "Не искать", description: "Только выбранные ниже модули", modules: [], credentials: false },
];

export const MODULE_SHORT: Record<string, string> = {
  discovery: "Обнаружение",
  vuln: "Уязвимости (Nuclei)",
  auth_inventory: "Уязвимости (учётка)",
  config_audit: "Конфигурации",
  cred_audit: "Учётные данные",
};

export const moduleList = (ids: string[]) => ids.map((m) => MODULE_SHORT[m] ?? m).join(", ");

// Имя прогона по опциям — то же правило, что scanner/core/naming.py на бэкенде
// (здесь — для подсказки в форме до отправки).
const TITLE_PARTS: [string, string][] = [
  ["discovery", "обнаружение"],
  ["vuln", "Nuclei"],
  ["auth_inventory", "учётная запись"],
  ["config_audit", "конфигурации"],
  ["cred_audit", "пароли"],
];
const TITLE_ALONE: Record<string, string> = {
  auth_inventory: "по учётной записи",
  config_audit: "аудит конфигураций",
  cred_audit: "аудит паролей",
  discovery: "инвентаризация",
};
const cap = (s: string) => s.charAt(0).toUpperCase() + s.slice(1);

export function runTitle(modules: string[], targets: string[] = []): string {
  const names = [...new Set(modules)];
  let title: string;
  if (names.length === 1 && TITLE_ALONE[names[0]]) title = cap(TITLE_ALONE[names[0]]);
  else {
    const known = new Set(TITLE_PARTS.map(([m]) => m));
    const parts = [...TITLE_PARTS.filter(([m]) => names.includes(m)).map(([, l]) => l), ...names.filter((m) => !known.has(m))];
    title = parts.length ? cap(parts.join(" + ")) : "Прогон";
  }
  const items = [...new Set(targets.map((t) => t.trim()).filter(Boolean))];
  if (items.length) {
    const rest = items.length - 2;
    title += ` · ${items.slice(0, 2).join(", ")}${rest > 0 ? ` и ещё ${rest}` : ""}`;
  }
  return title;
}

/** Подпись прогона в списках. */
export const runName = (r: Pick<RunOut, "name" | "modules" | "targets">) => r.name || runTitle(r.modules, r.targets ?? []);

export const WEEKDAYS = ["Пн", "Вт", "Ср", "Чт", "Пт", "Сб", "Вс"];

export const SCHEDULE_KINDS = [
  { id: "daily", label: "Каждый день" },
  { id: "weekly", label: "По дням недели" },
  { id: "monthly", label: "Раз в месяц" },
  { id: "once", label: "Один раз" },
] as const;

/** «Каждый день в 03:00», «Пн, Пт в 22:00», «15-го числа в 01:00», «Один раз». */
export function scheduleWhen(s: Pick<ScheduleOut, "kind" | "time_of_day" | "weekdays" | "month_day">): string {
  const at = s.time_of_day ? ` в ${s.time_of_day}` : "";
  switch (s.kind) {
    case "daily":
      return `Каждый день${at}`;
    case "weekly":
      return s.weekdays.length === 7 ? `Каждый день${at}` : `${s.weekdays.map((d) => WEEKDAYS[d]).join(", ")}${at}`;
    case "monthly":
      return `${s.month_day}-го числа${at}`;
    default:
      return "Один раз";
  }
}

export const SCHEDULE_RESULT_LABEL: Record<string, string> = {
  queued: "Прогон поставлен",
  skipped_overlap: "Пропущен: предыдущий прогон ещё идёт",
  skipped_no_rights: "Выключено: у владельца нет прав на такой прогон",
};

export const scheduleResult = (r: string | null) => (r ? (SCHEDULE_RESULT_LABEL[r] ?? (r.startsWith("error") ? `Ошибка: ${r.replace(/^error:\s*/, "")}` : r)) : "—");

export const FINDING_TYPE_LABEL: Record<string, string> = {
  vuln: "Уязвимость",
  config: "Нарушение конфигурации",
  cred: "Слабые учётные данные",
  info: "Информация",
};

export const RATE_PROFILES = [
  { id: "gentle", label: "Щадящий", description: "Минимальная нагрузка на сеть заказчика" },
  { id: "normal", label: "Обычный", description: "Баланс скорости и нагрузки" },
  { id: "aggressive", label: "Быстрый", description: "Только для согласованных окон" },
];

export const ROLES = [
  { id: "admin", label: "Администратор", description: "Пользователи, договоры, allowlist, журнал аудита. Не запускает прогоны." },
  { id: "operator", label: "Оператор", description: "Запуск и остановка прогонов, просмотр результатов, отметка ложных срабатываний" },
  { id: "auditor", label: "Аудитор", description: "Просмотр и экспорт отчётов, журнал аудита" },
  { id: "cred_audit", label: "Право cred_audit", description: "Доступ к модулю аудита учётных данных (вдобавок к оператору)" },
  {
    id: "host_credentials",
    label: "Право host_credentials",
    description: "Учётные записи активов: заводить и запускать с ними поиск уязвимостей по учётной записи и аудит конфигураций",
  },
];

export const ROLE_LABEL: Record<string, string> = Object.fromEntries(ROLES.map((r) => [r.id, r.label]));

/** Семейства ОС в порядке групп — как scanner/core/osfamily.py (отечественные ОС первыми). */
export const OS_FAMILIES: { id: string; label: string }[] = [
  { id: "astra", label: "Astra Linux" },
  { id: "redos", label: "РЕД ОС" },
  { id: "alt", label: "Альт" },
  { id: "rosa", label: "РОСА" },
  { id: "msvsphere", label: "МСВСфера" },
  { id: "osnova", label: "ОС Основа" },
  { id: "ubuntu", label: "Ubuntu" },
  { id: "debian", label: "Debian" },
  { id: "centos", label: "CentOS" },
  { id: "rocky", label: "Rocky Linux" },
  { id: "almalinux", label: "AlmaLinux" },
  { id: "oracle", label: "Oracle Linux" },
  { id: "rhel", label: "Red Hat Enterprise Linux" },
  { id: "fedora", label: "Fedora" },
  { id: "suse", label: "SUSE / openSUSE" },
  { id: "alpine", label: "Alpine Linux" },
  { id: "linux", label: "Linux (дистрибутив не определён)" },
  { id: "windows", label: "Windows" },
  { id: "macos", label: "macOS / Apple" },
  { id: "bsd", label: "BSD" },
  { id: "network", label: "Сетевое оборудование" },
  { id: "other", label: "Другая ОС" },
  { id: "unknown", label: "ОС не определена" },
];
export const OS_FAMILY_ORDER = OS_FAMILIES.map((f) => f.id);
export const OS_FAMILY_LABEL: Record<string, string> = Object.fromEntries(OS_FAMILIES.map((f) => [f.id, f.label]));

/** Подсказка, откуда взята ОС хоста. */
export function osSourceHint(source: string | null | undefined, accuracy: number | null | undefined): string {
  if (source === "ssh") return "Прочитано на хосте (/etc/os-release) по учётной записи";
  if (source === "banner") return "По баннерам сервисов (nmap -sV) — без учётной записи Astra может выглядеть как Debian";
  if (source === "nmap") return `Отпечаток стека nmap -O${accuracy != null ? `, точность ${accuracy}%` : ""}: ядро без дистрибутива`;
  return "ОС не определена: нужен discovery с -O или учётная запись";
}

export const CRITICALITIES: Criticality[] = ["critical", "high", "medium", "low"];

export const CRITICALITY_LABEL: Record<Criticality, string> = {
  critical: "Критическая",
  high: "Высокая",
  medium: "Средняя",
  low: "Низкая",
};
