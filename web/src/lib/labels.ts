// Русские подписи для значений API и справочники модулей/профилей.

import type { FindingStatus, RunStatus, Severity, VulnEngine } from "../api/types";

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
  { id: "config_audit", label: "Аудит конфигураций", description: "CIS, требования ФСТЭК/ГОСТ (OpenSCAP, Lynis по SSH)" },
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
    description: "Учётные записи активов: заводить и запускать с ними поиск уязвимостей по учётной записи",
  },
];

export const ROLE_LABEL: Record<string, string> = Object.fromEntries(ROLES.map((r) => [r.id, r.label]));
