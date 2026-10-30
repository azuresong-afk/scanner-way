// Агрегаты для дашборда, таблиц и раздела по хостам (считаются на клиенте).

import type { FindingOut, FindingStatus, InventoryHostOut, ServiceOut, Severity } from "../api/types";
import { MODULE_LABEL, OS_FAMILY_LABEL, OS_FAMILY_ORDER, SEVERITIES } from "./labels";

export const SEVERITY_RANK: Record<Severity, number> = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };

export type SeverityCounts = Record<Severity, number>;

export const emptyCounts = (): SeverityCounts => ({ critical: 0, high: 0, medium: 0, low: 0, info: 0 });

/** Ключ сопоставления находок между прогонами — как dedup_key на бэкенде. */
export function findingKey(f: Pick<FindingOut, "host" | "port" | "vuln_id" | "title" | "module">): string {
  return [f.host, f.port ?? "", f.vuln_id ?? f.title, f.module].join("|");
}

/** Находка отмечена специалистом как ложное срабатывание. */
export const isFalsePositive = (f: FindingOut) => !!f.false_positive;

/** Информационные находки (host up, баннеры) и ложные срабатывания не считаются уязвимостями. */
export const isIssue = (f: FindingOut) => f.severity !== "info" && !isFalsePositive(f);

/** Счётчики по уровням; ложные срабатывания не считаются. */
export function severityCounts(findings: FindingOut[]): SeverityCounts {
  const c = emptyCounts();
  for (const f of findings) if (!isFalsePositive(f)) c[f.severity] += 1;
  return c;
}

/** Заменить находку в списке её обновлённой версией (после отметки/снятия). */
export function replaceFinding(list: FindingOut[], updated: FindingOut): FindingOut[] {
  return list.map((f) => (f.id === updated.id ? updated : f));
}

export const issueTotal = (c: SeverityCounts) => c.critical + c.high + c.medium + c.low;

export interface RunSummary {
  counts: SeverityCounts;
  open: number;
  hosts: number;
  newCount: number;
  regression: number;
  fixed: number;
  /** Доля уязвимостей (module=vuln) с привязкой к БДУ ФСТЭК, 0..1; null — нет таких находок. */
  bduShare: number | null;
  prevOpen: number | null;
  prevCritical: number | null;
  prevHosts: number | null;
}

function hostCount(findings: FindingOut[], services?: ServiceOut[]): number {
  const set = new Set(findings.map((f) => f.host));
  for (const s of services ?? []) set.add(s.host);
  return set.size;
}

export function summarize(
  current: FindingOut[],
  previous?: FindingOut[] | null,
  services?: ServiceOut[],
  prevServices?: ServiceOut[],
): RunSummary {
  const counts = severityCounts(current);
  const issues = current.filter(isIssue);
  const vulns = issues.filter((f) => f.cve_ids.length > 0 || f.bdu_ids.length > 0 || f.module === "vuln");
  let fixed = 0;
  let prevCounts: SeverityCounts | null = null;
  if (previous) {
    const now = new Set(issues.map(findingKey));
    fixed = previous.filter(isIssue).filter((f) => !now.has(findingKey(f))).length;
    prevCounts = severityCounts(previous);
  }
  return {
    counts,
    open: issueTotal(counts),
    hosts: hostCount(current, services),
    newCount: issues.filter((f) => f.status === "new").length,
    regression: issues.filter((f) => f.status === "regression").length,
    fixed,
    bduShare: vulns.length ? vulns.filter((f) => f.bdu_ids.length > 0).length / vulns.length : null,
    prevOpen: prevCounts ? issueTotal(prevCounts) : null,
    prevCritical: prevCounts ? prevCounts.critical : null,
    prevHosts: previous ? hostCount(previous, prevServices) : null,
  };
}

export interface HostRow {
  host: string;
  counts: SeverityCounts;
  total: number;
  maxSeverity: Severity;
  findings: FindingOut[];
  services: ServiceOut[];
  /** Краткое описание по данным discovery: «OpenSSH 7.4, nginx 1.20». */
  summary: string;
}

/** Сравнение «опаснее раньше»: по числу критических, высоких и т.д. */
export function compareRisk(a: SeverityCounts, b: SeverityCounts): number {
  for (const s of SEVERITIES) if (a[s] !== b[s]) return b[s] - a[s];
  return 0;
}

export function byHost(findings: FindingOut[], services: ServiceOut[] = []): HostRow[] {
  const map = new Map<string, HostRow>();
  const get = (host: string) => {
    let row = map.get(host);
    if (!row) {
      row = { host, counts: emptyCounts(), total: 0, maxSeverity: "info", findings: [], services: [], summary: "" };
      map.set(host, row);
    }
    return row;
  };
  for (const f of findings) {
    const row = get(f.host);
    row.findings.push(f);
    if (isFalsePositive(f)) continue; // показывается, но не считается
    row.counts[f.severity] += 1;
    if (f.severity !== "info") row.total += 1;
    if (SEVERITY_RANK[f.severity] > SEVERITY_RANK[row.maxSeverity]) row.maxSeverity = f.severity;
  }
  for (const s of services) get(s.host).services.push(s);
  for (const row of map.values()) {
    row.findings.sort(compareFindings);
    row.services.sort((a, b) => a.port - b.port);
    const names = row.services
      .map((s) => [s.product ?? s.service, s.version].filter(Boolean).join(" "))
      .filter(Boolean);
    row.summary = [...new Set(names)].slice(0, 3).join(", ");
  }
  return [...map.values()].sort((a, b) => compareRisk(a.counts, b.counts) || compareIp(a.host, b.host));
}

export interface InventoryRow extends HostRow {
  /** Хост был в выбранном прогоне (иначе счётчики не применимы). */
  inRun: boolean;
  lastRunId: number | null;
  /** Семейство ОС; "unknown" — не определена. */
  osFamily: string;
  osLabel: string;
  /** Как ОС определена: «Linux 4.15 - 5.8», PRETTY_NAME из os-release. */
  osName: string | null;
  osSource: InventoryHostOut["os_source"];
  osAccuracy: number | null;
}

export interface OsGroup {
  family: string;
  label: string;
  rows: InventoryRow[];
  counts: SeverityCounts;
  total: number;
}

/** Группы хостов по семейству ОС: отечественные ОС первыми, «не определена» — в конце. */
export function groupByOs(rows: InventoryRow[]): OsGroup[] {
  const map = new Map<string, OsGroup>();
  for (const r of rows) {
    let g = map.get(r.osFamily);
    if (!g) map.set(r.osFamily, (g = { family: r.osFamily, label: r.osLabel, rows: [], counts: emptyCounts(), total: 0 }));
    g.rows.push(r);
    if (r.inRun) {
      for (const s of SEVERITIES) g.counts[s] += r.counts[s];
      g.total += r.total;
    }
  }
  const rank = (f: string) => {
    const i = OS_FAMILY_ORDER.indexOf(f);
    return i < 0 ? OS_FAMILY_ORDER.length - 2 : i;
  };
  return [...map.values()].sort((a, b) => rank(a.family) - rank(b.family) || a.label.localeCompare(b.label));
}

/**
 * Строки вкладки «Хосты»: постоянный список инвентаря (порядок по IP),
 * а счётчики уязвимостей — из находок выбранного прогона.
 */
export function inventoryRows(inventory: InventoryHostOut[], findings: FindingOut[], runId: number | null): InventoryRow[] {
  const perHost = new Map(byHost(findings.filter(isIssue)).map((r) => [r.host, r]));
  return [...inventory]
    .sort((a, b) => compareIp(a.host, b.host))
    .map((h) => {
      const r = perHost.get(h.host);
      const base = byHost([], h.services)[0];
      return {
        host: h.host,
        counts: r?.counts ?? emptyCounts(),
        total: r?.total ?? 0,
        maxSeverity: r?.maxSeverity ?? "info",
        findings: r?.findings ?? [],
        services: base?.services ?? [],
        summary: base?.summary ?? "",
        inRun: runId !== null && (h.run_ids.includes(runId) || !!r),
        lastRunId: h.run_ids.length ? h.run_ids[h.run_ids.length - 1] : null,
        osFamily: h.os_family ?? "unknown",
        osLabel: h.os_family_label ?? OS_FAMILY_LABEL[h.os_family ?? "unknown"] ?? h.os_family ?? "ОС не определена",
        osName: h.os_guess,
        osSource: h.os_source ?? null,
        osAccuracy: h.os_accuracy ?? null,
      };
    });
}

export interface SoftwareRow {
  key: string;
  /** Название ПО; для находок без ПО — название модуля или «Сервис на порту N». */
  name: string;
  version: string | null;
  /** ПО определено (сервис/пакет); false — группа по модулю/порту. */
  known: boolean;
  /** Где найдено: порты сервиса и/или «пакет». */
  ports: string[];
  fromPackage: boolean;
  counts: SeverityCounts;
  total: number;
  maxSeverity: Severity;
  maxCvss: number | null;
  findings: FindingOut[];
}

/**
 * Уязвимости хоста по ПО (продукт + версия). Одно и то же ПО, найденное и по
 * баннеру на порту, и по пакету, — одна строка. Находки без ПО (аудит
 * конфигурации, пароли, порт без баннера) группируются по модулю/порту.
 * Ложные срабатывания показываются в группе, но не считаются.
 */
export function bySoftware(findings: FindingOut[], services: ServiceOut[] = []): SoftwareRow[] {
  const map = new Map<string, SoftwareRow>();
  for (const f of findings) {
    let name = f.software ?? null;
    let version = f.software_version ?? null;
    if (!name && f.port != null) {
      // старый API без поля software — берём сервис на порту
      const svc = services.find((s) => s.host === f.host && s.port === f.port);
      name = svc?.product ?? svc?.service ?? null;
      version = svc?.product ? (svc.version ?? null) : null;
    }
    const known = !!name;
    const key = known
      ? `sw:${name!.toLowerCase()}|${version ?? ""}`
      : f.port != null
        ? `port:${f.port}`
        : `module:${f.module}`;
    let row = map.get(key);
    if (!row) {
      row = {
        key,
        name: name ?? (f.port != null ? `Сервис на порту ${f.port}` : (MODULE_LABEL[f.module] ?? f.module)),
        version,
        known,
        ports: [],
        fromPackage: false,
        counts: emptyCounts(),
        total: 0,
        maxSeverity: "info",
        maxCvss: null,
        findings: [],
      };
      map.set(key, row);
    }
    row.findings.push(f);
    if (f.port != null) {
      const svc = services.find((s) => s.host === f.host && s.port === f.port);
      const p = `${f.port}/${svc?.protocol ?? "tcp"}`;
      if (!row.ports.includes(p)) row.ports.push(p);
    } else if (f.software_source === "package") row.fromPackage = true;
    if (isFalsePositive(f)) continue;
    row.counts[f.severity] += 1;
    if (f.severity !== "info") row.total += 1;
    if (SEVERITY_RANK[f.severity] > SEVERITY_RANK[row.maxSeverity]) row.maxSeverity = f.severity;
    if (f.cvss != null && (row.maxCvss == null || f.cvss > row.maxCvss)) row.maxCvss = f.cvss;
  }
  for (const row of map.values()) {
    row.findings.sort(compareFindings);
    row.ports.sort((a, b) => parseInt(a) - parseInt(b));
  }
  return [...map.values()].sort(
    (a, b) =>
      compareRisk(a.counts, b.counts) ||
      b.total - a.total ||
      Number(b.known) - Number(a.known) ||
      a.name.localeCompare(b.name, "ru"),
  );
}

export function compareFindings(a: FindingOut, b: FindingOut): number {
  return (
    SEVERITY_RANK[b.severity] - SEVERITY_RANK[a.severity] ||
    (b.cvss ?? -1) - (a.cvss ?? -1) ||
    compareIp(a.host, b.host) ||
    (a.port ?? 0) - (b.port ?? 0)
  );
}

export function compareIp(a: string, b: string): number {
  const pa = a.split(".").map(Number);
  const pb = b.split(".").map(Number);
  if (pa.length === 4 && pb.length === 4 && [...pa, ...pb].every((n) => Number.isInteger(n))) {
    for (let i = 0; i < 4; i++) if (pa[i] !== pb[i]) return pa[i] - pb[i];
    return 0;
  }
  return a.localeCompare(b);
}

export interface FindingFilter {
  severities: Severity[];
  modules: string[];
  statuses: (FindingStatus | "none")[];
  query: string;
  bduOnly: boolean;
}

export const emptyFilter = (): FindingFilter => ({ severities: [], modules: [], statuses: [], query: "", bduOnly: false });

export function applyFilter(findings: FindingOut[], f: FindingFilter): FindingOut[] {
  const q = f.query.trim().toLowerCase();
  return findings.filter((x) => {
    if (f.severities.length && !f.severities.includes(x.severity)) return false;
    if (f.modules.length && !f.modules.includes(x.module)) return false;
    if (f.statuses.length && !f.statuses.includes(x.status ?? "none")) return false;
    if (f.bduOnly && x.bdu_ids.length === 0) return false;
    if (q) {
      const hay = [x.title, x.host, x.vuln_id ?? "", ...x.cve_ids, ...x.bdu_ids, x.port ? `${x.host}:${x.port}` : ""]
        .join(" ")
        .toLowerCase();
      if (!hay.includes(q)) return false;
    }
    return true;
  });
}

/** Ступень тепловой карты (0 — пусто, 4 — максимум). */
export function heatLevel(n: number): number {
  if (n <= 0) return 0;
  if (n === 1) return 1;
  if (n <= 3) return 2;
  if (n <= 6) return 3;
  return 4;
}
