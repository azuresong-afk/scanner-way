import type { FindingOut, FindingsSummary, MeOut } from "../api/types";

export function finding(p: Partial<FindingOut> = {}): FindingOut {
  return {
    id: 1,
    dedup_key: "k1",
    module: "vuln",
    host: "10.0.0.1",
    port: 443,
    finding_type: "vuln",
    title: "Test finding",
    severity: "high",
    vuln_id: "CVE-2021-44228",
    cve_ids: ["CVE-2021-44228"],
    bdu_ids: ["BDU:2021-05969"],
    cvss: 9.8,
    evidence: null,
    status: "open",
    detected_at: "2026-10-28T09:00:00",
    false_positive: null,
    ...p,
  };
}

export function me(roles: string[], permissions: string[]): MeOut {
  return { id: 1, username: "tester", display_name: "Тест Тестов", is_active: true, roles, permissions };
}

export const OPERATOR = ["view_engagements", "run_scan", "view_report", "triage_findings"];
export const ADMIN = ["manage_users", "manage_engagements", "manage_nodes", "manage_allowlist", "view_engagements", "view_report", "view_audit"];

type Handler = (init: RequestInit | undefined, url: URL) => unknown | Response;

/** Подменяет fetch: ключ — "METHOD /path" (без префикса /api). */
export function mockApi(routes: Record<string, Handler | unknown>) {
  const calls: { method: string; path: string; init?: RequestInit }[] = [];
  const fn = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = new URL(String(input), "http://localhost");
    const path = url.pathname.replace(/^\/api/, "");
    const method = (init?.method ?? "GET").toUpperCase();
    calls.push({ method, path, init });
    const key = `${method} ${path}`;
    // Сводку прогона, если её не задали явно, считаем из подменённых находок —
    // так же, как сервер (ложные срабатывания не входят в счётчики).
    const sm = /^GET (\/runs\/\d+)\/findings\/summary$/.exec(key);
    if (sm && !(key in routes) && `GET ${sm[1]}/findings` in routes) {
      const list = routes[`GET ${sm[1]}/findings`] as FindingOut[];
      return new Response(JSON.stringify(summaryOf(list)), { status: 200, headers: { "Content-Type": "application/json" } });
    }
    if (!(key in routes)) return new Response(JSON.stringify({ detail: "not mocked" }), { status: 404 });
    const h = routes[key];
    const out = typeof h === "function" ? (h as Handler)(init, url) : h;
    if (out instanceof Response) return out;
    return new Response(JSON.stringify(out), { status: 200, headers: { "Content-Type": "application/json" } });
  });
  vi.stubGlobal("fetch", fn);
  return { fn, calls };
}

/** Серверная сводка прогона (/findings/summary), посчитанная по списку находок. */
export function summaryOf(list: FindingOut[]): FindingsSummary {
  const live = list.filter((f) => !f.false_positive);
  const counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 } as FindingsSummary["counts"];
  const hosts = new Map<string, FindingsSummary["counts"]>();
  for (const f of live) {
    counts[f.severity] += 1;
    const h = hosts.get(f.host) ?? { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
    h[f.severity] += 1;
    hosts.set(f.host, h);
  }
  const issues = live.filter((f) => f.severity !== "info");
  const vulns = issues.filter((f) => f.cve_ids.length > 0 || f.bdu_ids.length > 0 || f.module === "vuln");
  const statuses: Record<string, number> = {};
  for (const f of issues) if (f.status) statuses[f.status] = (statuses[f.status] ?? 0) + 1;
  return {
    counts,
    open: issues.length,
    hosts: hosts.size,
    new: statuses.new ?? 0,
    regression: statuses.regression ?? 0,
    fixed: 0,
    false_positives: list.length - live.length,
    bdu_share: vulns.length ? vulns.filter((f) => f.bdu_ids.length > 0).length / vulns.length : null,
    modules: [...new Set(list.map((f) => f.module))].sort(),
    statuses,
    previous_run_id: null,
    host_counts: [...hosts.entries()].map(([host, c]) => ({ host, counts: c, total: c.critical + c.high + c.medium + c.low })),
  };
}
