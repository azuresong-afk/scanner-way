import type { FindingOut, MeOut } from "../api/types";

export function finding(p: Partial<FindingOut> = {}): FindingOut {
  return {
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
    ...p,
  };
}

export function me(roles: string[], permissions: string[]): MeOut {
  return { id: 1, username: "tester", display_name: "Тест Тестов", is_active: true, roles, permissions };
}

export const OPERATOR = ["view_engagements", "run_scan", "view_report"];
export const ADMIN = ["manage_users", "manage_engagements", "manage_allowlist", "view_engagements", "view_report", "view_audit"];

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
    if (!(key in routes)) return new Response(JSON.stringify({ detail: "not mocked" }), { status: 404 });
    const h = routes[key];
    const out = typeof h === "function" ? (h as Handler)(init, url) : h;
    if (out instanceof Response) return out;
    return new Response(JSON.stringify(out), { status: 200, headers: { "Content-Type": "application/json" } });
  });
  vi.stubGlobal("fetch", fn);
  return { fn, calls };
}
