import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { AuthProvider } from "../auth/AuthContext";
import { setToken } from "../api/client";
import type { CoverageOut, FindingsSummary, RunOut } from "../api/types";
import { ADMIN, finding, me, mockApi, OPERATOR } from "../test/fixtures";
import { RunDetailPage } from "./RunDetailPage";

afterEach(() => {
  setToken(null);
  vi.unstubAllGlobals();
});

const run = (p: Partial<RunOut> = {}): RunOut => ({
  id: 7, engagement_id: 1, modules: ["discovery", "vuln", "auth_inventory"], rate_profile: "gentle", credential_ids: [1], cred_set_ids: [],
  name: "стенд", targets: ["10.0.0.5"], schedule_id: null, status: "partial", started_by: 2, started_at: "2026-11-03T10:00:00Z",
  finished_at: "2026-11-03T10:05:00Z", created_at: "2026-11-03T10:00:00Z",
  error_message: "Проверка неполная — 10.0.0.5: Уязвимости по учётной записи — таймаут SSH", retry_of: null, warnings: [], ...p,
});

const cov = (p: Partial<CoverageOut> = {}): CoverageOut => ({
  scan_run_id: 7, status: "partial", legacy: false,
  summary: { hosts: 1, hosts_checked: 0, hosts_partial: 1, hosts_unreachable: 0, hosts_not_checked: 0, gaps: 1, auth_gaps: 1,
    counts: { completed: 2, timeout: 1, not_applicable: 0, skipped: 0, unreachable: 0, no_credentials: 0, error: 0 } },
  hosts: [{ host: "10.0.0.5", status: "partial", modules: {
    discovery: { status: "completed", label: "выполнено", reason: null },
    auth_inventory: { status: "timeout", label: "таймаут", reason: "таймаут SSH (попыток: 2)" } } }],
  entries: [
    { host: "10.0.0.5", module: "discovery", status: "completed", label: "выполнено", reason: null },
    { host: "10.0.0.5", module: "auth_inventory", status: "timeout", label: "таймаут", reason: "таймаут SSH (попыток: 2)" },
  ],
  ...p,
});

function renderPage(perms: string[], r: RunOut, extra: Record<string, unknown> = {}) {
  setToken("t");
  const api = mockApi({
    "GET /me": me(["operator"], perms),
    "GET /runs/7": r,
    "GET /runs/7/findings": [],
    "GET /runs/7/services": [],
    "GET /runs/7/coverage": cov(),
    "GET /engagements/1/runs": [r],
    "POST /feeds/advisories/releases": { source: "advisories", running: true, message: null },
    ...extra,
  });
  render(
    <MemoryRouter initialEntries={["/runs/7"]}>
      <AuthProvider>
        <Routes>
          <Route path="/runs/:id" element={<RunDetailPage />} />
        </Routes>
      </AuthProvider>
    </MemoryRouter>,
  );
  return api;
}

it("SSH timeout: «Частично», пробел покрытия и находка по баннеру «не подтверждено»", async () => {
  renderPage(OPERATOR, run(), {
    "GET /runs/7/findings": [finding({ host: "10.0.0.5", confidence: "low", source: "banner", title: "OpenSSH CVE-2025-26465" })],
  });
  expect(await screen.findByText("Частично")).toBeInTheDocument();
  expect(screen.getByText(/Проверка выполнена не полностью/)).toBeInTheDocument();
  expect(await screen.findByText("не подтверждено")).toBeInTheDocument();
  await userEvent.click(screen.getByRole("tab", { name: /Полнота проверки/ }));
  expect((await screen.findAllByText("Таймаут")).length).toBeGreaterThan(0);
  expect(screen.getByText(/попыток: 2/)).toBeInTheDocument();
});

it("выключенный хост: не «уязвимостей не найдено», а «проверка не выполнена»", async () => {
  const summary: Partial<FindingsSummary> = {
    counts: { critical: 0, high: 0, medium: 0, low: 0, info: 0 }, open: 0, hosts: 0, new: 0, regression: 0, fixed: 0, false_positives: 0,
    bdu_share: null, modules: [], statuses: {}, previous_run_id: null, host_counts: [],
    coverage: { hosts: 1, hosts_checked: 0, hosts_partial: 0, hosts_unreachable: 1, hosts_not_checked: 0, gaps: 2, auth_gaps: 0,
      counts: { completed: 0, timeout: 0, not_applicable: 0, skipped: 0, unreachable: 2, no_credentials: 0, error: 0 } },
  };
  renderPage(OPERATOR, run({ status: "failed", error_message: "Хост недоступен, проверка не выполнена: 10.0.0.7" }), {
    "GET /runs/7/findings/summary": summary,
  });
  expect(await screen.findByText(/Хост недоступен, проверка не выполнена: 10.0.0.7/)).toBeInTheDocument();
  expect(screen.getAllByText("Хост недоступен, проверка не выполнена").length).toBeGreaterThan(0);
  expect(screen.queryByText("Уязвимостей не найдено")).not.toBeInTheDocument();
});

it("«Бэкпорты не учтены» — загрузка бюллетеней выпуска одним действием", async () => {
  const api = renderPage(ADMIN, run({
    warnings: [{ kind: "advisories_missing", family: "debian", release: "trixie", os: "Debian 13", hosts: ["10.0.0.5"], loadable: true,
      message: "Бэкпорты не учтены: нет бюллетеней debian:trixie (хосты: 10.0.0.5)" }],
  }));
  const btn = await screen.findByRole("button", { name: /Загрузить бюллетени debian:trixie/ });
  await userEvent.click(btn);
  await waitFor(() => expect(api.calls.some((c) => c.method === "POST" && c.path === "/feeds/advisories/releases")).toBe(true));
  const call = api.calls.find((c) => c.path === "/feeds/advisories/releases")!;
  expect(JSON.parse(String(call.init!.body))).toEqual({ family: "debian", release: "trixie" });
  expect(await screen.findByText(/Загрузка запущена/)).toBeInTheDocument();
});

it("сравнение: базовый прогон назван, несопоставимость и непроверенные видны", async () => {
  const summary = {
    counts: { critical: 0, high: 0, medium: 0, low: 0, info: 0 }, open: 0, hosts: 1, new: 0, regression: 0, fixed: 0, false_positives: 0,
    bdu_share: null, modules: [], statuses: {}, previous_run_id: 5, host_counts: [], unverified: 3,
    comparability: { level: "partial", common_hosts: ["10.0.0.5"], common_modules: ["discovery"], only_baseline_hosts: ["10.0.0.6"],
      only_current_hosts: [], only_baseline_modules: ["auth_inventory"], only_current_modules: [],
      warnings: ["Хосты, не проверенные в текущем прогоне (1): их находки не считаются исправленными."] },
  };
  renderPage(OPERATOR, run({ status: "done", error_message: null }), { "GET /runs/7/findings/summary": summary });
  const note = (await screen.findByText(/Сравнение с базовым прогоном/)).closest(".alert")!;
  expect(within(note as HTMLElement).getByRole("link", { name: "№5" })).toBeInTheDocument();
  expect(note).toHaveTextContent("сопоставим частично");
  expect(note).toHaveTextContent("не считаются исправленными");
  expect(note).toHaveTextContent("Не проверено в этом прогоне: 3");
});
