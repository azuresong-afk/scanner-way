import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { setToken } from "../api/client";
import type { ComplianceProfileDef, ComplianceSummary } from "../api/types";
import { mockApi } from "../test/fixtures";
import { CompliancePage } from "./CompliancePage";

let perms: string[] = [];
vi.mock("../auth/AuthContext", () => ({ useAuth: () => ({ has: (p: string) => perms.includes(p) }) }));
vi.mock("../auth/EngagementContext", () => ({
  useEngagement: () => ({ current: { id: 5, name: "Договор", client: "Ромашка" } }),
}));

afterEach(() => {
  setToken(null);
  vi.unstubAllGlobals();
});

const profile: ComplianceProfileDef = {
  id: "fstec-17",
  title: "Приказ ФСТЭК России №17 (ГИС)",
  short: "ФСТЭК №17",
  document: "Требования о защите информации в ГИС",
  url: "https://fstec.ru/",
  level_label: "Класс защищённости ГИС",
  levels: ["К1", "К2", "К3"],
  default_level: "К2",
  dynamic: null,
  groups: [],
  controls: [],
};

const summary: ComplianceSummary = {
  run_id: 7,
  has_results: true,
  profile: { ...profile },
  level: "К2",
  adapted: { excluded: [], added: [] },
  percent: 66.7,
  counts: { passed: 2, failed: 1, manual: 5, na: 3 },
  evaluated: 3,
  automated: 6,
  hosts: [{ host: "10.0.0.5", passed: 2, failed: 1, na: 3, percent: 66.7 }],
  groups: [],
  controls: [
    {
      id: "УПД.6",
      title: "Ограничение неуспешных попыток входа",
      group: "УПД",
      group_title: "Управление доступом",
      status: "passed",
      hosts: { passed: 1, failed: 0, manual: 0, na: 0 },
      added: false,
    },
    {
      id: "ИАФ.4",
      title: "Управление средствами аутентификации",
      group: "ИАФ",
      group_title: "Идентификация и аутентификация",
      status: "failed",
      hosts: { passed: 0, failed: 1, manual: 0, na: 0 },
      added: false,
      failed_hosts: [{ host: "10.0.0.5", checks: [{ id: "password_length", failures: [{ kind: "finding", title: "minlen < 8" }], more: 0 }] }],
      recommendations: [{ check: "password_length", title: "Минимальная длина пароля", remediation: "Задать minlen ≥ 8", doc: null }],
    },
  ],
  failures: [],
  manual: [{ id: "ИНЦ.1", title: "Определение ответственных", group: "ИНЦ", group_title: "Инциденты" }],
};

function renderPage(p: string[]) {
  perms = p;
  setToken("t");
  const api = mockApi({
    "GET /engagements/5/runs": [{ id: 7, engagement_id: 5, status: "done", modules: ["config_audit"], targets: [], name: "Аудит", schedule_id: null, created_at: null, started_at: null, finished_at: null, rate_profile: "gentle", credential_ids: [], cred_set_ids: [] }],
    "GET /compliance/profiles": [profile],
    "GET /engagements/5/compliance-profiles": [],
    "GET /engagements/5/asset-groups": [],
    "GET /runs/7/compliance": summary,
    "PUT /engagements/5/compliance-profiles/fstec-17": { profile: "fstec-17", level: "К2", excluded: [], added: [], in_report: true },
  });
  render(
    <MemoryRouter>
      <CompliancePage />
    </MemoryRouter>,
  );
  return api;
}

it("показывает процент, провалы с рекомендацией и меры «вручную»", async () => {
  renderPage(["view_report"]);
  expect((await screen.findAllByText("67%")).length).toBeGreaterThan(0);
  expect(screen.getByText("ИНЦ.1")).toBeInTheDocument();
  await userEvent.click(screen.getByRole("button", { name: /где и что сделать/ }));
  expect(screen.getByText("Задать minlen ≥ 8")).toBeInTheDocument();
  expect(screen.queryByRole("button", { name: "Включить в отчёт" })).toBeNull();
});

it("с правом управления включает профиль в отчёт", async () => {
  const api = renderPage(["view_report", "manage_engagements"]);
  await userEvent.click(await screen.findByRole("button", { name: "Включить в отчёт" }));
  await waitFor(() =>
    expect(api.calls.some((c) => c.method === "PUT" && c.path === "/engagements/5/compliance-profiles/fstec-17")).toBe(true),
  );
});
