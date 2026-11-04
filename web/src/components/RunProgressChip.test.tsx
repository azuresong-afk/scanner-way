import { render, screen } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { App } from "../App";
import { setToken } from "../api/client";
import type { RunOut } from "../api/types";
import { AuthProvider } from "../auth/AuthContext";
import { ThemeProvider } from "../theme/ThemeContext";
import { OPERATOR, me, mockApi } from "../test/fixtures";
import { chipParts } from "../lib/runProgress";

const ENG = { id: 1, name: "Периметр", client: "ООО Тест", contract_ref: "Д-1", created_by: 1, created_at: "2026-10-01T10:00:00" };

const RUN: RunOut = {
  id: 131, engagement_id: 1, modules: ["discovery", "auth_inventory"], rate_profile: "gentle", credential_ids: [], cred_set_ids: [],
  name: "Ночной", targets: ["10.0.0.0/26"], schedule_id: null, status: "running", started_by: 1,
  started_at: "2026-11-04T10:00:00Z", finished_at: null, created_at: "2026-11-04T09:59:00Z",
  progress: { stage: "auth_inventory", stage_index: 2, stages: 2, hosts_done: 27, hosts_total: 42, percent: 82, updated_at: "2026-11-04T10:05:00Z" },
};

afterEach(() => {
  setToken(null);
  vi.unstubAllGlobals();
  localStorage.clear();
});

it("текст плашки: номер, хосты с правильным склонением, процент, этап", () => {
  expect(chipParts(RUN)).toEqual({ main: "Прогон №131 идёт · 27 из 42 хостов · 82%", stage: "Уязвимости (учётка) (2/2)", percent: 82 });
  const one = { ...RUN, progress: { ...RUN.progress!, hosts_done: 0, hosts_total: 21, stage: "discovery", stage_index: 1, percent: 0 } };
  expect(chipParts(one).main).toBe("Прогон №131 идёт · 0 из 21 хоста · 0%");
  expect(chipParts({ ...RUN, progress: { ...RUN.progress!, stage: "saving" } }).stage).toBe("Сохранение результатов");
  expect(chipParts({ ...RUN, progress: null }).main).toBe("Прогон №131 идёт");
  expect(chipParts({ ...RUN, status: "pending", progress: null })).toEqual({ main: "Прогон №131 в очереди", stage: null, percent: null });
});

it("идущий прогон виден в шапке любой страницы и ведёт на прогон", async () => {
  setToken("t");
  const api = mockApi({
    "GET /me": me(["operator"], OPERATOR),
    "GET /engagements": [ENG],
    "GET /engagements/1/runs": [RUN, { ...RUN, id: 132, status: "pending", progress: null }],
    "GET /engagements/1/schedules": [],
  });
  render(
    <ThemeProvider>
      <MemoryRouter initialEntries={["/schedules"]} future={{ v7_startTransition: true, v7_relativeSplatPath: true }}>
        <AuthProvider>
          <App />
        </AuthProvider>
      </MemoryRouter>
    </ThemeProvider>,
  );
  const chip = await screen.findByRole("link", { name: /Прогон №131 идёт · 27 из 42 хостов · 82%/ });
  expect(chip).toHaveAttribute("href", "/runs/131");
  expect(chip).toHaveTextContent("+1");
  const call = api.calls.find((c) => c.path === "/engagements/1/runs");
  expect(call).toBeDefined();
});

it("без активных прогонов плашки нет", async () => {
  setToken("t");
  mockApi({ "GET /me": me(["operator"], OPERATOR), "GET /engagements": [ENG], "GET /engagements/1/runs": [], "GET /engagements/1/schedules": [] });
  render(
    <ThemeProvider>
      <MemoryRouter initialEntries={["/schedules"]} future={{ v7_startTransition: true, v7_relativeSplatPath: true }}>
        <AuthProvider>
          <App />
        </AuthProvider>
      </MemoryRouter>
    </ThemeProvider>,
  );
  await screen.findByRole("navigation", { name: "Основное меню" });
  expect(screen.queryByRole("link", { name: /Прогон №/ })).not.toBeInTheDocument();
});
