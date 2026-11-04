import { render, screen } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { App } from "../App";
import { setToken } from "../api/client";
import type { RunOut } from "../api/types";
import { AuthProvider } from "../auth/AuthContext";
import { ThemeProvider } from "../theme/ThemeContext";
import { OPERATOR, me, mockApi } from "../test/fixtures";
import { chipParts, etaText, remainingSeconds } from "../lib/runProgress";
import { RunProgressPanel } from "./RunProgressPanel";

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
  expect(chipParts(RUN)).toEqual({ main: "Прогон №131 идёт · 27 из 42 хостов · 82%", stage: "Уязвимости (учётка) (2/2)", percent: 82, eta: null });
  const one = { ...RUN, progress: { ...RUN.progress!, hosts_done: 0, hosts_total: 21, stage: "discovery", stage_index: 1, percent: 0 } };
  expect(chipParts(one).main).toBe("Прогон №131 идёт · 0 из 21 хоста · 0%");
  expect(chipParts({ ...RUN, progress: { ...RUN.progress!, stage: "saving" } }).stage).toBe("Сохранение результатов");
  expect(chipParts({ ...RUN, progress: null }).main).toBe("Прогон №131 идёт");
  expect(chipParts({ ...RUN, status: "pending", progress: null })).toEqual({ main: "Прогон №131 в очереди", stage: null, percent: null, eta: null });
});

it("таймер: оценка сервера идёт вниз между снимками", () => {
  const at = Date.parse(RUN.progress!.updated_at);
  const p = { ...RUN.progress!, eta_seconds: 720 };
  expect(remainingSeconds(p, at)).toBe(720);
  expect(remainingSeconds(p, at + 120_000)).toBe(600);
  expect(remainingSeconds(p, at + 900_000)).toBe(0);
  expect(remainingSeconds({ ...p, eta_seconds: null }, at)).toBeNull();
  expect(remainingSeconds({ ...p, stage: "saving" }, at)).toBeNull();
  expect(etaText(720)).toBe("≈ 12 мин");
  expect(etaText(4000)).toBe("≈ 1 ч 07 мин");
  expect(etaText(30)).toBe("< 1 мин");
  expect(etaText(0)).toBe("заканчивается");
  expect(chipParts({ ...RUN, progress: p }, at + 120_000).main).toBe("Прогон №131 идёт · 27 из 42 хостов · 82% · ≈ 10 мин");
});

it("страница прогона: этап, полоса и «Осталось ≈ …»", () => {
  const at = Date.parse(RUN.progress!.updated_at);
  render(<RunProgressPanel run={{ ...RUN, progress: { ...RUN.progress!, eta_seconds: 600 } }} now={at + 60_000} />);
  expect(screen.getByText("Этап 2 из 2: Уязвимости (учётка)")).toBeInTheDocument();
  expect(screen.getByText("Осталось ≈ 9 мин")).toBeInTheDocument();
  expect(screen.getByText("27 из 42 хостов на этапе")).toBeInTheDocument();
  expect(screen.getByText("идёт 6 мин")).toBeInTheDocument();
  expect(screen.getByLabelText("Выполнено 82%")).toBeInTheDocument();
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
