import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { AuthProvider } from "../auth/AuthContext";
import { setToken } from "../api/client";
import type { FeedOut } from "../api/types";
import { ADMIN, me, mockApi } from "../test/fixtures";
import { FeedsPage } from "./FeedsPage";

afterEach(() => {
  setToken(null);
  vi.unstubAllGlobals();
});

const feed = (p: Partial<FeedOut> = {}): FeedOut => ({
  source: "nvd",
  title: "NVD (CVE)",
  description: "Инкрементально",
  kind: "daily",
  time_of_day: "03:00",
  weekdays: [],
  month_day: null,
  timezone: "Europe/Moscow",
  enabled: true,
  next_run_at: "2026-10-31T00:00:00Z",
  last_run_at: "2026-10-30T00:00:00Z",
  last_success_at: "2026-10-30T00:00:00Z",
  last_result: "ok",
  last_count: 1234,
  message: "Обновлено CVE: 1234",
  running: false,
  ...p,
});

function renderPage(permissions: string[], feeds: FeedOut[]) {
  setToken("t");
  const api = mockApi({
    "GET /me": me(["admin"], permissions),
    "GET /feeds": feeds,
    "POST /feeds/nvd/run": feed({ running: true }),
  });
  render(
    <MemoryRouter>
      <AuthProvider>
        <FeedsPage />
      </AuthProvider>
    </MemoryRouter>,
  );
  return api;
}

it("показывает статус и запускает обновление вручную", async () => {
  const api = renderPage(ADMIN, [feed()]);
  expect(await screen.findByText("NVD (CVE)")).toBeInTheDocument();
  expect(screen.getByText("Обновлено CVE: 1234")).toBeInTheDocument();
  await userEvent.click(screen.getByRole("button", { name: /Обновить сейчас/ }));
  await waitFor(() => expect(api.calls.some((c) => c.method === "POST" && c.path === "/feeds/nvd/run")).toBe(true));
});

it("без права управления кнопок нет, ошибка последней загрузки видна", async () => {
  renderPage(["view_engagements"], [feed({ last_result: "error", message: "NVD недоступен" })]);
  expect(await screen.findByText("NVD недоступен")).toBeInTheDocument();
  expect(screen.queryByRole("button", { name: /Обновить сейчас/ })).toBeNull();
});

it("долгая загрузка: этап, загружено из всего, %, скорость, осталось; прошлая ошибка — как прошлая", async () => {
  setToken("t");
  mockApi({
    "GET /me": me(["admin"], ADMIN),
    "GET /feeds": [
      feed({
        running: true, last_result: "error", message: "NVD: ConnectTimeout", message_is_previous: true,
        progress: { stage: "Полная загрузка NVD через API", done: 20000, total: 300000, percent: 6.7, rate_per_sec: 200, eta_seconds: 1400,
          elapsed_seconds: 100, started_at: "2026-11-03T12:00:00Z", updated_at: "2026-11-03T12:01:40Z" },
      }),
    ],
    "GET /feeds/readiness": {
      ready: false, releases: [],
      sources: [
        { source: "bdu", title: "БДУ ФСТЭК", purpose: "привязка к БДУ", required: true, state: "missing", records: 0, progress: null, auto_update: false,
          last_success_at: null, last_result: null, message: null, message_is_previous: false, last_error_at: null,
          hint: "Загрузите файл vullist.xlsx с bdu.fstec.ru" },
      ],
      missing_releases: [{ family: "debian", release: "trixie", os: "Debian 13", hosts: ["10.0.0.5"], runs: [7] }],
    },
  });
  render(
    <MemoryRouter>
      <AuthProvider>
        <FeedsPage />
      </AuthProvider>
    </MemoryRouter>,
  );
  expect(await screen.findByText("Полная загрузка NVD через API")).toBeInTheDocument();
  const line = screen.getByText(/6.7%/);
  expect(line).toHaveTextContent(/20\s000 из 300\s000/);
  expect(line).toHaveTextContent("200/с");
  expect(line).toHaveTextContent("осталось ~23 мин");
  expect(screen.getByText(/Прошлая попытка: NVD: ConnectTimeout/)).toBeInTheDocument();
  expect(await screen.findByText("Готовность справочников")).toBeInTheDocument();
  expect(screen.getByText("Не загружен")).toBeInTheDocument();
  expect(screen.getByText(/Загрузить файл БДУ/)).toBeInTheDocument();
  expect(screen.getByRole("button", { name: /Загрузить debian:trixie/ })).toBeInTheDocument();
});
