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
