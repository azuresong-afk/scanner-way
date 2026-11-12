import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { AuthProvider } from "../auth/AuthContext";
import { setToken } from "../api/client";
import type { RunOut } from "../api/types";
import { ADMIN, me, mockApi, OPERATOR } from "../test/fixtures";
import { RunDetailPage } from "./RunDetailPage";

afterEach(() => {
  setToken(null);
  vi.unstubAllGlobals();
});

const run = (p: Partial<RunOut> = {}): RunOut => ({
  id: 7,
  engagement_id: 1,
  modules: ["discovery"],
  rate_profile: "gentle",
  credential_ids: [],
  cred_set_ids: [],
  name: "ночной",
  targets: ["10.0.0.1"],
  schedule_id: null,
  status: "interrupted",
  started_by: 2,
  started_at: "2026-11-02T10:00:00Z",
  finished_at: "2026-11-02T10:05:00Z",
  created_at: "2026-11-02T10:00:00Z",
  error_message: "Прогон прерван: служба сканера была остановлена или перезапущена во время выполнения.",
  retry_of: null,
  ...p,
});

function renderPage(permissions: string[], r: RunOut) {
  setToken("t");
  const api = mockApi({
    "GET /me": me(["operator"], permissions),
    "GET /runs/7": r,
    "GET /runs/7/findings": [],
    "GET /runs/7/services": [],
    "GET /engagements/1/runs": [r],
    "POST /runs/7/retry": { ...run({ id: 8, status: "pending", error_message: null, retry_of: 7 }), accepted_targets: 1, denied_targets: [] },
    "GET /runs/8": run({ id: 8, status: "pending", error_message: null, retry_of: 7 }),
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

it("прерванный прогон: статус, причина и «Повторить»", async () => {
  const api = renderPage(OPERATOR, run());
  expect(await screen.findByText("Прерван")).toBeInTheDocument();
  expect(screen.getByRole("alert")).toHaveTextContent("служба сканера была остановлена");
  await userEvent.click(screen.getByRole("button", { name: /Повторить/ }));
  await waitFor(() => expect(api.calls.some((c) => c.method === "POST" && c.path === "/runs/7/retry")).toBe(true));
  expect(await screen.findByText(/повтор/)).toBeInTheDocument();
});

it("успешный прогон тоже можно повторить", async () => {
  const api = renderPage(OPERATOR, run({ status: "done", error_message: null }));
  await userEvent.click(await screen.findByRole("button", { name: /Повторить/ }));
  await waitFor(() => expect(api.calls.some((c) => c.method === "POST" && c.path === "/runs/7/retry")).toBe(true));
});

it("у идущего прогона «Повторить» нет", async () => {
  renderPage(OPERATOR, run({ status: "running", error_message: null }));
  expect(await screen.findByRole("button", { name: /Остановить/ })).toBeInTheDocument();
  expect(screen.queryByRole("button", { name: /Повторить/ })).not.toBeInTheDocument();
});

it("причина ошибки видна, без права запуска кнопки нет", async () => {
  renderPage(ADMIN, run({ status: "failed", error_message: "Прогон завершён с ошибками — модуль vuln: timeout" }));
  expect(await screen.findByText(/модуль vuln: timeout/)).toBeInTheDocument();
  expect(screen.queryByRole("button", { name: /Повторить/ })).not.toBeInTheDocument();
});
