import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { setToken } from "../api/client";
import type { OfflineJobOut, RunOut } from "../api/types";
import { AuthProvider } from "../auth/AuthContext";
import { RunDetailPage } from "../pages/RunDetailPage";
import { me, mockApi, OPERATOR } from "../test/fixtures";

afterEach(() => {
  setToken(null);
  vi.unstubAllGlobals();
});

const run = (p: Partial<RunOut> = {}): RunOut => ({
  id: 42, engagement_id: 1, modules: ["discovery", "vuln"], rate_profile: "gentle", credential_ids: [], cred_set_ids: [],
  name: "АСУ ТП", targets: ["10.10.0.0/24"], schedule_id: null, status: "pending", started_by: 2, started_at: null,
  finished_at: null, created_at: "2026-11-06T10:00:00Z", node_id: 3, node_name: "АСУ-ТП-1", node_mode: "offline", ...p,
});

const job = (p: Partial<OfflineJobOut> = {}): OfflineJobOut => ({
  job_id: "7d5a63b8-0000-4000-8000-000000000001", run_id: 42, node_id: 3, node_name: "АСУ-ТП-1", status: "exported",
  status_label: "Ожидает результат", node_fingerprint: "2d7e-8564-b674-62a0-313f-0709-3296-ad87", job_sha256: "ab".repeat(32),
  exported_by: "user:op", exported_at: "2026-11-06T10:05:00Z", expires_at: "2026-11-20T10:05:00Z", imported_by: null,
  imported_at: null, result_sha256: null, result_summary: null, ...p,
});

function renderPage(r: RunOut, routes: Record<string, unknown>) {
  setToken("t");
  const api = mockApi({ "GET /me": me(["operator"], OPERATOR), "GET /runs/42": r, ...routes });
  render(
    <MemoryRouter initialEntries={["/runs/42"]}>
      <AuthProvider>
        <Routes>
          <Route path="/runs/:id" element={<RunDetailPage />} />
        </Routes>
      </AuthProvider>
    </MemoryRouter>,
  );
  return api;
}

it("прогон в очереди на автономном узле: «Выгрузить задание» вместо «Идёт сканирование»", async () => {
  vi.stubGlobal("URL", Object.assign(URL, { createObjectURL: () => "blob:x", revokeObjectURL: () => undefined }));
  const api = renderPage(run(), {
    "GET /runs/42/offline": new Response(JSON.stringify({ detail: "offline job not found" }), { status: 404 }),
    "POST /runs/42/offline/export": () =>
      new Response("{}", { status: 200, headers: { "Content-Disposition": "attachment; filename*=UTF-8''job-%D0%90-run42.scnjob" } }),
  });
  expect(await screen.findByText(/Автономный узел «АСУ-ТП-1»/)).toBeInTheDocument();
  expect(screen.queryByText("Прогон в очереди")).not.toBeInTheDocument();
  await userEvent.selectOptions(screen.getByLabelText("Срок действия задания"), "30");
  await userEvent.click(screen.getByRole("button", { name: /Выгрузить задание/ }));
  await waitFor(() => expect(api.calls.some((c) => c.method === "POST" && c.path === "/runs/42/offline/export")).toBe(true));
  const call = api.fn.mock.calls.find(([u]) => String(u).includes("/offline/export"));
  expect(String(call![0])).toContain("valid_days=30");
});

it("задание выгружено: срок, ключ узла, загрузка результата с предпросмотром", async () => {
  const api = renderPage(run({ status: "running", started_at: "2026-11-06T10:05:00Z" }), {
    "GET /runs/42/offline": job(),
    "POST /offline/results/preview": {
      job_id: job().job_id, run_id: 42, run_name: "АСУ ТП", engagement: "Д-7/2026", node_name: "АСУ-ТП-1",
      started_at: "2026-11-07T08:00:00Z", finished_at: "2026-11-07T09:10:00Z", hosts: 12, findings: 37, reference_as_of: "2026-11-05",
    },
    "POST /offline/results": { run_id: 42, status: "done", job_id: job().job_id, node: "АСУ-ТП-1", findings: 37, hosts: 12, started_at: null, finished_at: null },
  });
  expect(await screen.findByText("Ожидает результат")).toBeInTheDocument();
  expect(screen.getByText("2d7e-8564-b674-62a0-313f-0709-3296-ad87")).toBeInTheDocument();
  expect(screen.getByRole("button", { name: /Скачать задание ещё раз/ })).toBeInTheDocument();

  const file = new File(["{}"], "result-АСУ-ТП-1-run42.scnres");
  const input = document.querySelector('input[type="file"][accept=".scnres"]') as HTMLInputElement;
  await userEvent.upload(input, file);
  expect(await screen.findByText("Д-7/2026")).toBeInTheDocument();
  expect(screen.getByText(/12 хостов, 37 находок/)).toBeInTheDocument();
  expect(screen.getByText("на 2026-11-05")).toBeInTheDocument();
  await userEvent.click(screen.getByRole("button", { name: "Загрузить" }));
  expect(await screen.findByText(/Результат загружен: прогон №42, 37 находок/)).toBeInTheDocument();
  const post = api.calls.find((c) => c.method === "POST" && c.path === "/offline/results");
  expect(new Headers(post!.init!.headers).get("Content-Type")).toBe("application/octet-stream");
});

it("отмена задания — через подтверждение", async () => {
  const api = renderPage(run({ status: "running" }), {
    "GET /runs/42/offline": job(),
    "POST /runs/42/offline/cancel": { run_id: 42, status: "cancelled" },
  });
  await userEvent.click(await screen.findByRole("button", { name: /Отменить задание/ }));
  expect(screen.getByText(/результат по этому заданию центр больше не примет/)).toBeInTheDocument();
  const buttons = screen.getAllByRole("button", { name: "Отменить задание" });
  await userEvent.click(buttons[buttons.length - 1]);
  await waitFor(() => expect(api.calls.some((c) => c.path === "/runs/42/offline/cancel")).toBe(true));
});
