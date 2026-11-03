import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter, Route, Routes, useLocation } from "react-router-dom";
import { setToken } from "../api/client";
import type { RunOut } from "../api/types";
import { finding, mockApi } from "../test/fixtures";
import { HostDetailPage } from "./HostDetailPage";

let perms: string[] = [];
vi.mock("../auth/AuthContext", () => ({ useAuth: () => ({ has: (p: string) => perms.includes(p) }) }));
vi.mock("../auth/EngagementContext", () => ({
  useEngagement: () => ({ current: { id: 5, name: "Договор", client: null } }),
}));

afterEach(() => {
  setToken(null);
  vi.unstubAllGlobals();
});

const run = (id: number, modules: string[]): RunOut => ({
  id,
  engagement_id: 5,
  modules,
  rate_profile: "normal",
  credential_ids: [],
  cred_set_ids: [],
  name: `Прогон ${id}`,
  targets: ["10.0.0.1"],
  schedule_id: null,
  status: id === 3 ? "partial" : "done",
  started_by: 1,
  started_at: null,
  finished_at: null,
  created_at: null,
});

function Where() {
  return <span data-testid="where">{useLocation().search}</span>;
}

it("без выбора прогона — последние известные уязвимости хоста из нескольких прогонов", async () => {
  setToken("t");
  perms = ["view_report"];
  const ssh = { host: "10.0.0.1", port: 22, protocol: "tcp", service: "ssh", product: "OpenSSH", version: "9.2", cpe: null };
  mockApi({
    "GET /engagements/5/runs": [run(1, ["discovery", "auth_inventory"]), run(3, ["discovery", "auth_inventory"])],
    "GET /engagements/5/hosts": [
      { host: "10.0.0.1", os_guess: null, run_ids: [1, 3], services_run_id: 3, services: [ssh], packages_run_id: 1, package_count: 1 },
    ],
    // №3: сеть проверена, SSH — таймаут; пакетные уязвимости — из №1
    "GET /engagements/5/hosts/10.0.0.1/latest": {
      host: "10.0.0.1",
      run_ids: [1, 3],
      checked_run_id: 3,
      module_runs: { discovery: 3, auth_inventory: 1 },
      findings: [
        finding({ id: 11, host: "10.0.0.1", module: "auth_inventory", severity: "critical", vuln_id: "CVE-PKG-1", title: "openssl" }),
        finding({ id: 12, host: "10.0.0.1", module: "auth_inventory", severity: "high", vuln_id: "CVE-PKG-2", title: "sudo" }),
      ],
    },
    "GET /runs/1/packages": [{ host: "10.0.0.1", manager: "dpkg", name: "openssl", version: "3.0.1", arch: "amd64" }],
    "GET /runs/3/findings": [],
    "GET /runs/3/services": [ssh],
    "GET /runs/3/packages": [],
  });
  render(
    <MemoryRouter initialEntries={["/hosts/10.0.0.1"]}>
      <Routes>
        <Route
          path="/hosts/:host"
          element={
            <>
              <HostDetailPage />
              <Where />
            </>
          }
        />
      </Routes>
    </MemoryRouter>,
  );
  const kpi = (await screen.findAllByText("Уязвимостей"))[0];
  expect(kpi.parentElement).toHaveTextContent("2");
  expect(screen.getByRole("combobox", { name: "Прогон" })).toHaveValue("");
  const sources = screen.getByText(/собраны из нескольких прогонов/);
  expect(within(sources).getByRole("button", { name: "прогон №1" })).toBeInTheDocument();
  expect(within(sources).getByRole("button", { name: "прогон №3" })).toBeInTheDocument();
  expect(screen.getByText(/Установленные пакеты \(1\)/)).toBeInTheDocument();

  // выбор прогона №3 — только его данные: SSH там не отработал, уязвимостей нет
  await userEvent.click(within(sources).getByRole("button", { name: "прогон №3" }));
  expect(screen.getByTestId("where")).toHaveTextContent("?run=3");
  expect(screen.getByRole("combobox", { name: "Прогон" })).toHaveValue("3");
  expect(screen.queryByText(/собраны из нескольких прогонов/)).toBeNull();
  expect((await screen.findAllByText("Уязвимостей"))[0].parentElement).toHaveTextContent("0");
});

it("хост, который ещё не проверялся", async () => {
  setToken("t");
  perms = ["view_report"];
  mockApi({
    "GET /engagements/5/runs": [run(1, ["discovery"])],
    "GET /engagements/5/hosts": [],
    "GET /engagements/5/hosts/10.0.0.9/latest": { host: "10.0.0.9", run_ids: [], checked_run_id: null, module_runs: {}, findings: [] },
  });
  render(
    <MemoryRouter initialEntries={["/hosts/10.0.0.9"]}>
      <Routes>
        <Route path="/hosts/:host" element={<HostDetailPage />} />
      </Routes>
    </MemoryRouter>,
  );
  expect(await screen.findByText("Хост ещё не проверялся")).toBeInTheDocument();
});
