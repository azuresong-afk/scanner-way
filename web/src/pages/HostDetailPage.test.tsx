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

it("«Что исправить» на карточке актива: по последним данным хоста, а с прогоном — по прогону", async () => {
  setToken("t");
  perms = ["view_report"];
  localStorage.removeItem("scanner.host.vulnView");
  const plan = (title: string) => ({
    total: 1,
    tasks: 1,
    hosts: 1,
    findings: 1,
    false_positives: 0,
    kinds: { package: 1 },
    os: { "Debian 12": 1 },
    severities: { critical: 1 },
    items: [
      {
        key: "k1",
        kind: "package",
        kind_label: "Обновление пакета",
        title,
        os: "Debian 12",
        os_family: "debian",
        manager: "dpkg",
        packages: ["openssl"],
        fixed_version: "3.0.15",
        software: null,
        steps: ["Обновите openssl."],
        commands: ["sudo apt-get update", "sudo apt-get install --only-upgrade -y openssl"],
        verify: [],
        reboot: false,
        details: null,
        details_source: null,
        severity: "critical",
        priority: null,
        cves: ["CVE-PKG-1"],
        bdu_ids: [],
        advisories: [],
        references: [],
        hosts: [{ host: "10.0.0.1", installed: "3.0.1", note: null, ports: [], findings: [{ id: 11, label: "CVE-PKG-1", severity: "critical" }] }],
        host_count: 1,
        finding_count: 1,
      },
    ],
  });
  const { calls } = mockApi({
    "GET /engagements/5/runs": [run(1, ["discovery", "auth_inventory"])],
    "GET /engagements/5/hosts": [{ host: "10.0.0.1", os_guess: null, run_ids: [1], services_run_id: 1, services: [], packages_run_id: null, package_count: 0 }],
    "GET /engagements/5/hosts/10.0.0.1/latest": {
      host: "10.0.0.1",
      run_ids: [1],
      checked_run_id: 1,
      module_runs: { auth_inventory: 1 },
      findings: [finding({ id: 11, host: "10.0.0.1", module: "auth_inventory", severity: "critical", vuln_id: "CVE-PKG-1", title: "openssl" })],
    },
    "GET /engagements/5/hosts/10.0.0.1/fixes": plan("Обновить openssl до 3.0.15"),
    "GET /runs/1/fixes": plan("Обновить openssl (прогон 1)"),
    "GET /runs/1/findings": [finding({ id: 11, host: "10.0.0.1", module: "auth_inventory", severity: "critical", vuln_id: "CVE-PKG-1", title: "openssl" })],
    "GET /runs/1/services": [],
    "GET /runs/1/packages": [],
    "GET /engagements/5/assets": [],
  });
  render(
    <MemoryRouter initialEntries={["/hosts/10.0.0.1"]}>
      <Routes>
        <Route path="/hosts/:host" element={<HostDetailPage />} />
      </Routes>
    </MemoryRouter>,
  );
  expect(await screen.findByRole("heading", { name: "Что исправить на хосте" })).toBeInTheDocument();
  expect(screen.getByRole("radio", { name: "Что исправить" })).toHaveAttribute("aria-checked", "true");
  expect(await screen.findByText("Обновить openssl до 3.0.15")).toBeInTheDocument();
  expect(screen.getByText(/sudo apt-get install --only-upgrade -y openssl/)).toBeInTheDocument();
  expect(screen.getByText(/Последние данные хоста/)).toBeInTheDocument();
  // фильтра по ОС на карточке одного хоста нет
  expect(screen.queryByRole("group", { name: "ОС хостов" })).toBeNull();

  // выбран прогон — план этого прогона только по этому хосту
  await userEvent.selectOptions(screen.getByRole("combobox", { name: "Прогон" }), "1");
  expect(await screen.findByText("Обновить openssl (прогон 1)")).toBeInTheDocument();
  const runCall = calls.find((c) => c.path === "/runs/1/fixes");
  expect(runCall).toBeDefined();

  // выбор вида запоминается
  await userEvent.click(screen.getByRole("radio", { name: "Списком" }));
  expect(localStorage.getItem("scanner.host.vulnView")).toBe("list");
  expect(screen.getByRole("heading", { name: "Уязвимости хоста" })).toBeInTheDocument();
});
