import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { setToken } from "../api/client";
import type { AssetOut, InventoryHostOut, RunOut } from "../api/types";
import { ADMIN, finding, mockApi, OPERATOR } from "../test/fixtures";
import { HostsPage } from "./HostsPage";

let perms: string[] = [];
vi.mock("../auth/AuthContext", () => ({ useAuth: () => ({ has: (p: string) => perms.includes(p) }) }));
vi.mock("../auth/EngagementContext", () => ({
  useEngagement: () => ({ current: { id: 5, name: "Договор", client: "Ромашка" } }),
}));

afterEach(() => {
  setToken(null);
  vi.unstubAllGlobals();
});

const run: RunOut = {
  id: 2,
  engagement_id: 5,
  modules: ["discovery", "vuln"],
  rate_profile: "normal",
  credential_ids: [],
  cred_set_ids: [],
  name: "Прогон",
  targets: ["10.0.0.0/24"],
  schedule_id: null,
  status: "done",
  started_by: 1,
  started_at: null,
  finished_at: null,
  created_at: null,
};

const inv = (host: string, p: Partial<InventoryHostOut> = {}): InventoryHostOut => ({
  host,
  os_guess: null,
  os_family: "debian",
  os_family_label: "Debian",
  run_ids: [2],
  services_run_id: 2,
  packages_run_id: null,
  package_count: 0,
  services: [{ host, port: 22, protocol: "tcp", service: "ssh", product: "OpenSSH", version: "9.2", cpe: null }],
  ...p,
});

const asset = (p: Partial<AssetOut> = {}): AssetOut => ({
  id: 1,
  engagement_id: 5,
  address: "10.0.0.1",
  hostname: "srv-1",
  owner: "Отдел ИТ",
  criticality: "high",
  notes: null,
  tags: ["prod"],
  groups: [{ id: 3, name: "ДМЗ" }],
  created_at: null,
  os_guess: null,
  os_family: null,
  os_family_label: null,
  last_run_id: 2,
  finding_counts: {},
  findings_total: 0,
  ...p,
});

const routes = (assets: AssetOut[], extra: Record<string, unknown> = {}) => ({
  "GET /engagements/5/runs": [run],
  "GET /engagements/5/hosts": [inv("10.0.0.1"), inv("10.0.0.2")],
  "GET /runs/2/findings": [finding({ host: "10.0.0.1", severity: "critical" })],
  "GET /engagements/5/assets": assets,
  "GET /engagements/5/asset-groups": [{ id: 3, engagement_id: 5, name: "ДМЗ", asset_count: 1, created_at: null }],
  "GET /engagements/5/asset-tags": [{ tag: "prod", count: 1 }],
  ...extra,
});

function renderPage(p: string[]) {
  perms = p;
  return render(
    <MemoryRouter>
      <HostsPage />
    </MemoryRouter>,
  );
}

const rowOf = async (host: string) => (await screen.findByText(host)).closest("tr")!;

it("в одной строке — инвентарь, уязвимости прогона и учётные атрибуты хоста", async () => {
  setToken("t");
  mockApi(routes([asset(), asset({ id: 9, address: "10.0.0.50", hostname: null, owner: "Бухгалтерия", last_run_id: null, groups: [], tags: [] })]));
  renderPage([...ADMIN]);
  const row = await rowOf("10.0.0.1");
  expect(within(row).getByText("Debian")).toBeInTheDocument();
  expect(within(row).getByText(/OpenSSH 9\.2/)).toBeInTheDocument();
  expect(within(row).getByText("Высокая")).toBeInTheDocument();
  expect(within(row).getByText("Отдел ИТ")).toBeInTheDocument();
  expect(within(row).getByText("ДМЗ")).toBeInTheDocument();
  expect(within(row).getByText("#prod")).toBeInTheDocument();
  expect(within(row).getByText(/^Крит/)).toBeInTheDocument();
  // хост без учётной записи — критичность по умолчанию
  expect(within(await rowOf("10.0.0.2")).getByTitle(/По умолчанию/)).toHaveTextContent("Средняя");
  // заведённый вручную и не сканированный хост тоже в списке
  expect(within(await rowOf("10.0.0.50")).getByText("не сканировался")).toBeInTheDocument();
  expect(screen.getByRole("heading", { level: 2 })).toHaveTextContent("3 актива");
});

it("фильтр по группе оставляет только её хосты", async () => {
  setToken("t");
  mockApi(routes([asset()]));
  renderPage([...ADMIN]);
  await screen.findByText("10.0.0.2");
  await userEvent.click(screen.getByRole("button", { name: /^ДМЗ/ }));
  expect(screen.queryByText("10.0.0.2")).toBeNull();
  expect(screen.getByText("10.0.0.1")).toBeInTheDocument();
});

it("массовое действие заводит учёт для хостов без него и применяет изменения ко всем", async () => {
  setToken("t");
  const { calls } = mockApi(
    routes([asset()], {
      "POST /engagements/5/assets": asset({ id: 7, address: "10.0.0.2" }),
      "POST /engagements/5/assets/bulk": [],
    }),
  );
  renderPage([...ADMIN]);
  await screen.findByText("10.0.0.2");
  await userEvent.click(screen.getByRole("checkbox", { name: "Выбрать все" }));
  await userEvent.type(screen.getByLabelText("Добавить теги"), "dmz");
  await userEvent.click(screen.getByRole("button", { name: /Применить/ }));
  await waitFor(() => expect(calls.some((c) => c.path.endsWith("/assets/bulk"))).toBe(true));
  const created = calls.find((c) => c.method === "POST" && c.path === "/engagements/5/assets")!;
  expect(JSON.parse(String(created.init?.body))).toEqual({ address: "10.0.0.2" });
  const bulk = calls.find((c) => c.path.endsWith("/assets/bulk"))!;
  expect(JSON.parse(String(bulk.init?.body))).toEqual({ asset_ids: [1, 7], add_tags: ["dmz"] });
});

it("без права manage_engagements атрибуты видны, но изменять нельзя", async () => {
  setToken("t");
  mockApi(routes([asset()]));
  renderPage(OPERATOR);
  await screen.findByText("Отдел ИТ");
  expect(screen.queryByRole("button", { name: /Добавить актив/ })).toBeNull();
  expect(screen.queryByRole("checkbox", { name: "Выбрать все" })).toBeNull();
  expect(screen.queryByRole("button", { name: /Изменить 10\.0\.0\.1/ })).toBeNull();
});
