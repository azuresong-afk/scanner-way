import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { setToken } from "../api/client";
import type { AssetOut } from "../api/types";
import { ADMIN, mockApi } from "../test/fixtures";
import { AssetsPage } from "./AssetsPage";

let perms: string[] = [];
vi.mock("../auth/AuthContext", () => ({ useAuth: () => ({ has: (p: string) => perms.includes(p) }) }));
vi.mock("../auth/EngagementContext", () => ({
  useEngagement: () => ({ current: { id: 5, name: "Договор", client: "Ромашка" } }),
}));

afterEach(() => {
  setToken(null);
  vi.unstubAllGlobals();
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
  os_family_label: "Debian",
  last_run_id: 2,
  finding_counts: { high: 2 },
  findings_total: 2,
  ...p,
});

function renderPage(p: string[]) {
  perms = p;
  return render(<AssetsPage />);
}

const routes = (assets: AssetOut[]) => ({
  "GET /engagements/5/assets": assets,
  "GET /engagements/5/asset-groups": [{ id: 3, engagement_id: 5, name: "ДМЗ", asset_count: 1, created_at: null }],
  "GET /engagements/5/asset-tags": [{ tag: "prod", count: 1 }],
});

it("показывает владельца, критичность, теги и группы актива", async () => {
  setToken("t");
  mockApi(routes([asset()]));
  renderPage(ADMIN);
  const row = (await screen.findByText("10.0.0.1")).closest("tr")!;
  expect(within(row).getByText("Отдел ИТ")).toBeInTheDocument();
  expect(within(row).getByText("Высокая")).toBeInTheDocument();
  expect(within(row).getByText("prod")).toBeInTheDocument();
  expect(within(row).getByText("ДМЗ")).toBeInTheDocument();
});

it("без права manage_engagements кнопок изменения нет", async () => {
  setToken("t");
  mockApi(routes([asset()]));
  renderPage(["view_engagements"]);
  await screen.findByText("10.0.0.1");
  expect(screen.queryByRole("button", { name: /Добавить актив/ })).toBeNull();
  expect(screen.queryByRole("checkbox", { name: "Выбрать все" })).toBeNull();
});

it("массово добавляет тег выбранным активам", async () => {
  setToken("t");
  const { calls } = mockApi({
    ...routes([asset(), asset({ id: 2, address: "10.0.0.2" })]),
    "POST /engagements/5/assets/bulk": [],
  });
  renderPage(ADMIN);
  await screen.findByText("10.0.0.2");
  await userEvent.click(screen.getByRole("checkbox", { name: "Выбрать все" }));
  await userEvent.type(screen.getByLabelText("Добавить теги"), "dmz, БД");
  await userEvent.click(screen.getByRole("button", { name: /Применить/ }));
  await waitFor(() => expect(calls.some((c) => c.method === "POST" && c.path.endsWith("/assets/bulk"))).toBe(true));
  const call = calls.find((c) => c.path.endsWith("/assets/bulk"))!;
  expect(JSON.parse(String(call.init?.body))).toEqual({ asset_ids: [1, 2], add_tags: ["dmz", "БД"] });
});

it("фильтр по группе уходит в запрос", async () => {
  setToken("t");
  const { fn } = mockApi(routes([asset()]));
  renderPage(ADMIN);
  await screen.findByText("10.0.0.1");
  await userEvent.click(screen.getByRole("button", { name: /^ДМЗ/ }));
  await waitFor(() => expect(fn.mock.calls.some(([u]) => String(u).includes("/assets?group_id=3"))).toBe(true));
});
