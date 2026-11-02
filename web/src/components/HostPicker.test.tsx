import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { setToken } from "../api/client";
import type { AssetOut, InventoryHostOut } from "../api/types";
import { mockApi } from "../test/fixtures";
import { HostPicker } from "./HostPicker";

afterEach(() => {
  setToken(null);
  vi.unstubAllGlobals();
});

const inv = (host: string, family = "debian", label = "Debian"): InventoryHostOut => ({
  host,
  os_guess: null,
  os_family: family,
  os_family_label: label,
  run_ids: [2],
  services_run_id: 2,
  packages_run_id: null,
  package_count: 0,
  services: [],
});

const asset = (id: number, address: string, p: Partial<AssetOut> = {}): AssetOut => ({
  id,
  engagement_id: 5,
  address,
  hostname: null,
  owner: null,
  criticality: "medium",
  notes: null,
  tags: [],
  groups: [],
  created_at: null,
  os_guess: null,
  os_family: null,
  os_family_label: null,
  last_run_id: null,
  finding_counts: {},
  findings_total: 0,
  ...p,
});

function setup(mode: "run" | "allowlist", allowlist: string[]) {
  setToken("t");
  mockApi({
    "GET /engagements/5/hosts": [inv("10.0.0.1"), inv("10.0.0.2"), inv("10.0.0.3", "windows", "Windows"), inv("10.0.9.9")],
    "GET /engagements/5/assets": [
      asset(1, "10.0.0.1", { hostname: "web-1", groups: [{ id: 3, name: "ДМЗ" }], tags: ["prod"], criticality: "high" }),
      asset(2, "10.0.0.2", { groups: [{ id: 3, name: "ДМЗ" }] }),
      asset(3, "10.0.0.4", { hostname: "db-1", tags: ["prod"], criticality: "critical" }),
    ],
    "GET /engagements/5/asset-groups": [{ id: 3, engagement_id: 5, name: "ДМЗ", asset_count: 2, created_at: null }],
    "GET /engagements/5/asset-tags": [{ tag: "prod", count: 2 }],
  });
  const onPick = vi.fn();
  render(<HostPicker engagementId={5} allowlist={allowlist} mode={mode} onClose={() => {}} onPick={onPick} />);
  return onPick;
}

it("цели прогона: хосты вне allowlist выбрать нельзя, группа выбирается целиком", async () => {
  const onPick = setup("run", ["10.0.0.0/24"]);
  const dlg = await screen.findByRole("dialog", { name: "Цели прогона из активов" });
  // хост из инвентаря и заведённый вручную актив (не сканировался) — оба в списке
  expect(await within(dlg).findByRole("checkbox", { name: "Выбрать 10.0.0.4" })).toBeEnabled();
  expect(within(dlg).getByRole("checkbox", { name: "Выбрать 10.0.9.9" })).toBeDisabled();

  await userEvent.click(within(dlg).getByRole("button", { name: /ДМЗ/ }));
  await userEvent.click(within(dlg).getByRole("button", { name: /Выбрать найденные \(2\)/ }));
  await userEvent.click(within(dlg).getByRole("button", { name: /ДМЗ/ })); // снять фильтр группы
  await userEvent.click(within(dlg).getByRole("checkbox", { name: "Выбрать 10.0.0.4" }));
  // «Выбрать все» не трогает хосты вне allowlist
  expect(within(dlg).getByText(/вне allowlist: 1/)).toBeInTheDocument();
  await userEvent.click(screen.getByRole("button", { name: "Добавить в цели (3)" }));
  expect(onPick).toHaveBeenCalledWith(["10.0.0.1", "10.0.0.2", "10.0.0.4"]);
});

it("поиск и фильтры по ОС, тегу и критичности", async () => {
  setup("run", ["10.0.0.0/16"]);
  const dlg = await screen.findByRole("dialog");
  await within(dlg).findByRole("checkbox", { name: "Выбрать 10.0.0.1" });
  await userEvent.type(within(dlg).getByRole("searchbox", { name: "Поиск хостов" }), "db-1");
  expect(within(dlg).getAllByRole("checkbox", { name: /^Выбрать 10\./ }).map((c) => c.getAttribute("aria-label"))).toEqual(["Выбрать 10.0.0.4"]);
  await userEvent.click(within(dlg).getByRole("button", { name: "Сбросить фильтры" }));
  await userEvent.click(within(dlg).getByRole("button", { name: /Windows/ }));
  expect(within(dlg).getAllByRole("checkbox", { name: /^Выбрать 10\./ })).toHaveLength(1);
  await userEvent.click(within(dlg).getByRole("button", { name: "Сбросить фильтры" }));
  await userEvent.selectOptions(within(dlg).getByRole("combobox", { name: "Тег" }), "prod");
  await userEvent.selectOptions(within(dlg).getByRole("combobox", { name: "Критичность" }), "critical");
  await waitFor(() => expect(within(dlg).getAllByRole("checkbox", { name: /^Выбрать 10\./ })).toHaveLength(1));
  expect(within(dlg).getByText("db-1")).toBeInTheDocument();
});

it("allowlist: уже разрешённые хосты не выбираются повторно", async () => {
  const onPick = setup("allowlist", ["10.0.0.1/32"]);
  const dlg = await screen.findByRole("dialog", { name: "Добавить активы в allowlist" });
  expect(await within(dlg).findByRole("checkbox", { name: "Выбрать 10.0.0.1" })).toBeDisabled();
  await userEvent.click(within(dlg).getByRole("button", { name: /Выбрать все \(4\)/ }));
  await userEvent.click(screen.getByRole("button", { name: "Добавить в allowlist (4)" }));
  expect(onPick).toHaveBeenCalledWith(["10.0.0.2", "10.0.0.3", "10.0.0.4", "10.0.9.9"]);
});
