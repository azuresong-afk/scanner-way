import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { AuthProvider } from "../auth/AuthContext";
import { setToken } from "../api/client";
import type { ScanNode } from "../api/types";
import { ADMIN, me, mockApi } from "../test/fixtures";
import { NodesPage } from "./NodesPage";

afterEach(() => {
  setToken(null);
  vi.unstubAllGlobals();
});

const node = (p: Partial<ScanNode> = {}): ScanNode => ({
  id: 1,
  name: "Филиал Казань",
  description: null,
  mode: "online",
  status: "online",
  scope: ["10.1.0.0/24"],
  allow_credentials: true,
  enabled: true,
  token_prefix: "snode_AbCd",
  hostname: "scan-kzn",
  version: "0.1.0",
  local_allowlist: ["10.1.0.0/25"],
  outside_local_allowlist: ["10.1.0.0/24"],
  tools: { nmap: true, nuclei: false },
  created_at: "2026-11-06T10:00:00Z",
  registered_at: "2026-11-06T10:01:00Z",
  last_seen_at: "2026-11-06T10:05:00Z",
  active_runs: [42],
  queued_runs: 1,
  has_public_key: false,
  ...p,
});

function renderPage(permissions: string[]) {
  setToken("t");
  const api = mockApi({
    "GET /me": me(["admin"], permissions),
    "GET /nodes": [node(), node({ id: 2, name: "АСУ ТП", mode: "offline", status: "autonomous", token_prefix: null, active_runs: [], queued_runs: 0, outside_local_allowlist: [], tools: {} })],
    "POST /nodes": { ...node({ id: 3, name: "ДМЗ", status: "never", scope: ["192.168.10.0/24"] }), token: "snode_secret-token" },
    "GET /offline/center-key": { public_key: "scanner-center-key:v1:AAA:BBB", fingerprint: "c3a1-77d0-9e42-0b15" },
    "GET /nodes/2/public-key": { public_key: null, fingerprint: null },
    "PUT /nodes/2/public-key": { public_key: "scanner-node-key:v1:CCC:DDD", fingerprint: "5be0-12aa-f00d-4c21" },
  });
  render(
    <MemoryRouter>
      <AuthProvider>
        <NodesPage />
      </AuthProvider>
    </MemoryRouter>,
  );
  return api;
}

describe("NodesPage", () => {
  it("показывает статус, текущий прогон и предупреждения узла", async () => {
    renderPage(ADMIN);
    expect(await screen.findByText("Филиал Казань")).toBeInTheDocument();
    expect(screen.getByText("На связи")).toBeInTheDocument();
    expect(screen.getAllByText("Автономный").length).toBeGreaterThan(0);
    expect(screen.getByRole("link", { name: "прогон #42" })).toHaveAttribute("href", "/runs/42");
    expect(screen.getByText(/не входят в локальный allowlist узла/)).toBeInTheDocument();
    expect(screen.getByText(/На узле нет: Nuclei/)).toBeInTheDocument();
  });

  it("заводит сетевой узел и один раз показывает токен с .env.node", async () => {
    const api = renderPage(ADMIN);
    await userEvent.click(await screen.findByRole("button", { name: /Добавить узел/ }));
    await userEvent.type(screen.getByLabelText("Название"), "ДМЗ");
    await userEvent.type(screen.getByLabelText("Сети узла"), "192.168.10.0/24");
    await userEvent.click(screen.getAllByRole("button", { name: "Добавить узел" }).at(-1)!);
    await waitFor(() => expect(api.calls.some((c) => c.method === "POST" && c.path === "/nodes")).toBe(true));
    const call = api.calls.find((c) => c.method === "POST" && c.path === "/nodes")!;
    expect(JSON.parse(String(call.init?.body))).toMatchObject({ name: "ДМЗ", mode: "online", scope: ["192.168.10.0/24"] });
    const env = await screen.findByTestId("node-env");
    expect(env.textContent).toContain("SCANNER_NODE_TOKEN=snode_secret-token");
    expect(env.textContent).toContain("SCANNER_NODE_ALLOWLIST=192.168.10.0/24");
  });

  it("без права manage_nodes узлы только видны", async () => {
    renderPage(["view_engagements", "run_scan"]);
    expect(await screen.findByText("Филиал Казань")).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /Добавить узел/ })).toBeNull();
    expect(screen.queryByRole("button", { name: /Отключить/ })).toBeNull();
    expect(screen.queryByRole("button", { name: /Загрузить ключ узла/ })).toBeNull();
    // результат с носителя загружает оператор
    expect(screen.getByText("Загрузить результат")).toBeInTheDocument();
  });

  it("автономный узел: ключ центра, загрузка node.pub", async () => {
    const api = renderPage(ADMIN);
    expect(await screen.findByText("c3a1-77d0-9e42-0b15")).toBeInTheDocument();
    expect(await screen.findByText(/не загружен — задания узлу не выгрузить/)).toBeInTheDocument();
    // у администратора без run_scan кнопки «Загрузить результат» нет
    expect(screen.queryByText("Загрузить результат")).toBeNull();
    await userEvent.click(screen.getByRole("button", { name: /Загрузить ключ узла/ }));
    await userEvent.type(screen.getByLabelText("Открытый ключ узла «АСУ ТП»"), "scanner-node-key:v1:CCC:DDD");
    await userEvent.click(screen.getByRole("button", { name: "Сохранить" }));
    expect(await screen.findByText("5be0-12aa-f00d-4c21")).toBeInTheDocument();
    const put = api.calls.find((c) => c.method === "PUT" && c.path === "/nodes/2/public-key")!;
    expect(JSON.parse(String(put.init?.body))).toMatchObject({ public_key: "scanner-node-key:v1:CCC:DDD" });
    expect(screen.getByRole("button", { name: /Заменить ключ узла/ })).toBeInTheDocument();
  });
});
