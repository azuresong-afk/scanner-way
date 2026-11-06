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
  });
});
