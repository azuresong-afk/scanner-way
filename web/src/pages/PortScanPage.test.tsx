import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { setToken } from "../api/client";
import type { PortScanDetail } from "../api/types";
import { parsePortSpec, subtractRanges } from "../lib/ports";
import { mockApi } from "../test/fixtures";
import { PortScanPage } from "./PortScanPage";

let perms: string[] = [];
vi.mock("../auth/AuthContext", () => ({
  useAuth: () => ({ has: (p: string) => perms.includes(p) }),
}));
vi.mock("../auth/EngagementContext", () => ({
  useEngagement: () => ({
    current: { id: 5, name: "Договор", client: "Ромашка" },
  }),
}));

afterEach(() => {
  setToken(null);
  vi.unstubAllGlobals();
});

const scan: PortScanDetail = {
  id: 3,
  engagement_id: 5,
  status: "done",
  requested_targets: ["10.0.0.0/30"],
  port_mode: "top",
  ports: null,
  exclude_ports: "9100",
  port_count: 1000,
  no_ping: false,
  service_detection: true,
  rate_profile: "gentle",
  hosts_total: 2,
  hosts_done: 2,
  hosts_up: 1,
  open_ports: 2,
  assets_created: 1,
  error: null,
  actor: "user:op",
  created_at: "2026-11-03T10:00:00Z",
  started_at: "2026-11-03T10:00:01Z",
  finished_at: "2026-11-03T10:00:31Z",
  results: [
    {
      host: "10.0.0.1",
      up: true,
      reason: "syn-ack",
      hostname: "gw.local",
      mac: null,
      vendor: null,
      ports: [
        {
          port: 22,
          protocol: "tcp",
          service: "ssh",
          product: "OpenSSH",
          version: "9.2p1",
        },
        {
          port: 443,
          protocol: "tcp",
          service: "https",
          product: null,
          version: null,
        },
      ],
    },
    {
      host: "10.0.0.2",
      up: false,
      reason: null,
      hostname: null,
      mac: null,
      vendor: null,
      ports: [],
    },
  ],
};

function renderPage(p: string[]) {
  perms = p;
  setToken("t");
  const api = mockApi({
    "GET /engagements/5/allowlist": [
      {
        id: 1,
        engagement_id: 5,
        cidr: "10.0.0.0/24",
        note: null,
        created_at: null,
      },
    ],
    "GET /engagements/5/port-scans": [scan],
    "GET /port-scans/3": scan,
    "POST /engagements/5/port-scans": {
      ...scan,
      id: 4,
      status: "queued",
      hosts_done: 0,
      denied_targets: [],
    },
    "GET /port-scans/4": {
      ...scan,
      id: 4,
      status: "running",
      hosts_done: 0,
      results: [],
    },
  });
  render(
    <MemoryRouter>
      <PortScanPage />
    </MemoryRouter>,
  );
  return api;
}

it("разбирает и вычитает порты", () => {
  expect(parsePortSpec("80, 22 - 25;8000–8001")).toEqual([
    [22, 25],
    [80, 80],
    [8000, 8001],
  ]);
  expect(parsePortSpec("22,--script")).toMatch(/не порт/);
  expect(parsePortSpec("70000")).toMatch(/вне диапазона/);
  expect(subtractRanges([[1, 100]], [[10, 20]])).toEqual([
    [1, 9],
    [21, 100],
  ]);
});

it("показывает последнюю проверку: хосты в сети, порты, добавленные активы", async () => {
  renderPage(["view_report"]);
  expect(await screen.findByText("gw.local")).toBeInTheDocument();
  expect(screen.getByText(/22\/ssh · OpenSSH 9.2p1/)).toBeInTheDocument();
  expect(screen.getByText("Добавлено в «Активы»")).toBeInTheDocument();
  expect(screen.queryByText("10.0.0.2")).toBeNull(); // по умолчанию — только хосты в сети
  await userEvent.click(screen.getByLabelText(/Только хосты в сети/));
  expect(screen.getByText("10.0.0.2")).toBeInTheDocument();
  // без права run_scan формы запуска нет
  expect(screen.queryByRole("form", { name: "Новая проверка доступности" })).toBeNull();
});

it("запускает проверку своего списка портов с исключениями и -Pn", async () => {
  const api = renderPage(["view_report", "run_scan"]);
  await screen.findByText("gw.local");
  await userEvent.type(screen.getByLabelText(/Адреса/), "10.0.0.5-10");
  await userEvent.click(screen.getByRole("radio", { name: "Свой список" }));
  await userEvent.type(screen.getByPlaceholderText("22, 80, 443, 8000-8100"), "20-25, 80");
  await userEvent.type(screen.getByLabelText("Исключить порты"), "23");
  await userEvent.click(screen.getByLabelText(/Без проверки ping/));
  await userEvent.click(screen.getByRole("button", { name: /Проверить · 6 портов/ }));
  await waitFor(() => expect(api.calls.some((c) => c.method === "POST" && c.path === "/engagements/5/port-scans")).toBe(true));
  const post = api.calls.find((c) => c.method === "POST")!;
  expect(JSON.parse(String(post.init?.body))).toMatchObject({
    targets: ["10.0.0.5-10"],
    port_mode: "list",
    ports: "20-25, 80",
    exclude_ports: "23",
    no_ping: true,
    service_detection: false,
  });
});

it("не даёт запустить, если после исключений портов не осталось", async () => {
  renderPage(["view_report", "run_scan"]);
  await screen.findByText("gw.local");
  await userEvent.type(screen.getByLabelText(/Адреса/), "10.0.0.5");
  await userEvent.click(screen.getByRole("radio", { name: "Свой список" }));
  await userEvent.type(screen.getByPlaceholderText("22, 80, 443, 8000-8100"), "22");
  await userEvent.type(screen.getByLabelText("Исключить порты"), "1-100");
  expect(screen.getByText("После исключений не осталось ни одного порта")).toBeInTheDocument();
  expect(screen.getByRole("button", { name: /^Проверить/ })).toBeDisabled();
});
