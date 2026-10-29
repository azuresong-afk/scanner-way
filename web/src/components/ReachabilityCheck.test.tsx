import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { ReachabilityCheck } from "./ReachabilityCheck";
import { mockApi } from "../test/fixtures";

const OK = {
  target: "10.0.0.5",
  reachable: true,
  methods: ["icmp", "tcp"],
  icmp_available: true,
  icmp_alive: true,
  icmp_rtt_ms: 0.8,
  ports: [
    { port: 22, state: "open", rtt_ms: 1.1 },
    { port: 443, state: "filtered", rtt_ms: null },
  ],
  elapsed_ms: 1503,
  checked_at: "2026-10-29T12:00:00Z",
};

afterEach(() => vi.unstubAllGlobals());

it("отправляет адрес и порты, показывает результат", async () => {
  const api = mockApi({ "POST /engagements/7/reachability": OK });
  render(<ReachabilityCheck engagementId={7} initialTarget="10.0.0.5" />);
  const ports = screen.getByLabelText("TCP-порты");
  await userEvent.clear(ports);
  await userEvent.type(ports, "443, 22 22");
  await userEvent.click(screen.getByRole("button", { name: /Проверить/ }));
  expect(await screen.findByText("Доступен")).toBeInTheDocument();
  expect(screen.getByText("22 открыт")).toBeInTheDocument();
  expect(screen.getByText("443 нет ответа")).toBeInTheDocument();
  expect(screen.getByText(/ICMP: ответ за 0.8 мс/)).toBeInTheDocument();
  const call = api.calls.find((c) => c.path === "/engagements/7/reachability");
  expect(JSON.parse(String(call?.init?.body))).toEqual({ target: "10.0.0.5", ports: [22, 443] });
});

it("не отправляет подсеть и мусор в портах", async () => {
  const api = mockApi({});
  render(<ReachabilityCheck engagementId={7} />);
  await userEvent.type(screen.getByLabelText("IP-адрес"), "10.0.0.0/24");
  await userEvent.click(screen.getByRole("button", { name: /Проверить/ }));
  expect(await screen.findByRole("alert")).toHaveTextContent("один IP-адрес");
  await userEvent.clear(screen.getByLabelText("IP-адрес"));
  await userEvent.type(screen.getByLabelText("IP-адрес"), "10.0.0.5");
  await userEvent.clear(screen.getByLabelText("TCP-порты"));
  await userEvent.type(screen.getByLabelText("TCP-порты"), "ssh");
  await userEvent.click(screen.getByRole("button", { name: /Проверить/ }));
  expect(await screen.findByRole("alert")).toHaveTextContent("Порты");
  expect(api.calls).toHaveLength(0);
});

it("объясняет отказ allowlist по-русски", async () => {
  mockApi({
    "POST /engagements/7/reachability": () =>
      new Response(JSON.stringify({ detail: "target is not in the engagement allowlist" }), { status: 422 }),
  });
  render(<ReachabilityCheck engagementId={7} initialTarget="192.168.1.1" />);
  await userEvent.click(screen.getByRole("button", { name: /Проверить/ }));
  expect(await screen.findByRole("alert")).toHaveTextContent("не входит в allowlist");
});
