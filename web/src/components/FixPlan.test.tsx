import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { AuthProvider } from "../auth/AuthContext";
import { setToken } from "../api/client";
import type { FixPlanOut, FixTaskOut } from "../api/types";
import { finding, me, mockApi, OPERATOR } from "../test/fixtures";
import { FixPlan } from "./FixPlan";

afterEach(() => {
  setToken(null);
  vi.unstubAllGlobals();
});

const task = (p: Partial<FixTaskOut> = {}): FixTaskOut => ({
  key: "k1",
  kind: "package",
  kind_label: "Обновление пакета",
  title: "Обновить libssl3, openssl до 3.0.15-1~deb12u1",
  os: "Debian 12",
  os_family: "debian",
  manager: "dpkg",
  packages: ["libssl3", "openssl"],
  fixed_version: "3.0.15-1~deb12u1",
  software: null,
  steps: ["Обновите пакеты libssl3, openssl до версии не ниже 3.0.15-1~deb12u1 из репозитория Debian bookworm (бюллетень DSA-5532-1)."],
  commands: ["sudo apt-get update", "sudo apt-get install --only-upgrade -y libssl3 openssl"],
  verify: ["dpkg-query -W -f='${Package} ${Version}\\n' libssl3 openssl"],
  reboot: false,
  details: null,
  details_source: null,
  severity: "high",
  priority: { score: 81, label: "high", label_ru: "Высокий", rank: 1 },
  cves: ["CVE-2023-5678"],
  bdu_ids: [],
  advisories: ["DSA-5532-1"],
  references: ["https://www.debian.org/security/2023/dsa-5532", "javascript:alert(1)"],
  hosts: [{ host: "10.0.0.2", installed: "3.0.11-1~deb12u1", note: null, ports: [], findings: [{ id: 11, label: "CVE-2023-5678", severity: "high" }] }],
  host_count: 1,
  finding_count: 1,
  ...p,
});

const plan = (items: FixTaskOut[]): FixPlanOut => ({
  total: items.length,
  items,
  tasks: items.length,
  hosts: 1,
  findings: 1,
  false_positives: 2,
  kinds: { package: 1, kernel: 1 },
  os: { "Debian 12": 2 },
  severities: { high: 2 },
});

it("план исправлений: действие, команды, хосты, ссылки; находка открывается из карточки", async () => {
  setToken("t");
  const kernel = task({ key: "k2", kind: "kernel", title: "Обновить ядро Linux и перезагрузить (Debian 12)", reboot: true, commands: ["sudo apt-get update", "sudo reboot"], verify: ["uname -r"], references: [], advisories: [] });
  const api = mockApi({
    "GET /me": me(["operator"], OPERATOR),
    "GET /runs/7/fixes": plan([task(), kernel]),
    "GET /findings/11": finding({ id: 11, host: "10.0.0.2", title: "CVE-2023-5678: пакет openssl" }),
  });
  render(
    <MemoryRouter initialEntries={["/findings?run=7"]}>
      <AuthProvider>
        <FixPlan runId={7} onHost={() => undefined} />
      </AuthProvider>
    </MemoryRouter>,
  );
  expect(await screen.findByText("Обновить libssl3, openssl до 3.0.15-1~deb12u1")).toBeInTheDocument();
  expect(screen.getByText(/без 2 ложных срабатываний/)).toBeInTheDocument();
  expect(screen.getByText(/sudo apt-get install --only-upgrade -y libssl3 openssl/)).toBeInTheDocument();
  expect(screen.getByText("перезагрузка")).toBeInTheDocument();
  // ссылки — только http(s)
  expect(screen.getByRole("link", { name: "debian.org · dsa-5532" })).toHaveAttribute("href", "https://www.debian.org/security/2023/dsa-5532");
  expect(screen.queryByText("javascript:alert(1)")).not.toBeInTheDocument();

  // фильтр по виду действия уходит на сервер
  await userEvent.click(screen.getByRole("button", { name: /Ядро и перезагрузка/ }));
  await waitFor(() => {
    const last = api.fn.mock.calls.map((c) => new URL(String(c[0]), "http://x")).filter((u) => u.pathname.endsWith("/runs/7/fixes")).at(-1)!;
    expect(last.searchParams.getAll("kind")).toEqual(["kernel"]);
  });

  // находка из карточки — для отметки «ложное срабатывание»
  const card = screen.getByText("Обновить libssl3, openssl до 3.0.15-1~deb12u1").closest("details")!;
  await userEvent.click(within(card).getByRole("button", { name: "CVE-2023-5678" }));
  expect(await screen.findByText("CVE-2023-5678: пакет openssl")).toBeInTheDocument();
});
