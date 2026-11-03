import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { AuthProvider } from "../auth/AuthContext";
import { setToken } from "../api/client";
import type { EngagementOut, RunPlan, RunProfile } from "../api/types";
import { me, mockApi, OPERATOR } from "../test/fixtures";
import { StartRunModal } from "./StartRunModal";

afterEach(() => {
  setToken(null);
  vi.unstubAllGlobals();
});

const ENG = { id: 1, name: "Стенд", client: null, contract_ref: null, created_by: 1, created_at: null } as unknown as EngagementOut;

const PROFILES: RunProfile[] = [
  { id: "linux_full", title: "Полная проверка Linux", description: "Всё по SSH", modules: ["discovery", "vuln", "auth_inventory", "config_audit", "password_policy"], needs: ["ssh"] },
  { id: "network", title: "Только сетевая проверка", description: "Без учётки", modules: ["discovery", "vuln"], needs: [] },
  { id: "discovery", title: "Только обнаружение", description: "nmap", modules: ["discovery"], needs: [] },
];

const PLAN: RunPlan = {
  modules: [
    { name: "discovery", title: "Обнаружение хостов", companion: false, note: null },
    { name: "vuln", title: "Сетевая проверка", companion: false, note: null },
  ],
  removed: [{ name: "win_inventory", title: "Windows по WinRM", companion: false, note: "нет учётки WinRM" }],
  warnings: ["Нет проверки по учётной записи: уязвимости определяются только по сети"],
  full_check: false,
  accepted_targets: 1,
  denied_targets: [],
};

function open(perms: string[]) {
  setToken("t");
  const api = mockApi({
    "GET /me": me(["operator"], perms),
    "GET /engagements/1/allowlist": [{ id: 1, cidr: "10.0.0.0/24", note: null, added_by: 1, added_at: null }],
    "GET /run-profiles": PROFILES,
    "POST /engagements/1/runs/plan": PLAN,
    "POST /engagements/1/runs": { id: 9, engagement_id: 1, modules: [], rate_profile: "gentle", credential_ids: [], cred_set_ids: [], status: "pending",
      started_by: 1, started_at: null, finished_at: null, created_at: null, accepted_targets: 1, denied_targets: [] },
  });
  render(
    <MemoryRouter>
      <AuthProvider>
        <StartRunModal engagement={ENG} onClose={() => undefined} onStarted={() => undefined} />
      </AuthProvider>
    </MemoryRouter>,
  );
  return api;
}

it("профиль проверки, итоговый состав прогона и -Pn с последствиями", async () => {
  const api = open(OPERATOR);
  const dlg = await screen.findByRole("dialog", { name: "Новый прогон" });
  // профиль с SSH недоступен без права на учётки
  expect(await within(dlg).findByRole("radio", { name: /Полная проверка Linux/ })).toBeDisabled();
  await userEvent.click(within(dlg).getByRole("radio", { name: /Только сетевая проверка/ }));
  expect(within(dlg).getByRole("radio", { name: /^Nuclei/ })).toBeChecked();
  await userEvent.type(within(dlg).getByLabelText(/Цели/), "10.0.0.5");
  const plan = await within(dlg).findByRole("region", { name: "Итоговый состав прогона" });
  expect(within(plan).getByText("Неполная проверка")).toBeInTheDocument();
  expect(within(plan).getByText(/Не будет запущено/)).toHaveTextContent("нет учётки WinRM");
  expect(within(plan).getByText(/только по сети/)).toBeInTheDocument();
  const pn = within(dlg).getByRole("checkbox", { name: /не отвечающие на ping/ });
  expect(within(dlg).getByText(/прогон заметно дольше/)).toBeInTheDocument();
  await userEvent.click(pn);
  await userEvent.click(within(dlg).getByRole("checkbox", { name: /Подтверждаю/ }));
  await userEvent.click(screen.getByRole("button", { name: "Запустить" }));
  await waitFor(() => expect(api.calls.some((c) => c.path === "/engagements/1/runs" && c.init?.method === "POST")).toBe(true));
  const sent = JSON.parse(String(api.calls.find((c) => c.path === "/engagements/1/runs" && c.init?.method === "POST")!.init!.body));
  expect(sent).toMatchObject({ modules: ["discovery", "vuln"], no_ping: true, profile: "network", targets: ["10.0.0.5"] });
  const planCall = api.calls.find((c) => c.path === "/engagements/1/runs/plan")!;
  expect(JSON.parse(String(planCall.init!.body)).modules).toEqual(["discovery", "vuln"]);
});
