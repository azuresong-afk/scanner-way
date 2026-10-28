import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { App } from "./App";
import { setToken } from "./api/client";
import { AuthProvider } from "./auth/AuthContext";
import { ThemeProvider } from "./theme/ThemeContext";
import { ADMIN, OPERATOR, finding, me, mockApi } from "./test/fixtures";

const ENG = { id: 1, name: "Периметр", client: "ООО Тест", contract_ref: "Д-1", created_by: 1, created_at: "2026-10-01T10:00:00" };

function renderApp(path = "/") {
  return render(
    <ThemeProvider>
      <MemoryRouter initialEntries={[path]} future={{ v7_startTransition: true, v7_relativeSplatPath: true }}>
        <AuthProvider>
          <App />
        </AuthProvider>
      </MemoryRouter>
    </ThemeProvider>,
  );
}

afterEach(() => {
  setToken(null);
  vi.unstubAllGlobals();
  localStorage.clear();
});

it("без токена показывает вход и сообщает о неверном пароле", async () => {
  mockApi({ "POST /auth/token": () => new Response(JSON.stringify({ detail: "invalid credentials" }), { status: 401 }) });
  renderApp("/");
  await userEvent.type(await screen.findByLabelText("Имя пользователя"), "ivanov");
  await userEvent.type(screen.getByLabelText("Пароль"), "wrong-password");
  await userEvent.click(screen.getByRole("button", { name: /Войти/ }));
  expect(await screen.findByRole("alert")).toHaveTextContent("Неверное имя пользователя или пароль");
});

it("после входа отправляет Bearer-токен", async () => {
  const api = mockApi({
    "POST /auth/token": { access_token: "tok123", token_type: "bearer", expires_in: 3600 },
    "GET /me": me(["operator"], OPERATOR),
    "GET /engagements": [ENG],
    "GET /engagements/1/runs": [],
  });
  renderApp("/");
  await userEvent.type(await screen.findByLabelText("Имя пользователя"), "ivanov");
  await userEvent.type(screen.getByLabelText("Пароль"), "correct-horse-battery");
  await userEvent.click(screen.getByRole("button", { name: /Войти/ }));
  expect(await screen.findByRole("heading", { name: "Сводка по договору" })).toBeInTheDocument();
  const meCall = api.calls.find((c) => c.path === "/me");
  expect(new Headers(meCall?.init?.headers).get("Authorization")).toBe("Bearer tok123");
});

it("меню зависит от прав: оператор не видит администрирование", async () => {
  setToken("t");
  mockApi({ "GET /me": me(["operator"], OPERATOR), "GET /engagements": [ENG], "GET /engagements/1/runs": [] });
  renderApp("/");
  const nav = await screen.findByRole("navigation", { name: "Основное меню" });
  await within(nav).findByText("Прогоны");
  expect(within(nav).queryByText("Пользователи и роли")).not.toBeInTheDocument();
  expect(within(nav).queryByText("Журнал аудита")).not.toBeInTheDocument();
});

it("администратор видит пользователей, но не кнопку запуска прогона", async () => {
  setToken("t");
  mockApi({ "GET /me": me(["admin"], ADMIN), "GET /engagements": [ENG], "GET /engagements/1/runs": [] });
  renderApp("/");
  const nav = await screen.findByRole("navigation", { name: "Основное меню" });
  await within(nav).findByText("Пользователи и роли");
  await screen.findByText("Завершённых прогонов пока нет");
  expect(screen.queryByRole("button", { name: /Новый прогон/ })).not.toBeInTheDocument();
});

it("закрытый раздел без права показывает отказ", async () => {
  setToken("t");
  mockApi({ "GET /me": me(["operator"], OPERATOR), "GET /engagements": [ENG] });
  renderApp("/users");
  expect(await screen.findByText("Нет доступа")).toBeInTheDocument();
});

describe("модуль cred_audit в форме запуска", () => {
  async function openForm(perms: string[]) {
    setToken("t");
    mockApi({
      "GET /me": me(["operator"], perms),
      "GET /engagements": [ENG],
      "GET /engagements/1/runs": [],
      "GET /engagements/1/allowlist": [{ id: 1, cidr: "10.0.0.0/24", note: null, added_by: 1, added_at: null }],
    });
    renderApp("/runs");
    await userEvent.click(await screen.findByRole("button", { name: /Новый прогон/ }));
    return screen.findByRole("dialog", { name: "Новый прогон" });
  }

  it("скрыт без права cred_audit", async () => {
    const dlg = await openForm(OPERATOR);
    expect(within(dlg).getByText("Поиск уязвимостей")).toBeInTheDocument();
    expect(within(dlg).queryByText("Аудит учётных данных")).not.toBeInTheDocument();
  });

  it("виден при наличии права", async () => {
    const dlg = await openForm([...OPERATOR, "cred_audit"]);
    expect(within(dlg).getByText("Аудит учётных данных")).toBeInTheDocument();
  });

  it("запуск требует подтверждения объёма работ", async () => {
    const dlg = await openForm(OPERATOR);
    await userEvent.click(within(dlg).getByRole("button", { name: /Подставить весь allowlist/ }));
    const submit = screen.getByRole("button", { name: "Запустить" });
    expect(submit).toBeDisabled();
    await userEvent.click(within(dlg).getByRole("checkbox", { name: /Подтверждаю/ }));
    await waitFor(() => expect(submit).toBeEnabled());
  });
});

it("сводка показывает открытые уязвимости и изменения к прошлому прогону", async () => {
  setToken("t");
  const run = (id: number) => ({
    id, engagement_id: 1, modules: ["discovery", "vuln"], rate_profile: "gentle", status: "done",
    started_by: 1, started_at: "2026-10-27T10:00:00", finished_at: "2026-10-27T11:00:00", created_at: "2026-10-27T10:00:00",
  });
  const log4j = finding({ severity: "critical", title: "Log4Shell" });
  mockApi({
    "GET /me": me(["operator"], OPERATOR),
    "GET /engagements": [ENG],
    "GET /engagements/1/runs": [run(1), run(2)],
    "GET /runs/1/findings": [log4j, finding({ vuln_id: "CVE-2017-0144", cve_ids: ["CVE-2017-0144"], title: "EternalBlue" })],
    "GET /runs/2/findings": [log4j, finding({ host: "10.0.0.2", vuln_id: "X", cve_ids: [], bdu_ids: [], severity: "medium", status: "new", title: "TLS 1.0" })],
    "GET /runs/1/services": [],
    "GET /runs/2/services": [],
  });
  renderApp("/");
  await screen.findByRole("heading", { name: "Сводка по договору" });
  expect(await screen.findByText("открытые уязвимости на 2 хостах")).toBeInTheDocument();
  expect(screen.getByText("без изменений к прогону №1")).toBeInTheDocument();
  const tile = (label: string) => screen.getByText(label).closest(".change-tile") as HTMLElement;
  expect(within(tile("Новые")).getByText("1")).toBeInTheDocument();
  expect(within(tile("Закрытые")).getByText("1")).toBeInTheDocument();
  expect(within(tile("Регрессии")).getByText("0")).toBeInTheDocument();
});

it("переключает светлую и тёмную тему и запоминает выбор", async () => {
  setToken("t");
  mockApi({ "GET /me": me(["operator"], OPERATOR), "GET /engagements": [ENG], "GET /engagements/1/runs": [] });
  renderApp("/");
  const html = document.documentElement;
  await screen.findByRole("heading", { name: "Сводка по договору" });
  expect(html.dataset.theme).toBe("dark");

  await userEvent.click(screen.getByRole("button", { name: "Включить светлую тему" }));
  expect(html.dataset.theme).toBe("light");
  expect(localStorage.getItem("scanner.theme")).toBe("light");

  await userEvent.click(screen.getByRole("button", { name: "Включить тёмную тему" }));
  expect(html.dataset.theme).toBe("dark");
});
