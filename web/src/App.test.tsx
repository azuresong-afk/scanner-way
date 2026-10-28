import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { App } from "./App";
import { setToken } from "./api/client";
import { AuthProvider } from "./auth/AuthContext";
import { AppearanceProvider } from "./theme/AppearanceContext";
import { ADMIN, OPERATOR, me, mockApi } from "./test/fixtures";

const ENG = { id: 1, name: "Периметр", client: "ООО Тест", contract_ref: "Д-1", created_by: 1, created_at: "2026-10-01T10:00:00" };

function renderApp(path = "/") {
  return render(
    <AppearanceProvider>
      <MemoryRouter initialEntries={[path]} future={{ v7_startTransition: true, v7_relativeSplatPath: true }}>
        <AuthProvider>
          <App />
        </AuthProvider>
      </MemoryRouter>
    </AppearanceProvider>,
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
  expect(await screen.findByRole("heading", { name: "Обзор безопасности" })).toBeInTheDocument();
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

it("переключает вид интерфейса и помнит тему отдельно для каждого вида", async () => {
  setToken("t");
  mockApi({ "GET /me": me(["operator"], OPERATOR), "GET /engagements": [ENG], "GET /engagements/1/runs": [] });
  renderApp("/");
  const html = document.documentElement;
  await screen.findByRole("heading", { name: "Обзор безопасности" });
  expect(html.dataset.layout).toBe("sidebar");
  expect(html.dataset.theme).toBe("dark");

  await userEvent.click(screen.getByRole("button", { name: "Верхнее меню" }));
  expect(await screen.findByRole("heading", { name: "Сводка по договору" })).toBeInTheDocument();
  expect(html.dataset.layout).toBe("topnav");
  expect(html.dataset.theme).toBe("light");

  await userEvent.click(screen.getByRole("button", { name: "Включить тёмную тему" }));
  expect(html.dataset.theme).toBe("dark");

  await userEvent.click(screen.getByRole("button", { name: "Боковое меню" }));
  await userEvent.click(screen.getByRole("button", { name: "Включить светлую тему" }));
  expect(html.dataset.theme).toBe("light");

  await userEvent.click(screen.getByRole("button", { name: "Верхнее меню" }));
  expect(html.dataset.theme).toBe("dark");
  expect(localStorage.getItem("scanner.layout")).toBe("topnav");
});
