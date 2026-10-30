import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
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

const CRED = {
  id: 5, engagement_id: 1, name: "Серверы ДМЗ", username: "audit", auth: "key", port: 22,
  targets: ["10.0.0.0/24"], key_fingerprint: "SHA256:abc", created_by: 1, created_at: null, become: "sudo",
};

describe("модуль cred_audit в форме запуска", () => {
  async function openForm(perms: string[], extra: Record<string, unknown> = {}) {
    setToken("t");
    const api = mockApi({
      "GET /me": me(["operator"], perms),
      "GET /engagements": [ENG],
      "GET /engagements/1/runs": [],
      "GET /engagements/1/allowlist": [{ id: 1, cidr: "10.0.0.0/24", note: null, added_by: 1, added_at: null }],
      ...extra,
    } as Parameters<typeof mockApi>[0]);
    renderApp("/runs");
    await userEvent.click(await screen.findByRole("button", { name: /Новый прогон/ }));
    return { dlg: await screen.findByRole("dialog", { name: "Новый прогон" }), api };
  }

  it("скрыт без права cred_audit", async () => {
    const { dlg } = await openForm(OPERATOR);
    expect(within(dlg).getByText("Поиск уязвимостей — движок")).toBeInTheDocument();
    expect(within(dlg).queryByText("Аудит учётных данных")).not.toBeInTheDocument();
  });

  it("движок «по учётной записи» недоступен без права host_credentials", async () => {
    const { dlg } = await openForm(OPERATOR);
    expect(within(dlg).getByRole("radio", { name: /Nuclei/ })).toBeChecked();
    expect(within(dlg).getByRole("radio", { name: /По учётной записи/ })).toBeDisabled();
    expect(within(dlg).getAllByText("Нужно право host_credentials")).toHaveLength(2);
  });

  it("по учётной записи: нужна учётка, в запрос уходят auth_inventory и её id", async () => {
    const { dlg, api } = await openForm([...OPERATOR, "host_credentials"], {
      "GET /engagements/1/credentials": [CRED],
      "POST /engagements/1/runs": { id: 9, engagement_id: 1, modules: [], rate_profile: "gentle", credential_ids: [5], status: "pending",
        started_by: 1, started_at: null, finished_at: null, created_at: null, accepted_targets: 1, denied_targets: [] },
    });
    await userEvent.click(within(dlg).getByRole("radio", { name: /По учётной записи/ }));
    await userEvent.click(within(dlg).getByRole("button", { name: /Подставить весь allowlist/ }));
    await userEvent.click(within(dlg).getByRole("checkbox", { name: /Подтверждаю/ }));
    const submit = screen.getByRole("button", { name: "Запустить" });
    expect(submit).toBeDisabled();                       // учётка не выбрана
    await userEvent.click(await within(dlg).findByRole("checkbox", { name: /Серверы ДМЗ/ }));
    await waitFor(() => expect(submit).toBeEnabled());
    await userEvent.click(submit);
    await waitFor(() => expect(api.calls.some((c) => c.path === "/engagements/1/runs" && c.init?.method === "POST")).toBe(true));
    const call = api.calls.find((c) => c.path === "/engagements/1/runs" && c.init?.method === "POST")!;
    const sent = JSON.parse(String(call.init!.body));
    expect(sent.modules).toEqual(["discovery", "auth_inventory"]);
    expect(sent.credential_ids).toEqual([5]);
  });

  it("аудит конфигураций скрыт без права host_credentials", async () => {
    const { dlg } = await openForm(OPERATOR);
    expect(within(dlg).queryByText("Аудит конфигураций")).not.toBeInTheDocument();
  });

  it("аудит конфигураций требует учётку, в запрос уходят config_audit и её id", async () => {
    const { dlg, api } = await openForm([...OPERATOR, "host_credentials"], {
      "GET /engagements/1/credentials": [CRED],
      "POST /engagements/1/runs": { id: 9, engagement_id: 1, modules: [], rate_profile: "gentle", credential_ids: [5], status: "pending",
        started_by: 1, started_at: null, finished_at: null, created_at: null, accepted_targets: 1, denied_targets: [] },
    });
    await userEvent.click(within(dlg).getByRole("radio", { name: /Не искать/ }));
    expect(within(dlg).queryByText("Учётные записи для входа на хосты")).not.toBeInTheDocument();
    await userEvent.click(within(dlg).getByRole("checkbox", { name: /Аудит конфигураций/ }));
    expect(within(dlg).getByText(/Аудиту конфигураций нужны права root/)).toBeInTheDocument();
    await userEvent.click(within(dlg).getByRole("button", { name: /Подставить весь allowlist/ }));
    await userEvent.click(within(dlg).getByRole("checkbox", { name: /Подтверждаю/ }));
    const submit = screen.getByRole("button", { name: "Запустить" });
    expect(submit).toBeDisabled();                       // учётка не выбрана
    const cred = await within(dlg).findByRole("checkbox", { name: /Серверы ДМЗ/ });
    expect(cred.closest("label")).toHaveTextContent("sudo");
    await userEvent.click(cred);
    await waitFor(() => expect(submit).toBeEnabled());
    await userEvent.click(submit);
    await waitFor(() => expect(api.calls.some((c) => c.path === "/engagements/1/runs" && c.init?.method === "POST")).toBe(true));
    const call = api.calls.find((c) => c.path === "/engagements/1/runs" && c.init?.method === "POST")!;
    const sent = JSON.parse(String(call.init!.body));
    expect(sent.modules).toEqual(["discovery", "config_audit"]);
    expect(sent.credential_ids).toEqual([5]);
  });

  it("виден при наличии права", async () => {
    const { dlg } = await openForm([...OPERATOR, "cred_audit"]);
    expect(within(dlg).getByText("Аудит учётных данных")).toBeInTheDocument();
  });

  it("запуск требует подтверждения объёма работ", async () => {
    const { dlg } = await openForm(OPERATOR);
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

it("вкладка «Хосты»: список постоянный, от прогона меняются только счётчики", async () => {
  setToken("t");
  const run = (id: number) => ({
    id, engagement_id: 1, modules: ["discovery", "vuln"], rate_profile: "gentle", status: "done",
    started_by: 1, started_at: "2026-10-27T10:00:00", finished_at: "2026-10-27T11:00:00", created_at: "2026-10-27T10:00:00",
  });
  const ssh = { port: 22, protocol: "tcp", service: "ssh", product: "OpenSSH", version: "7.4", cpe: null };
  mockApi({
    "GET /me": me(["operator"], OPERATOR),
    "GET /engagements": [ENG],
    "GET /engagements/1/runs": [run(1), run(2)],
    "GET /engagements/1/hosts": [
      { host: "10.0.0.1", os_guess: null, run_ids: [1, 2], services_run_id: 2, services: [{ host: "10.0.0.1", ...ssh }] },
      { host: "10.0.0.2", os_guess: null, run_ids: [1], services_run_id: 1, services: [{ host: "10.0.0.2", ...ssh }] },
    ],
    "GET /runs/1/findings": [
      finding({ host: "10.0.0.1", severity: "critical", vuln_id: "A" }),
      finding({ host: "10.0.0.1", severity: "high", vuln_id: "B" }),
      finding({ host: "10.0.0.2", severity: "medium" }),
    ],
    "GET /runs/2/findings": [finding({ host: "10.0.0.1", severity: "high", vuln_id: "B" })],
  });
  renderApp("/hosts");
  const row = async (host: string) => (await screen.findByRole("link", { name: host })).closest("tr") as HTMLElement;
  const vulns = async (host: string) => (await row(host)).lastElementChild?.textContent;

  // по умолчанию — последний прогон (№2): 10.0.0.2 в нём не было, но он остаётся в списке
  await screen.findByText(/в прогоне №2: 1/);
  expect(await vulns("10.0.0.1")).toBe("1");
  expect(within(await row("10.0.0.2")).getByText("не в прогоне №2")).toBeInTheDocument();

  fireEvent.change(screen.getByRole("combobox", { name: "Прогон" }), { target: { value: "1" } });
  await screen.findByText(/в прогоне №1: 2/);
  await waitFor(async () => expect(await vulns("10.0.0.1")).toBe("2"));
  expect(await vulns("10.0.0.2")).toBe("1");
  expect(screen.getAllByRole("link").filter((a) => a.closest("tbody"))).toHaveLength(2);
});

it("показывает ОС хостов, фильтрует и группирует по семейству ОС", async () => {
  setToken("t");
  const run = {
    id: 1, engagement_id: 1, modules: ["discovery"], rate_profile: "gentle", status: "done",
    started_by: 1, started_at: "2026-10-27T10:00:00", finished_at: "2026-10-27T11:00:00", created_at: "2026-10-27T10:00:00",
  };
  const host = (ip: string, family: string | null, label: string, guess: string | null, source: string | null) => ({
    host: ip, os_guess: guess, os_family: family, os_family_label: label, os_source: source, os_accuracy: source === "ssh" ? 100 : 95,
    run_ids: [1], services_run_id: 1, services: [],
  });
  mockApi({
    "GET /me": me(["operator"], OPERATOR),
    "GET /engagements": [ENG],
    "GET /engagements/1/runs": [run],
    "GET /engagements/1/hosts": [
      host("10.0.0.1", "astra", "Astra Linux", "Astra Linux SE 1.7", "ssh"),
      host("10.0.0.2", "windows", "Windows", "Microsoft Windows Server 2016", "nmap"),
      host("10.0.0.3", "astra", "Astra Linux", "Astra Linux CE 2.12", "ssh"),
      host("10.0.0.4", null, "ОС не определена", null, null),
    ],
    "GET /runs/1/findings": [finding({ host: "10.0.0.2", severity: "high" })],
  });
  renderApp("/hosts");
  const links = () => screen.getAllByRole("link").filter((a) => a.closest("tbody")).map((a) => a.textContent);
  await screen.findByRole("link", { name: "10.0.0.1" });
  expect(screen.getByText("Astra Linux SE 1.7")).toBeInTheDocument();

  const filter = screen.getByRole("group", { name: "Фильтр по ОС" });
  // чипы — в порядке групп: Astra первой, «не определена» последней
  expect(within(filter).getAllByRole("button").map((b) => b.textContent)).toEqual(["Astra Linux 2", "Windows 1", "ОС не определена 1"]);
  fireEvent.click(within(filter).getByRole("button", { name: /Astra Linux/ }));
  expect(links()).toEqual(["10.0.0.1", "10.0.0.3"]);
  fireEvent.click(within(filter).getByRole("button", { name: "Все ОС" }));
  expect(links()).toHaveLength(4);

  fireEvent.click(screen.getByRole("checkbox", { name: "По ОС" }));
  const groups = screen.getAllByRole("rowgroup").filter((g) => g.tagName === "TBODY");
  expect(groups.map((g) => g.getAttribute("aria-label"))).toEqual(["Astra Linux", "Windows", "ОС не определена"]);
  expect(within(groups[0]).getByText("2 хоста")).toBeInTheDocument();
  expect(localStorage.getItem("scanner.hosts.byOs")).toBe("1");
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

describe("журнал аудита", () => {
  const ROW = { id: 7, ts: "2026-10-02T08:30:00+00:00", subject: "scanner", action: "deny", target: "10.9.9.9", result: "not_in_allowlist", details: null };

  it("выгружает CSV с выбранными действиями и периодом", async () => {
    setToken("t");
    const urls: URL[] = [];
    const created = vi.fn(() => "blob:x");
    URL.createObjectURL = created;
    URL.revokeObjectURL = vi.fn();
    vi.spyOn(HTMLAnchorElement.prototype, "click").mockImplementation(() => {});
    mockApi({
      "GET /me": me(["auditor"], ["view_engagements", "view_report", "view_audit"]),
      "GET /engagements": [ENG],
      "GET /audit": [ROW],
      "GET /audit/actions": ["deny", "custom_action"],
      "GET /audit/export": (_init: RequestInit | undefined, url: URL) => {
        urls.push(url);
        return new Response("id,ts\r\n", { status: 200, headers: { "Content-Type": "text/csv" } });
      },
    });
    renderApp("/audit");
    expect(await screen.findByText("Цель отклонена (вне allowlist)", { selector: "td" })).toBeInTheDocument();

    await userEvent.click(screen.getByText(/Действия: все/));
    const group = screen.getByRole("group", { name: "Действия" });
    await userEvent.click(within(group).getByRole("button", { name: "Цель отклонена (вне allowlist)" }));
    await userEvent.click(await within(group).findByRole("button", { name: "custom_action" }));
    expect(screen.getByText(/Действия: выбрано 2/)).toBeInTheDocument();
    fireEvent.change(screen.getByLabelText("С"), { target: { value: "2026-10-01T10:00" } });

    await userEvent.click(screen.getByRole("button", { name: "Выгрузить журнал CSV" }));
    await waitFor(() => expect(urls).toHaveLength(1));
    const q = urls[0].searchParams;
    expect(q.get("format")).toBe("csv");
    expect(q.getAll("action")).toEqual(["deny", "custom_action"]);
    expect(q.get("since")).toBe(new Date("2026-10-01T10:00").toISOString());
    expect(q.has("until")).toBe(false);
    await waitFor(() => expect(created).toHaveBeenCalled());
  });

  it("не даёт выгрузить при перевёрнутом периоде", async () => {
    setToken("t");
    mockApi({
      "GET /me": me(["auditor"], ["view_engagements", "view_report", "view_audit"]),
      "GET /engagements": [ENG],
      "GET /audit": [],
      "GET /audit/actions": [],
    });
    renderApp("/audit");
    await screen.findByText("Записей нет");
    fireEvent.change(screen.getByLabelText("С"), { target: { value: "2026-10-05T10:00" } });
    fireEvent.change(screen.getByLabelText("По"), { target: { value: "2026-10-01T10:00" } });
    expect(screen.getByText("Начало периода должно быть раньше конца.")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Выгрузить журнал JSON" })).toBeDisabled();
  });
});

it("повторно занесённая цель не дублируется в allowlist и подсвечивает существующую запись", async () => {
  setToken("t");
  const entry = { id: 3, cidr: "10.0.0.0/24", note: "ДМЗ", added_by: 1, added_at: null };
  const { calls } = mockApi({
    "GET /me": me(["admin"], ADMIN),
    "GET /engagements": [ENG],
    "GET /engagements/1": ENG,
    "GET /engagements/1/runs": [],
    "GET /engagements/1/allowlist": [entry],
    "POST /engagements/1/allowlist": () =>
      new Response(
        JSON.stringify({
          detail: {
            message: "10.0.0.5/32 уже входит в подсеть 10.0.0.0/24 из allowlist",
            code: "allowlist_duplicate",
            cidr: "10.0.0.5/32",
            existing_id: 3,
            existing_cidr: "10.0.0.0/24",
          },
        }),
        { status: 409, headers: { "Content-Type": "application/json" } },
      ),
  });
  renderApp("/engagements/1");
  await userEvent.type(await screen.findByPlaceholderText("10.0.0.0/24"), "10.0.0.5");
  await userEvent.click(screen.getByRole("button", { name: /Добавить/ }));
  expect(await screen.findByText(/уже входит в подсеть 10\.0\.0\.0\/24/)).toBeInTheDocument();
  const row = screen.getByText("ДМЗ").closest("tr")!;
  expect(row).toHaveClass("selected");
  expect(calls.filter((c) => c.method === "POST")).toHaveLength(1);
  expect(screen.getAllByRole("row")).toHaveLength(2); // заголовок + одна запись
});

describe("проверка доступности хоста на странице договора", () => {
  function open(roles: string[], perms: string[]) {
    setToken("t");
    mockApi({
      "GET /me": me(roles, perms),
      "GET /engagements": [ENG],
      "GET /engagements/1": ENG,
      "GET /engagements/1/runs": [],
      "GET /engagements/1/allowlist": [{ id: 1, cidr: "10.0.0.0/24", note: null, added_by: 1, added_at: null }],
    });
    renderApp("/engagements/1");
  }

  it("видна оператору", async () => {
    open(["operator"], OPERATOR);
    expect(await screen.findByRole("heading", { name: "Проверка доступности хоста" })).toBeInTheDocument();
  });

  it("скрыта от администратора (не сканирует)", async () => {
    open(["admin"], ADMIN);
    expect(await screen.findByRole("heading", { name: "Периметр" })).toBeInTheDocument();
    expect(screen.queryByRole("heading", { name: "Проверка доступности хоста" })).not.toBeInTheDocument();
  });
});

describe("расписания", () => {
  const SCHED = {
    id: 3, engagement_id: 1, name: null, title: "Обнаружение + Nuclei · 10.0.0.0/24", targets: ["10.0.0.0/24"], modules: ["discovery", "vuln"],
    rate_profile: "gentle", credential_ids: [], kind: "weekly", time_of_day: "22:00", weekdays: [0, 4], month_day: null, run_at: null,
    timezone: "Europe/Moscow", enabled: true, next_run_at: "2026-10-30T19:00:00Z", last_run_at: "2026-10-27T19:00:00Z",
    last_result: "skipped_overlap", last_run_id: 7, owner_id: 1, created_at: null,
  };

  it("список показывает имя по опциям, периодичность и итог последнего запуска", async () => {
    setToken("t");
    mockApi({ "GET /me": me(["operator"], OPERATOR), "GET /engagements": [ENG], "GET /engagements/1/schedules": [SCHED] });
    renderApp("/schedules");
    expect(await screen.findByText("Обнаружение + Nuclei · 10.0.0.0/24")).toBeInTheDocument();
    expect(screen.getByText("Пн, Пт в 22:00")).toBeInTheDocument();
    expect(screen.getByText("Пропущен: предыдущий прогон ещё идёт")).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "прогон №7" })).toHaveAttribute("href", "/runs/7");
  });

  it("форма создаёт расписание по дням недели", async () => {
    setToken("t");
    const api = mockApi({
      "GET /me": me(["operator"], OPERATOR),
      "GET /engagements": [ENG],
      "GET /engagements/1/schedules": [],
      "GET /engagements/1/allowlist": [{ id: 1, cidr: "10.0.0.0/24", note: null, added_by: 1, added_at: null }],
      "POST /engagements/1/schedules": SCHED,
    });
    renderApp("/schedules");
    await userEvent.click(await screen.findByRole("button", { name: /Новое расписание/ }));
    const dlg = await screen.findByRole("dialog", { name: "Новое расписание" });
    await userEvent.click(within(dlg).getByRole("button", { name: /Подставить весь allowlist/ }));
    expect(within(dlg).getByPlaceholderText("Обнаружение + Nuclei · 10.0.0.0/24")).toBeInTheDocument();
    await userEvent.click(within(dlg).getByRole("button", { name: "По дням недели" }));
    await userEvent.click(within(dlg).getByRole("button", { name: "Пт" }));
    fireEvent.change(within(dlg).getByLabelText("Время"), { target: { value: "22:00" } });
    await userEvent.click(within(dlg).getByRole("checkbox", { name: /Подтверждаю/ }));
    const submit = screen.getByRole("button", { name: "Запланировать" });
    await waitFor(() => expect(submit).toBeEnabled());
    await userEvent.click(submit);
    await waitFor(() => expect(api.calls.some((c) => c.path === "/engagements/1/schedules" && c.init?.method === "POST")).toBe(true));
    const call = api.calls.find((c) => c.path === "/engagements/1/schedules" && c.init?.method === "POST")!;
    const sent = JSON.parse(String(call.init!.body));
    expect(sent).toMatchObject({ kind: "weekly", weekdays: [0, 4], time_of_day: "22:00", targets: ["10.0.0.0/24"], modules: ["discovery", "vuln"] });
    expect(sent.name).toBeUndefined();
    expect(sent.timezone).toBeTruthy();
    expect(await screen.findByText(/Расписание «Обнаружение \+ Nuclei · 10.0.0.0\/24» сохранено/)).toBeInTheDocument();
  });
});
