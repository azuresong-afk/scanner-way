import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { App } from "./App";
import { setToken } from "./api/client";
import { AuthProvider } from "./auth/AuthContext";
import { ThemeProvider } from "./theme/ThemeContext";
import { ADMIN, OPERATOR, finding, me, mockApi, summaryOf } from "./test/fixtures";

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
  expect(await screen.findByRole("heading", { name: "Сводка по проекту" })).toBeInTheDocument();
  const meCall = api.calls.find((c) => c.path === "/me");
  expect(new Headers(meCall?.init?.headers).get("Authorization")).toBe("Bearer tok123");
});

it("меню зависит от прав: оператор не видит администрирование", async () => {
  setToken("t");
  mockApi({ "GET /me": me(["operator"], OPERATOR), "GET /engagements": [ENG], "GET /engagements/1/runs": [] });
  renderApp("/");
  const nav = await screen.findByRole("navigation", { name: "Основное меню" });
  await within(nav).findByText("Сканирование");
  expect(within(nav).queryByText("Пользователи и роли")).not.toBeInTheDocument();
  expect(within(nav).queryByText("Журнал аудита")).not.toBeInTheDocument();
});

it("меню идёт сверху вниз по ходу работы, служебные разделы — в «Администрировании»", async () => {
  setToken("t");
  mockApi({ "GET /me": me(["admin", "operator"], [...new Set([...ADMIN, ...OPERATOR])]), "GET /engagements": [ENG], "GET /engagements/1/runs": [] });
  renderApp("/");
  const nav = await screen.findByRole("navigation", { name: "Основное меню" });
  await within(nav).findByText("Сканирование");
  const links = within(nav).getAllByRole("link").map((a) => [a.textContent, a.getAttribute("href")]);
  expect(links.slice(0, 9)).toEqual([
    ["Сводка", "/"],
    ["Проекты", "/engagements"],
    ["Активы", "/hosts"],
    ["Находки", "/findings"],
    ["Сетевой поиск", "/reachability"],
    ["Сканирование", "/runs"],
    ["Расписание", "/schedules"],
    ["Соответствие нормативам", "/compliance"],
    ["Отчёты", "/reports"],
  ]);
  expect(within(nav).getByText("Администрирование")).toBeInTheDocument();
  expect(links.slice(9).map(([t]) => t)).toEqual(expect.arrayContaining(["Справочники", "Журнал аудита", "Пользователи и роли"]));
  expect(screen.getByRole("combobox", { name: "Проект" })).toBeInTheDocument(); // выбор проекта в шапке, без видимой подписи
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
  protocol: "ssh",
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
      "POST /engagements/1/runs": { id: 9, engagement_id: 1, modules: [], rate_profile: "gentle", credential_ids: [5], cred_set_ids: [], status: "pending",
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
    expect(sent.modules).toEqual(["discovery", "auth_inventory", "win_inventory", "netdev_audit"]);
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

  it("цели: выбор хостов из активов и записей allowlist, диапазоны уходят в запрос", async () => {
    const host = (h: string) => ({ host: h, os_guess: null, os_family: "debian", os_family_label: "Debian", run_ids: [1], services_run_id: 1, packages_run_id: null, package_count: 0, services: [] });
    const { dlg, api } = await openForm(OPERATOR, {
      "GET /engagements/1/allowlist": [
        { id: 1, cidr: "10.0.0.0/24", note: null, added_by: 1, added_at: null, range_spec: null },
        { id: 2, cidr: "10.0.5.1/32", note: null, added_by: 1, added_at: null, range_spec: "10.0.5.1-10.0.5.3" },
        { id: 3, cidr: "10.0.5.2/31", note: null, added_by: 1, added_at: null, range_spec: "10.0.5.1-10.0.5.3" },
      ],
      "GET /engagements/1/hosts": ["10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.9", "10.9.9.9"].map(host),
      "GET /engagements/1/assets": [],
      "GET /engagements/1/asset-groups": [],
      "GET /engagements/1/asset-tags": [],
      "POST /engagements/1/runs": { id: 9, engagement_id: 1, modules: [], rate_profile: "gentle", credential_ids: [], cred_set_ids: [], status: "pending",
        started_by: 1, started_at: null, finished_at: null, created_at: null, accepted_targets: 7, denied_targets: [] },
    });
    // запись-диапазон allowlist — одна кнопка
    await userEvent.click(await within(dlg).findByRole("button", { name: "10.0.5.1-10.0.5.3" }));
    await userEvent.click(within(dlg).getByRole("button", { name: /Выбрать хосты из активов/ }));
    const picker = await screen.findByRole("dialog", { name: "Цели прогона из активов" });
    expect(await within(picker).findByRole("checkbox", { name: "Выбрать 10.9.9.9" })).toBeDisabled();
    await userEvent.click(within(picker).getByRole("button", { name: /Выбрать все \(4\)/ }));
    await userEvent.click(within(picker).getByRole("button", { name: "Добавить в цели (4)" }));
    const form = await screen.findByRole("dialog", { name: "Новый прогон" });
    const box = within(form).getByRole("textbox", { name: /Цели/ });
    expect(box).toHaveValue("10.0.5.1-10.0.5.3\n10.0.0.1-10.0.0.3\n10.0.0.9");
    expect(within(form).getByText(/3 записей · до 7 адресов/)).toBeInTheDocument();
    await userEvent.click(within(form).getByRole("checkbox", { name: /Подтверждаю/ }));
    await userEvent.click(screen.getByRole("button", { name: "Запустить" }));
    await waitFor(() => expect(api.calls.some((c) => c.path === "/engagements/1/runs" && c.method === "POST")).toBe(true));
    const sent = JSON.parse(String(api.calls.find((c) => c.path === "/engagements/1/runs" && c.method === "POST")!.init!.body));
    expect(sent.targets).toEqual(["10.0.5.1-10.0.5.3", "10.0.0.1-10.0.0.3", "10.0.0.9"]);
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

it("сводка: новый вид с «Главное» и графиком по прогонам, прежний — по переключателю", async () => {
  setToken("t");
  const run = (id: number) => ({
    id, engagement_id: 1, modules: ["discovery", "vuln"], rate_profile: "gentle", status: "done",
    started_by: 1, started_at: "2026-10-27T10:00:00", finished_at: "2026-10-27T11:00:00", created_at: "2026-10-27T10:00:00",
  });
  const log4j = finding({ severity: "critical", title: "Log4Shell" });
  const run2 = [log4j, finding({ host: "10.0.0.2", vuln_id: "X", cve_ids: [], bdu_ids: [], severity: "medium", status: "new", title: "TLS 1.0" })];
  mockApi({
    "GET /me": me(["operator"], OPERATOR),
    "GET /engagements": [ENG],
    "GET /engagements/1/runs": [run(1), run(2)],
    "GET /runs/1/findings": [log4j, finding({ vuln_id: "CVE-2017-0144", cve_ids: ["CVE-2017-0144"], title: "EternalBlue" })],
    "GET /runs/2/findings": run2,
    // «Закрытые» сервер считает по прошлому успешному прогону (EternalBlue исчезла)
    "GET /runs/2/findings/summary": { ...summaryOf(run2), fixed: 1, previous_run_id: 1 },
    "GET /runs/1/services": [],
    "GET /runs/2/services": [],
    "GET /runs/2/fixes": {
      total: 2, tasks: 2, hosts: 2, findings: 2, false_positives: 0, kinds: {}, os: {}, severities: {},
      items: [
        {
          key: "pkg:log4j", kind: "package", kind_label: "Обновить пакет", title: "Обновить log4j", os: null, os_family: null,
          manager: null, packages: ["log4j"], fixed_version: "2.17.1", software: null, steps: [], commands: [], verify: [],
          reboot: false, details: null, details_source: null, severity: "critical",
          priority: { score: 97, label: "critical", label_ru: "Критический", rank: 1 },
          cves: ["CVE-2021-44228"], bdu_ids: ["BDU:2021-05969"], advisories: [], references: [], hosts: [],
          host_count: 1, finding_count: 1,
        },
      ],
    },
    "GET /engagements/1/assets": [{ id: 1, engagement_id: 1, address: "10.0.0.1", hostname: "astra-db01", os_family_label: "Astra Linux" }],
    "GET /runs/2/events": [
      { id: 9, ts: "2026-10-27T11:00:00", kind: "run_finish", subject: "Прогон", host: null, severity: null, message: "завершён, открытых 2, новых 1, закрыто 1" },
      { id: 8, ts: "2026-10-27T10:59:00", kind: "host_new", subject: "10.0.0.2", host: "10.0.0.2", severity: "medium", message: "новых уязвимостей: 1 · TLS 1.0" },
      { id: 7, ts: "2026-10-27T10:30:00", kind: "module_finish", subject: "Уязвимости ПО", host: null, severity: null, message: "готов: 2 находки" },
    ],
    // за год — 30 еженедельных прогонов: столбцы по месяцам
    "GET /engagements/1/trend": (_: unknown, url: URL) =>
      url.searchParams.get("days") === "365"
        ? Array.from({ length: 30 }, (_, i) => ({
            scan_run_id: i + 1, status: "done", finished_at: null,
            started_at: new Date(Date.UTC(2026, 3, 6, 12) + i * 7 * 86_400_000).toISOString(),
            counts: { critical: 1, high: 2, medium: 3, low: 30 - i },
          }))
        : [],
  });
  renderApp("/");
  await screen.findByRole("heading", { name: "Сводка по проекту" });
  expect(await screen.findByText("открытые уязвимости на 2 хостах")).toBeInTheDocument();
  expect(screen.getByText("без изменений к прогону №1")).toBeInTheDocument();

  // новый вид («Сводка 2.0»): «Главное», крупные плитки уровней, первые действия, график столбцами
  expect(await screen.findByText(/первым стоит сделать «Обновить log4j»: закроет 1 находку на 1 хосте\. Новых уязвимостей: 1\./)).toBeInTheDocument();
  expect(screen.getByRole("button", { name: /^Критический: 1, 50% открытых/ })).toBeInTheDocument();
  expect(screen.getByRole("link", { name: "Обновить log4j" })).toHaveAttribute("href", "/findings?run=2&q=%D0%9E%D0%B1%D0%BD%D0%BE%D0%B2%D0%B8%D1%82%D1%8C%20log4j");
  const cols = screen.getByRole("list", { name: "Открытые уязвимости по уровням в каждом прогоне" });
  expect(within(cols).getAllByRole("listitem")).toHaveLength(2);
  expect(screen.getByText("astra-db01")).toBeInTheDocument();

  // лента последнего прогона: новые сверху, хост — ссылкой на его карточку
  expect(screen.getByRole("heading", { name: "Лента прогона №2" })).toBeInTheDocument();
  const feed = await screen.findByRole("list", { name: "События прогона №2, новые сверху" });
  const rows = within(feed).getAllByRole("listitem");
  expect(rows.map((r) => r.textContent)).toEqual([
    expect.stringContaining("Прогон завершён, открытых 2, новых 1, закрыто 1"),
    expect.stringContaining("10.0.0.2 новых уязвимостей: 1 · TLS 1.0"),
    expect.stringContaining("Уязвимости ПО готов: 2 находки"),
  ]);
  expect(within(rows[1]).getByRole("link", { name: "10.0.0.2" })).toHaveAttribute("href", "/hosts/10.0.0.2?run=2");

  // период графика: за год — одним запросом, столбцы по месяцам
  expect(screen.getByText(/^За 2 прогона:/)).toBeInTheDocument();
  await userEvent.click(screen.getByRole("radio", { name: "Год" }));
  expect(await screen.findByText(/^За год \(30 прогонов, по месяцам\):/)).toBeInTheDocument();
  const months = screen.getByRole("list", { name: "Открытые уязвимости по уровням в каждом прогоне" });
  expect(within(months).getAllByRole("listitem")).toHaveLength(7);
  await userEvent.click(screen.getByRole("radio", { name: "3 месяца" }));
  expect(await screen.findByText("За этот период меньше двух прогонов")).toBeInTheDocument();
  await userEvent.click(screen.getByRole("radio", { name: "10 прогонов" }));
  expect(screen.getByText(/^За 2 прогона:/)).toBeInTheDocument();

  // плиток «Новые / Закрытые / Регрессии» и матрицы риска в новом виде нет
  expect(screen.queryByText("Регрессии")).not.toBeInTheDocument();
  expect(screen.queryByText("Матрица риска")).not.toBeInTheDocument();

  // прежний вид оставлен: переключатель на странице, выбор запоминается
  await userEvent.click(screen.getByRole("radio", { name: "Прежний" }));
  expect(localStorage.getItem("scanner.summaryLook")).toBe("classic");
  expect(screen.queryByText(/^Главное:/)).not.toBeInTheDocument();
  const tile = (label: string) => screen.getByText(label).closest(".change-tile") as HTMLElement;
  expect(within(tile("Новые")).getByText("1")).toBeInTheDocument();
  expect(within(tile("Закрытые")).getByText("1")).toBeInTheDocument();
  expect(within(tile("Регрессии")).getByText("0")).toBeInTheDocument();
  // сводка разгружена: ни кнопок отчёта, ни запуска прогона сверху
  expect(screen.queryByRole("button", { name: /Новый прогон/ })).not.toBeInTheDocument();
  expect(screen.queryByRole("button", { name: /Скачать отчёт/ })).not.toBeInTheDocument();
  expect(screen.queryByRole("radiogroup", { name: "Версия отчёта" })).not.toBeInTheDocument();
});

it("вкладка «Активы»: по умолчанию последние данные каждого хоста, прогон — только его хосты", async () => {
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
      { host: "10.0.0.1", os_guess: null, run_ids: [1, 2], services_run_id: 2, services: [{ host: "10.0.0.1", ...ssh }],
        latest_counts: { high: 1 }, latest_total: 1, latest_run_ids: [2], checked_run_id: 2 },
      // в прогон №2 не входил — последние данные из №1
      { host: "10.0.0.2", os_guess: null, run_ids: [1], services_run_id: 1, services: [{ host: "10.0.0.2", ...ssh }],
        latest_counts: { medium: 1 }, latest_total: 1, latest_run_ids: [1], checked_run_id: 1 },
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
  const hostLinks = () => screen.getAllByRole("link").filter((a) => a.closest("tbody"));

  // по умолчанию — «Последние данные»: оба хоста со своими последними уязвимостями
  await screen.findByText(/последние известные уязвимости/);
  expect(screen.getByRole("combobox", { name: "Прогон" })).toHaveValue("");
  expect(await vulns("10.0.0.1")).toBe("1");
  expect(await vulns("10.0.0.2")).toBe("1");
  expect(within(await row("10.0.0.2")).getByText("по прогону №1")).toBeInTheDocument();
  expect((await screen.findByRole("link", { name: "10.0.0.2" })).getAttribute("href")).toBe("/hosts/10.0.0.2");

  // выбран прогон №2 — только его хосты и его находки
  fireEvent.change(screen.getByRole("combobox", { name: "Прогон" }), { target: { value: "2" } });
  await screen.findByText(/в прогоне №2 · всего в договоре 2/);
  await waitFor(() => expect(hostLinks().map((a) => a.textContent)).toEqual(["10.0.0.1"]));
  expect((await screen.findByRole("link", { name: "10.0.0.1" })).getAttribute("href")).toBe("/hosts/10.0.0.1?run=2");

  fireEvent.change(screen.getByRole("combobox", { name: "Прогон" }), { target: { value: "1" } });
  await screen.findByText(/в прогоне №1/);
  await waitFor(async () => expect(await vulns("10.0.0.1")).toBe("2"));
  expect(await vulns("10.0.0.2")).toBe("1");
  expect(hostLinks()).toHaveLength(2);

  // назад к последним данным
  fireEvent.change(screen.getByRole("combobox", { name: "Прогон" }), { target: { value: "" } });
  await waitFor(async () => expect(await vulns("10.0.0.1")).toBe("1"));
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
  expect(within(groups[0]).getByText("2 актива")).toBeInTheDocument();
  expect(localStorage.getItem("scanner.hosts.byOs")).toBe("1");
});

it("переключает светлую и тёмную тему и запоминает выбор", async () => {
  setToken("t");
  mockApi({ "GET /me": me(["operator"], OPERATOR), "GET /engagements": [ENG], "GET /engagements/1/runs": [] });
  renderApp("/");
  const html = document.documentElement;
  await screen.findByRole("heading", { name: "Сводка по проекту" });
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

it("allowlist: диапазоны и несколько целей добавляются одним действием, диапазон — одна строка", async () => {
  setToken("t");
  let list: unknown[] = [{ id: 1, cidr: "10.0.0.0/24", note: null, added_by: 1, added_at: null, range_spec: null }];
  const { calls, fn } = mockApi({
    "GET /me": me(["admin"], ADMIN),
    "GET /engagements": [ENG],
    "GET /engagements/1": ENG,
    "GET /engagements/1/runs": [],
    "GET /engagements/1/allowlist": () => list,
    "POST /engagements/1/allowlist/bulk": () => {
      const added = [
        { id: 2, cidr: "10.0.5.1/32", note: "ДМЗ-2", added_by: 1, added_at: null, range_spec: "10.0.5.1-10.0.5.3" },
        { id: 3, cidr: "10.0.5.2/31", note: "ДМЗ-2", added_by: 1, added_at: null, range_spec: "10.0.5.1-10.0.5.3" },
      ];
      list = [...list, ...added];
      return new Response(JSON.stringify({ added, skipped: [{ item: "10.0.0.7/32", reason: "duplicate", existing_cidr: "10.0.0.0/24" }], partial: [] }), {
        status: 201,
        headers: { "Content-Type": "application/json" },
      });
    },
    "DELETE /engagements/1/allowlist/2": () => new Response(null, { status: 204 }),
  });
  renderApp("/engagements/1");
  await userEvent.type(await screen.findByPlaceholderText("10.0.0.0/24"), "10.0.5.1 - 3, 10.0.0.7");
  await userEvent.type(screen.getByPlaceholderText(/ДМЗ/), "ДМЗ-2");
  await userEvent.click(screen.getByRole("button", { name: /^Добавить$/ }));
  expect(await screen.findByText(/Добавлено записей: 1; уже в allowlist: 10\.0\.0\.7\/32 \(входит в 10\.0\.0\.0\/24\)/)).toBeInTheDocument();
  const post = calls.find((c) => c.method === "POST")!;
  expect(JSON.parse(String(post.init!.body))).toEqual({ items: ["10.0.5.1-3", "10.0.0.7"], note: "ДМЗ-2" });
  expect(await screen.findByText("10.0.5.1-10.0.5.3")).toBeInTheDocument();
  expect(screen.getByText(/диапазон · 3 адресов/)).toBeInTheDocument();
  expect(screen.getAllByRole("row")).toHaveLength(3); // заголовок + /24 + диапазон одной строкой
  await userEvent.click(screen.getByRole("button", { name: "Удалить 10.0.5.1-10.0.5.3" }));
  await waitFor(() => expect(calls.some((c) => c.method === "DELETE" && c.path === "/engagements/1/allowlist/2")).toBe(true));
  // диапазон удаляется целиком
  expect(fn.mock.calls.map(([u]) => String(u)).find((u) => u.includes("/allowlist/2"))).toMatch(/whole_range=true$/);
});

describe("вкладка «Сетевой поиск» (бывшая «Доступность»)", () => {
  function open(roles: string[], perms: string[], path: string) {
    setToken("t");
    mockApi({
      "GET /me": me(roles, perms),
      "GET /engagements": [ENG],
      "GET /engagements/1": ENG,
      "GET /engagements/1/runs": [],
      "GET /engagements/1/port-scans": [],
      "GET /engagements/1/allowlist": [{ id: 1, cidr: "10.0.0.0/24", note: null, added_by: 1, added_at: null }],
    });
    renderApp(path);
  }

  it("оператор видит пункт меню и форму проверки", async () => {
    open(["operator"], OPERATOR, "/reachability");
    expect(await screen.findByRole("heading", { name: "Сетевой поиск" })).toBeInTheDocument();
    expect(screen.getByRole("link", { name: /Сетевой поиск/ })).toHaveAttribute("href", "/reachability");
    expect(await screen.findByRole("form", { name: "Новая проверка доступности" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "10.0.0.0/24" })).toBeInTheDocument();
  });

  it("страница договора без прогонов: нет кнопки запуска и списка прогонов", async () => {
    open(["operator"], OPERATOR, "/engagements/1");
    await screen.findByRole("heading", { name: "Allowlist — разрешённые цели" });
    expect(screen.queryByRole("button", { name: /Новый прогон/ })).not.toBeInTheDocument();
    expect(screen.queryByRole("heading", { name: "Прогоны по договору" })).not.toBeInTheDocument();
  });

  it("на странице договора проверки больше нет", async () => {
    open(["operator"], OPERATOR, "/engagements/1");
    expect(await screen.findByRole("heading", { name: "Периметр" })).toBeInTheDocument();
    expect(screen.queryByRole("heading", { name: "Проверка доступности хоста" })).not.toBeInTheDocument();
  });
});

describe("расписания", () => {
  const SCHED = {
    id: 3, engagement_id: 1, name: null, title: "Обнаружение + Nuclei · 10.0.0.0/24", targets: ["10.0.0.0/24"], modules: ["discovery", "vuln"],
    rate_profile: "gentle", credential_ids: [], cred_set_ids: [], kind: "weekly", time_of_day: "22:00", weekdays: [0, 4], month_day: null, run_at: null,
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

it("находки: фильтры и страницы — на сервере, состояние в адресе", async () => {
  setToken("t");
  const run = { id: 3, engagement_id: 1, modules: ["vuln"], rate_profile: "gentle", status: "done", targets: [], schedule_id: null,
    started_by: 1, started_at: "2026-10-27T10:00:00", finished_at: "2026-10-27T11:00:00", created_at: "2026-10-27T10:00:00" };
  const page = Array.from({ length: 50 }, (_, i) => finding({ host: `10.0.0.${i + 1}`, vuln_id: `CVE-2024-${i}`, title: `Уязвимость ${i}` }));
  const api = mockApi({
    "GET /me": me(["operator"], OPERATOR),
    "GET /engagements": [ENG],
    "GET /engagements/1/runs": [run],
    "GET /runs/3/findings": () => new Response(JSON.stringify(page), { status: 200, headers: { "Content-Type": "application/json", "X-Total-Count": "120" } }),
    "GET /runs/3/findings/summary": { ...summaryOf(page), counts: { critical: 0, high: 120, medium: 0, low: 0, info: 0 } },
  });
  renderApp("/findings?view=all&run=3&sev=high&page=2");
  expect(await screen.findByText("Показано 51–100 из 120")).toBeInTheDocument();
  const lastQuery = () =>
    api.fn.mock.calls.map((c) => new URL(String(c[0]), "http://x")).filter((u) => u.pathname.endsWith("/runs/3/findings")).at(-1)!.searchParams;
  const q = lastQuery();
  expect(q.getAll("severity")).toEqual(["high"]);
  expect(q.get("offset")).toBe("50");
  expect(q.get("limit")).toBe("50");
  expect(q.get("false_positives")).toBe("exclude");
  expect(q.get("sort")).toBe("severity");
  await userEvent.click(screen.getByRole("button", { name: "Следующая страница" }));
  await waitFor(() => expect(lastQuery().get("offset")).toBe("100"));
});
