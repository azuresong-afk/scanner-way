import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { CredentialsCard } from "./CredentialsCard";
import { mockApi } from "../test/fixtures";

afterEach(() => vi.unstubAllGlobals());

const ROW = {
  id: 3, engagement_id: 7, name: "root ДМЗ", username: "audit", auth: "password", port: 22,
  targets: [], key_fingerprint: null, created_by: 1, created_at: null, become: "none",
  protocol: "ssh",
};

it("показывает повышение прав и отправляет выбранный режим", async () => {
  const api = mockApi({
    "GET /engagements/7/credentials": [ROW],
    "POST /engagements/7/credentials": { ...ROW, id: 4, become: "sudo" },
  });
  render(<CredentialsCard engagementId={7} />);
  const row = (await screen.findByText("root ДМЗ")).closest("tr")!;
  expect(within(row).getByText("нет")).toBeInTheDocument();

  await userEvent.click(screen.getByRole("button", { name: /Добавить/ }));
  const dlg = await screen.findByRole("dialog");
  expect(within(dlg).getByRole("radio", { name: /sudo/ })).toBeChecked();      // по умолчанию
  expect(within(dlg).getByText(/через stdin/)).toBeInTheDocument();
  await userEvent.type(within(dlg).getByLabelText("Название"), "Аудит");
  await userEvent.type(within(dlg).getByLabelText("Логин на хосте"), "audit");
  await userEvent.type(within(dlg).getByLabelText("Пароль", { selector: "input[type=password]" }), "secret-pass");
  await userEvent.click(within(dlg).getByRole("radio", { name: /Нет/ }));
  await userEvent.click(screen.getByRole("button", { name: "Сохранить" }));
  await waitFor(() => expect(api.calls.some((c) => c.init?.method === "POST")).toBe(true));
  const sent = JSON.parse(String(api.calls.find((c) => c.init?.method === "POST")!.init!.body));
  expect(sent).toMatchObject({ name: "Аудит", username: "audit", auth: "password", become: "none" });
});

it("заводит учётку WinRM с доменом и портом по умолчанию 5986", async () => {
  const WIN = { ...ROW, id: 5, name: "Windows ДМЗ", username: "CORP\\svc", port: 5986, protocol: "winrm" };
  const api = mockApi({
    "GET /engagements/7/credentials": [],
    "POST /engagements/7/credentials": WIN,
  });
  render(<CredentialsCard engagementId={7} />);
  await userEvent.click(screen.getByRole("button", { name: /Добавить/ }));
  const dlg = await screen.findByRole("dialog");
  await userEvent.click(within(dlg).getByRole("radio", { name: /WinRM/ }));
  // порт переключился на 5986, выбор ключа SSH и повышения прав скрыты
  expect((within(dlg).getByLabelText("Порт WinRM") as HTMLInputElement).value).toBe("5986");
  expect(within(dlg).queryByRole("radio", { name: /Ключ SSH/ })).toBeNull();
  expect(within(dlg).queryByRole("radio", { name: /sudo/ })).toBeNull();
  await userEvent.type(within(dlg).getByLabelText("Название"), "Windows ДМЗ");
  await userEvent.type(within(dlg).getByLabelText("Логин Windows"), "svc");
  await userEvent.type(within(dlg).getByLabelText(/Домен Windows/), "CORP");
  await userEvent.type(within(dlg).getByLabelText("Пароль Windows", { selector: "input[type=password]" }), "win-pass");
  await userEvent.click(screen.getByRole("button", { name: "Сохранить" }));
  await waitFor(() => expect(api.calls.some((c) => c.init?.method === "POST")).toBe(true));
  const sent = JSON.parse(String(api.calls.find((c) => c.init?.method === "POST")!.init!.body));
  expect(sent).toMatchObject({ protocol: "winrm", domain: "CORP", auth: "password", port: 5986, become: "none" });
});

it("заводит учётку СУБД: Oracle требует имя сервиса, порт 1521, без sudo", async () => {
  const ORA = { ...ROW, id: 6, name: "Oracle ERP", username: "scan_ro", port: 1521, protocol: "oracle", db_name: "ERPPDB" };
  const api = mockApi({
    "GET /engagements/7/credentials": [ORA],
    "POST /engagements/7/credentials": ORA,
  });
  render(<CredentialsCard engagementId={7} />);
  const row = (await screen.findByText("Oracle ERP")).closest("tr")!;
  expect(within(row).getByText("Oracle · ERPPDB")).toBeInTheDocument();

  await userEvent.click(screen.getByRole("button", { name: /Добавить/ }));
  const dlg = await screen.findByRole("dialog");
  await userEvent.click(within(dlg).getByRole("radio", { name: /СУБД/ }));
  expect((within(dlg).getByLabelText("Порт СУБД") as HTMLInputElement).value).toBe("5432");
  expect((within(dlg).getByLabelText(/^База для входа/) as HTMLInputElement).value).toBe("postgres");
  await userEvent.selectOptions(within(dlg).getByLabelText("СУБД"), "oracle");
  expect((within(dlg).getByLabelText("Порт СУБД") as HTMLInputElement).value).toBe("1521");
  expect(within(dlg).queryByRole("radio", { name: /sudo/ })).toBeNull();
  await userEvent.type(within(dlg).getByLabelText("Название"), "Oracle ERP");
  await userEvent.type(within(dlg).getByLabelText("Логин СУБД"), "scan_ro");
  await userEvent.type(within(dlg).getByLabelText("Пароль СУБД", { selector: "input[type=password]" }), "db-pass");
  expect(screen.getByRole("button", { name: "Сохранить" })).toBeDisabled();       // нет имени сервиса
  await userEvent.type(within(dlg).getByLabelText(/Имя сервиса/), "ERPPDB");
  await userEvent.click(screen.getByRole("button", { name: "Сохранить" }));
  await waitFor(() => expect(api.calls.some((c) => c.init?.method === "POST")).toBe(true));
  const sent = JSON.parse(String(api.calls.find((c) => c.init?.method === "POST")!.init!.body));
  expect(sent).toMatchObject({ protocol: "oracle", db_name: "ERPPDB", auth: "password", port: 1521, become: "none" });
});

it("заводит учётку сетевого устройства (SSH) с платформой и показывает её в таблице", async () => {
  const NET = { ...ROW, id: 6, name: "Коммутаторы", protocol: "netssh", options: { platform: "cisco_ios" } };
  const api = mockApi({
    "GET /engagements/7/credentials": [NET],
    "POST /engagements/7/credentials": NET,
  });
  render(<CredentialsCard engagementId={7} />);
  const row = (await screen.findByText("Коммутаторы")).closest("tr")!;
  expect(within(row).getByText("SSH · Cisco IOS")).toBeInTheDocument();
  await userEvent.click(screen.getByRole("button", { name: /Добавить/ }));
  const dlg = await screen.findByRole("dialog");
  await userEvent.click(within(dlg).getByRole("radio", { name: /Сетевое устройство/ }));
  expect(within(dlg).queryByRole("radio", { name: /sudo/ })).toBeNull();   // без повышения прав
  await userEvent.type(within(dlg).getByLabelText("Название"), "Коммутаторы");
  await userEvent.type(within(dlg).getByLabelText("Логин на устройстве"), "audit");
  await userEvent.selectOptions(within(dlg).getByLabelText(/Платформа устройства/), "junos");
  await userEvent.type(within(dlg).getByLabelText("Пароль", { selector: "input[type=password]" }), "net-pass");
  await userEvent.click(screen.getByRole("button", { name: "Сохранить" }));
  await waitFor(() => expect(api.calls.some((c) => c.init?.method === "POST")).toBe(true));
  const sent = JSON.parse(String(api.calls.find((c) => c.init?.method === "POST")!.init!.body));
  expect(sent).toMatchObject({ protocol: "netssh", platform: "junos", auth: "password", port: 22, become: "none" });
});

it("SNMPv3: ключи auth и priv, порт 161; v2c — только community", async () => {
  const api = mockApi({
    "GET /engagements/7/credentials": [],
    "POST /engagements/7/credentials": { ...ROW, id: 7, protocol: "snmp", port: 161 },
  });
  render(<CredentialsCard engagementId={7} />);
  await userEvent.click(screen.getByRole("button", { name: /Добавить/ }));
  const dlg = await screen.findByRole("dialog");
  await userEvent.click(within(dlg).getByRole("radio", { name: /^SNMP/ }));
  expect((within(dlg).getByLabelText("Порт SNMP (UDP)") as HTMLInputElement).value).toBe("161");
  await userEvent.type(within(dlg).getByLabelText("Название"), "SNMP ядро");
  await userEvent.type(within(dlg).getByLabelText("Пользователь SNMPv3"), "nms");
  await userEvent.type(within(dlg).getByLabelText(/Ключ аутентификации/), "authkey123");
  const save = screen.getByRole("button", { name: "Сохранить" });
  expect(save).toBeDisabled();                                   // нет ключа priv
  await userEvent.type(within(dlg).getByLabelText(/Ключ шифрования/), "privkey123");
  await waitFor(() => expect(save).toBeEnabled());
  await userEvent.click(save);
  await waitFor(() => expect(api.calls.some((c) => c.init?.method === "POST")).toBe(true));
  const sent = JSON.parse(String(api.calls.find((c) => c.init?.method === "POST")!.init!.body));
  expect(sent).toMatchObject({
    protocol: "snmp", snmp_version: "3", snmp_auth_proto: "sha", snmp_priv_proto: "aes",
    username: "nms", password: "authkey123", passphrase: "privkey123", port: 161,
  });
});

it("правит учётку без повторного ввода пароля", async () => {
  const WIN = { ...ROW, id: 8, name: "Windows ДМЗ", username: "CORP\\svc", port: 5986, protocol: "winrm", targets: ["10.0.0.0/24"] };
  const api = mockApi({
    "GET /engagements/7/credentials": [WIN],
    "PUT /engagements/7/credentials/8": { ...WIN, name: "Windows ДМЗ-2" },
  });
  render(<CredentialsCard engagementId={7} />);
  await userEvent.click(await screen.findByRole("button", { name: "Изменить Windows ДМЗ" }));
  const dlg = await screen.findByRole("dialog");
  // поля заполнены, домен отделён от логина, пароль пуст и не обязателен
  expect(within(dlg).getByRole("radio", { name: /WinRM/ })).toBeChecked();
  expect((within(dlg).getByLabelText("Логин Windows") as HTMLInputElement).value).toBe("svc");
  expect((within(dlg).getByLabelText(/Домен Windows/) as HTMLInputElement).value).toBe("CORP");
  expect((within(dlg).getByLabelText(/Область действия/) as HTMLTextAreaElement).value).toBe("10.0.0.0/24");
  const pass = within(dlg).getByLabelText("Пароль Windows", { selector: "input[type=password]" }) as HTMLInputElement;
  expect(pass.value).toBe("");
  expect(pass.placeholder).toMatch(/сохранён/);
  const name = within(dlg).getByLabelText("Название");
  await userEvent.clear(name);
  await userEvent.type(name, "Windows ДМЗ-2");
  await userEvent.click(screen.getByRole("button", { name: "Сохранить" }));
  await waitFor(() => expect(api.calls.some((c) => c.init?.method === "PUT")).toBe(true));
  const sent = JSON.parse(String(api.calls.find((c) => c.init?.method === "PUT")!.init!.body));
  expect(sent).toMatchObject({ name: "Windows ДМЗ-2", username: "svc", domain: "CORP", protocol: "winrm", port: 5986, targets: ["10.0.0.0/24"] });
  expect(sent).not.toHaveProperty("password");
});

it("при смене способа входа на ключ требует ключ заново", async () => {
  mockApi({ "GET /engagements/7/credentials": [ROW] });
  render(<CredentialsCard engagementId={7} />);
  await userEvent.click(await screen.findByRole("button", { name: "Изменить root ДМЗ" }));
  const dlg = await screen.findByRole("dialog");
  const save = screen.getByRole("button", { name: "Сохранить" });
  expect(save).toBeEnabled();               // пароль сохранён — можно сохранять без него
  await userEvent.click(within(dlg).getByRole("radio", { name: /Ключ SSH/ }));
  expect(within(dlg).getByText(/введите пароль или ключ заново/)).toBeInTheDocument();
  expect(save).toBeDisabled();
});
