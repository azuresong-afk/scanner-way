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
