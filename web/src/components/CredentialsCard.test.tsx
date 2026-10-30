import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { CredentialsCard } from "./CredentialsCard";
import { mockApi } from "../test/fixtures";

afterEach(() => vi.unstubAllGlobals());

const ROW = {
  id: 3, engagement_id: 7, name: "root ДМЗ", username: "audit", auth: "password", port: 22,
  targets: [], key_fingerprint: null, created_by: 1, created_at: null, become: "none",
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
