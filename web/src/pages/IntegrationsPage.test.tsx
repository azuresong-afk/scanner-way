import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { AuthProvider } from "../auth/AuthContext";
import { setToken } from "../api/client";
import type { ChannelOut, DeliveryOut } from "../api/types";
import { ADMIN, me, mockApi } from "../test/fixtures";
import { IntegrationsPage } from "./IntegrationsPage";

afterEach(() => {
  setToken(null);
  vi.unstubAllGlobals();
});

const channel = (p: Partial<ChannelOut> = {}): ChannelOut => ({
  id: 1,
  name: "SOC Telegram",
  type: "telegram",
  enabled: true,
  config: { chat_id: "-100123" },
  events: ["run_finished", "new_critical"],
  filters: { min_severity: "high", min_priority: null, groups: ["DMZ"], owners: [], engagements: [] },
  has_secret: true,
  created_at: "2026-10-30T10:00:00Z",
  updated_at: "2026-10-30T10:00:00Z",
  ...p,
});

const delivery = (p: Partial<DeliveryOut> = {}): DeliveryOut => ({
  id: 5,
  channel_id: 1,
  channel_name: "SOC Telegram",
  event: "new_critical",
  status: "failed",
  attempts: 5,
  next_attempt_at: null,
  last_error: "Telegram: HTTP 502",
  engagement_id: 1,
  scan_run_id: 7,
  external_ref: null,
  summary: "Прогон: находок 2",
  created_at: "2026-10-30T11:00:00Z",
  sent_at: null,
  ...p,
});

function renderPage(permissions: string[]) {
  setToken("t");
  const api = mockApi({
    "GET /me": me(["admin"], permissions),
    "GET /integrations/channels": [channel()],
    "GET /integrations/log": [delivery()],
    "POST /integrations/channels": channel({ id: 2 }),
    "POST /integrations/log/5/retry": delivery({ status: "sent", last_error: null }),
  });
  render(
    <MemoryRouter>
      <AuthProvider>
        <IntegrationsPage />
      </AuthProvider>
    </MemoryRouter>,
  );
  return api;
}

describe("IntegrationsPage", () => {
  it("показывает каналы, фильтры и журнал с ошибкой", async () => {
    renderPage(ADMIN);
    expect((await screen.findAllByText("SOC Telegram"))[0]).toBeInTheDocument();
    expect(screen.getByText(/группы: DMZ/)).toBeInTheDocument();
    expect(screen.getByText("Telegram: HTTP 502")).toBeInTheDocument();
  });

  it("повторяет неудавшуюся доставку", async () => {
    const api = renderPage(ADMIN);
    await userEvent.click(await screen.findByRole("button", { name: /Повторить/ }));
    await waitFor(() => expect(api.calls.some((c) => c.method === "POST" && c.path === "/integrations/log/5/retry")).toBe(true));
  });

  it("создаёт канал: секрет уходит в secrets, а не в config", async () => {
    const api = renderPage(ADMIN);
    await userEvent.click(await screen.findByRole("button", { name: /Новый канал/ }));
    await userEvent.type(screen.getByLabelText("Название"), "Почта SOC");
    await userEvent.type(screen.getByLabelText("SMTP-сервер"), "mail.corp.local");
    await userEvent.type(screen.getByLabelText("От кого"), "scanner@corp.local");
    await userEvent.type(screen.getByLabelText(/Кому/), "sec@corp.local, soc@corp.local");
    await userEvent.type(screen.getByLabelText("Пароль SMTP"), "s3cret-pass");
    await userEvent.click(screen.getByRole("button", { name: "Сохранить" }));
    await waitFor(() => expect(api.calls.some((c) => c.method === "POST" && c.path === "/integrations/channels")).toBe(true));
    const call = api.calls.find((c) => c.method === "POST" && c.path === "/integrations/channels")!;
    const sent = JSON.parse(String(call.init?.body));
    expect(sent.type).toBe("smtp");
    expect(sent.config.to).toEqual(["sec@corp.local", "soc@corp.local"]);
    expect(sent.secrets).toEqual({ password: "s3cret-pass" });
    expect(JSON.stringify(sent.config)).not.toContain("s3cret-pass");
  });

  it("без права manage_engagements кнопок изменения нет", async () => {
    renderPage(["view_engagements"]);
    expect((await screen.findAllByText("SOC Telegram"))[0]).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /Новый канал/ })).toBeNull();
    expect(screen.queryByRole("button", { name: /Проверить/ })).toBeNull();
  });
});
