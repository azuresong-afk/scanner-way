import { useState } from "react";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { setToken } from "../api/client";
import type { FindingOut } from "../api/types";
import { AuthProvider } from "../auth/AuthContext";
import { finding, me, mockApi, OPERATOR } from "../test/fixtures";
import { FindingDrawer } from "./FindingDrawer";

const MARK = { reason: "бэкпорт в пакете", marked_by: "tester", marked_at: "2026-10-29T12:00:00Z" };

function Harness({ initial }: { initial: FindingOut }) {
  const [f, setF] = useState(initial);
  return (
    <AuthProvider>
      <FindingDrawer finding={f} onClose={() => {}} onChanged={setF} />
    </AuthProvider>
  );
}

beforeEach(() => setToken("t"));
afterEach(() => {
  setToken(null);
  vi.unstubAllGlobals();
});

it("отмечает находку как ложное срабатывание с обоснованием и снимает отметку", async () => {
  const f = finding({ id: 42 });
  const api = mockApi({
    "GET /me": me(["operator"], OPERATOR),
    "PUT /findings/42/false-positive": { ...f, false_positive: MARK },
    "DELETE /findings/42/false-positive": { ...f, false_positive: null },
  });
  render(<Harness initial={f} />);
  await userEvent.click(await screen.findByRole("button", { name: /Отметить как ложное срабатывание/ }));
  await userEvent.type(screen.getByLabelText(/^Обоснование/), "бэкпорт в пакете");
  await userEvent.click(screen.getByRole("button", { name: "Отметить" }));
  expect(await screen.findByText("Отмечено как ложное срабатывание")).toBeInTheDocument();
  expect(screen.getByText("бэкпорт в пакете")).toBeInTheDocument();
  const put = api.calls.find((c) => c.method === "PUT");
  expect(JSON.parse(String(put?.init?.body))).toEqual({ reason: "бэкпорт в пакете" });

  await userEvent.click(screen.getByRole("button", { name: /Снять отметку/ }));
  expect(await screen.findByRole("button", { name: /Отметить как ложное срабатывание/ })).toBeInTheDocument();
  expect(api.calls.some((c) => c.method === "DELETE" && c.path === "/findings/42/false-positive")).toBe(true);
});

it("без права triage_findings только показывает отметку", async () => {
  mockApi({ "GET /me": me(["auditor"], ["view_engagements", "view_report", "view_audit"]) });
  render(<Harness initial={finding({ false_positive: MARK })} />);
  expect(await screen.findByText("Отмечено как ложное срабатывание")).toBeInTheDocument();
  expect(screen.queryByRole("button", { name: /Снять отметку/ })).not.toBeInTheDocument();
});
