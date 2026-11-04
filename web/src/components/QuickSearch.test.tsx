import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter, Route, Routes, useLocation } from "react-router-dom";
import { setToken } from "../api/client";
import type { SearchOut } from "../api/types";
import { AuthProvider } from "../auth/AuthContext";
import { EngagementProvider } from "../auth/EngagementContext";
import { me, mockApi, OPERATOR } from "../test/fixtures";
import { QuickSearch } from "./QuickSearch";

const ENG = { id: 1, name: "Периметр", client: "ООО Тест", contract_ref: "Д-1", created_by: 1, created_at: "2026-10-01T10:00:00" };

const RESULT: SearchOut = {
  q: "openssl",
  run_id: 7,
  run_name: "Плановый",
  assets: 31,
  findings: 149,
  counts: { hosts: 2, software: 1, vulns: 1, actions: 1, commands: 1 },
  actions: [
    { key: "pkg:deb12:openssl", title: "Обновить openssl до 3.0.15-1~deb12u1", kind_label: "Обновление пакета", severity: "high", os: "Debian 12", host_count: 2, finding_count: 4, priority: 81 },
  ],
  hosts: [
    { host: "10.0.0.1", hostname: "db01", os: "Debian 12", criticality: "high", vulns: 3, max_severity: "high", match: "openssl 3.0.11-1~deb12u1" },
    { host: "10.0.0.2", hostname: null, os: null, criticality: null, vulns: 0, max_severity: null, match: "openssl 3.0.11-1~deb12u1" },
  ],
  software: [{ name: "openssl", versions: ["3.0.11-1~deb12u1"], host_count: 2, vulnerable_hosts: 2, vulns: 4, hosts: ["10.0.0.1", "10.0.0.2"], source: "package" }],
  vulns: [{ id: "CVE-2023-5678", title: "openssl: DoS", cves: ["CVE-2023-5678"], bdu_ids: ["BDU:2023-07890"], severity: "high", host_count: 2, hosts: ["10.0.0.1"] }],
  commands: [
    { key: "pkg:deb12:openssl", title: "Обновить openssl до 3.0.15-1~deb12u1", os: "Debian 12", command: "sudo apt-get install --only-upgrade -y openssl", commands: ["sudo apt-get update", "sudo apt-get install --only-upgrade -y openssl"] },
  ],
};

function Where() {
  const l = useLocation();
  return <output aria-label="адрес">{l.pathname + l.search}</output>;
}

function renderSearch() {
  return render(
    <MemoryRouter initialEntries={["/"]} future={{ v7_startTransition: true, v7_relativeSplatPath: true }}>
      <AuthProvider>
        <EngagementProvider>
          <QuickSearch />
          <Routes>
            <Route path="*" element={<Where />} />
          </Routes>
        </EngagementProvider>
      </AuthProvider>
    </MemoryRouter>,
  );
}

afterEach(() => {
  setToken(null);
  vi.unstubAllGlobals();
  localStorage.clear();
});

it("Ctrl+K открывает палитру: группы результатов, стрелки и Enter ведут на карточку хоста", async () => {
  setToken("t");
  const api = mockApi({ "GET /me": me(["operator"], OPERATOR), "GET /engagements": [ENG], "GET /engagements/1/search": RESULT });
  renderSearch();
  await screen.findByRole("button", { name: "Поиск по проекту (Ctrl+K)" });
  fireEvent.keyDown(window, { key: "k", ctrlKey: true });
  const dialog = await screen.findByRole("dialog", { name: "Быстрый поиск" });
  const input = within(dialog).getByRole("combobox");
  expect(input).toHaveFocus();
  await userEvent.type(input, "openssl");

  const list = await within(dialog).findByRole("listbox");
  for (const g of ["Действия", "Хосты", "ПО", "CVE и БДУ", "Команды"]) expect(await within(list).findByRole("group", { name: g })).toBeInTheDocument();
  expect(within(dialog).getByText(/31 хост, 149 находок прогона «Плановый»/)).toBeInTheDocument();
  const call = api.calls.find((c) => c.path === "/engagements/1/search");
  expect(call).toBeDefined();

  // первое — действие; вниз — первый хост
  const options = within(list).getAllByRole("option");
  expect(options[0]).toHaveAttribute("aria-selected", "true");
  fireEvent.keyDown(input, { key: "ArrowDown" });
  expect(options[1]).toHaveAttribute("aria-selected", "true");
  expect(options[1]).toHaveTextContent("db01 · openssl 3.0.11-1~deb12u1");
  fireEvent.keyDown(input, { key: "Enter" });
  expect(screen.getByLabelText("адрес")).toHaveTextContent("/hosts/10.0.0.1");
  expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
});

it("действие открывает «Что исправить» с этим действием, «>» оставляет только команды, Enter копирует", async () => {
  setToken("t");
  mockApi({ "GET /me": me(["operator"], OPERATOR), "GET /engagements": [ENG], "GET /engagements/1/search": RESULT });
  const writeText = vi.fn(async () => undefined);
  vi.stubGlobal("navigator", { ...navigator, clipboard: { writeText } });
  renderSearch();
  await userEvent.click(await screen.findByRole("button", { name: "Поиск по проекту (Ctrl+K)" }));
  const dialog = await screen.findByRole("dialog");
  const input = within(dialog).getByRole("combobox");
  await userEvent.type(input, "openssl");
  await within(dialog).findByRole("group", { name: "Действия" });
  fireEvent.keyDown(input, { key: "Enter" });
  expect(screen.getByLabelText("адрес")).toHaveTextContent("/findings?run=7&q=openssl&task=pkg%3Adeb12%3Aopenssl");

  await userEvent.click(screen.getByRole("button", { name: "Поиск по проекту (Ctrl+K)" }));
  const again = await screen.findByRole("dialog");
  const box = within(again).getByRole("combobox");
  await userEvent.type(box, ">openssl");
  await within(again).findByRole("group", { name: "Команды" });
  expect(within(again).queryByRole("group", { name: "Хосты" })).not.toBeInTheDocument();
  fireEvent.keyDown(box, { key: "Enter" });
  await waitFor(() => expect(writeText).toHaveBeenCalledWith("sudo apt-get update\nsudo apt-get install --only-upgrade -y openssl"));
  expect(await within(again).findByText("Скопировано")).toBeInTheDocument();
  fireEvent.keyDown(box, { key: "Escape" });
  expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
});

it("без права на отчёты поля поиска нет", async () => {
  setToken("t");
  mockApi({ "GET /me": me(["admin"], ["manage_users", "view_engagements"]), "GET /engagements": [ENG] });
  renderSearch();
  await screen.findByLabelText("адрес");
  await waitFor(() => expect(screen.queryByRole("button", { name: /Поиск по проекту/ })).not.toBeInTheDocument());
});
