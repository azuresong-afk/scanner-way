import { render, screen, fireEvent, waitFor } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { afterEach, describe, expect, it, vi } from "vitest";
import { api } from "../api/client";
import type { SystemHealth } from "../api/types";
import { HealthPage } from "./HealthPage";

const REPORT: SystemHealth = {
  status: "warn",
  status_title: "требует внимания",
  checked_at: "2026-11-07T12:00:00Z",
  components: [
    { id: "database", title: "База данных", status: "ok", summary: "отвечает за 2 мс, схема 0029", hint: null, items: [], details: {} },
    {
      id: "engines",
      title: "Движки проверок",
      status: "warn",
      summary: "не установлены: lynis — эти проверки не выполнятся",
      hint: "Пересоберите образ",
      items: [
        { id: "nmap", title: "nmap", status: "ok", version: "7.94", purpose: "обнаружение" },
        { id: "lynis", title: "lynis", status: "warn", version: null, purpose: "аудит конфигураций" },
      ],
      details: {},
    },
  ],
};

afterEach(() => vi.restoreAllMocks());

describe("HealthPage", () => {
  it("показывает компоненты, проблему с подсказкой и подробности", async () => {
    vi.spyOn(api, "systemHealth").mockResolvedValue(REPORT);
    render(
      <MemoryRouter>
        <HealthPage />
      </MemoryRouter>,
    );
    expect(await screen.findByText("Сканер: требует внимания")).toBeInTheDocument();
    expect(screen.getByText("База данных")).toBeInTheDocument();
    expect(screen.getByText("Пересоберите образ")).toBeInTheDocument();
    // проблемный компонент раскрыт сразу
    expect(screen.getByText(/версия 7\.94/)).toBeInTheDocument();
    expect(screen.getByText(/не установлен · аудит конфигураций/)).toBeInTheDocument();
  });

  it("«Проверить сейчас» запрашивает проверку заново", async () => {
    const spy = vi.spyOn(api, "systemHealth").mockResolvedValue({ ...REPORT, status: "ok", status_title: "в порядке", components: [REPORT.components[0]] });
    render(
      <MemoryRouter>
        <HealthPage />
      </MemoryRouter>,
    );
    expect(await screen.findByText("Сканер работает штатно")).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: /Проверить сейчас/ }));
    await waitFor(() => expect(spy).toHaveBeenCalledWith(true));
  });
});
