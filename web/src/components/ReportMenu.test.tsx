import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { setToken } from "../api/client";
import { mockApi } from "../test/fixtures";
import * as download from "../lib/download";
import type { RunOut } from "../api/types";
import { ReportMenu } from "./ReportMenu";

afterEach(() => {
  setToken(null);
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

it("по умолчанию выгружает полный отчёт, после переключения — краткий", async () => {
  setToken("t");
  const seen: string[] = [];
  mockApi({
    "GET /runs/7/report": (_init: RequestInit | undefined, url: URL) => {
      seen.push(url.searchParams.get("variant") ?? "");
      return new Response("x");
    },
  });
  const save = vi.spyOn(download, "saveBlob").mockImplementation(() => {});
  render(<ReportMenu runId={7} />);

  expect(screen.getByRole("radio", { name: "Полный" })).toHaveAttribute("aria-checked", "true");
  await userEvent.click(screen.getByRole("button", { name: "Скачать отчёт PDF" }));
  await waitFor(() => expect(save).toHaveBeenCalledTimes(1));
  expect(save.mock.calls[0][1]).toBe("report-run-7.pdf");

  await userEvent.click(screen.getByRole("radio", { name: "Краткий" }));
  expect(screen.getByRole("radio", { name: "Краткий" })).toHaveAttribute("aria-checked", "true");
  await userEvent.click(screen.getByRole("button", { name: "Скачать отчёт Word" }));
  await waitFor(() => expect(save).toHaveBeenCalledTimes(2));
  expect(save.mock.calls[1][1]).toBe("report-run-7-brief.docx");
  expect(seen).toEqual(["full", "brief"]);
});

const run = (id: number, status: RunOut["status"]): RunOut => ({
  id,
  engagement_id: 1,
  modules: ["vuln"],
  rate_profile: "gentle",
  status,
  started_by: 1,
  started_at: "2026-10-01T10:00:00Z",
  finished_at: "2026-10-01T11:00:00Z",
  created_at: null,
});

it("по умолчанию отчёт без сравнения; «Сравнить с» добавляет compare_to", async () => {
  setToken("t");
  const seen: (string | null)[] = [];
  mockApi({
    "GET /runs/7/report": (_init: RequestInit | undefined, url: URL) => {
      seen.push(url.searchParams.get("compare_to"));
      return new Response("x");
    },
  });
  const save = vi.spyOn(download, "saveBlob").mockImplementation(() => {});
  render(<ReportMenu runId={7} runs={[run(3, "done"), run(5, "stopped"), run(6, "done"), run(7, "done"), run(8, "done")]} />);

  const select = screen.getByRole("combobox", { name: "Сравнить с прогоном" });
  expect(select).toHaveValue("");
  // только более ранние успешно завершённые прогоны, свежие сверху
  expect([...select.querySelectorAll("option")].map((o) => o.value)).toEqual(["", "6", "3"]);

  await userEvent.click(screen.getByRole("button", { name: "Скачать отчёт PDF" }));
  await waitFor(() => expect(save).toHaveBeenCalledTimes(1));
  expect(save.mock.calls[0][1]).toBe("report-run-7.pdf");

  await userEvent.selectOptions(select, "3");
  await userEvent.click(screen.getByRole("button", { name: "Скачать отчёт PDF" }));
  await waitFor(() => expect(save).toHaveBeenCalledTimes(2));
  expect(save.mock.calls[1][1]).toBe("report-run-7-vs-3.pdf");
  expect(seen).toEqual([null, "3"]);
});

it("без более ранних прогонов выбора сравнения нет", () => {
  render(<ReportMenu runId={7} runs={[run(7, "done")]} />);
  expect(screen.queryByRole("combobox", { name: "Сравнить с прогоном" })).toBeNull();
});
