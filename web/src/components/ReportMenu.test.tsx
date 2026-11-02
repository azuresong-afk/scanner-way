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
  credential_ids: [], cred_set_ids: [],
  name: "Nuclei",
  targets: [],
  schedule_id: null,
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

it("выбор группы активов добавляет group_id в запрос отчёта", async () => {
  setToken("t");
  const seen: (string | null)[] = [];
  mockApi({
    "GET /engagements/5/asset-groups": [
      { id: 3, engagement_id: 5, name: "ДМЗ", asset_count: 2, created_at: null },
      { id: 4, engagement_id: 5, name: "Пустая", asset_count: 0, created_at: null },
    ],
    "GET /runs/7/report": (_init: RequestInit | undefined, url: URL) => {
      seen.push(url.searchParams.get("group_id"));
      return new Response("x");
    },
  });
  const save = vi.spyOn(download, "saveBlob").mockImplementation(() => {});
  render(<ReportMenu runId={7} engagementId={5} />);

  const select = await screen.findByRole("combobox", { name: "Группа активов" });
  expect(screen.queryByRole("option", { name: "Пустая" })).toBeNull(); // пустые группы не предлагаем
  await userEvent.click(screen.getByRole("button", { name: "Скачать отчёт PDF" }));
  await waitFor(() => expect(save).toHaveBeenCalledTimes(1));
  await userEvent.selectOptions(select, "ДМЗ");
  await userEvent.click(screen.getByRole("button", { name: "Скачать отчёт PDF" }));
  await waitFor(() => expect(save).toHaveBeenCalledTimes(2));
  expect(seen).toEqual([null, "3"]);
  expect(save.mock.calls[1][1]).toBe("report-run-7-group-3.pdf");
});

it("разделы: план и профили соответствия — опции отчёта", async () => {
  setToken("t");
  const seen: { plan: string | null; compliance: string | null }[] = [];
  mockApi({
    "GET /engagements/5/asset-groups": [],
    "GET /engagements/5/compliance-profiles": [
      { profile: "fstec-117", level: "К2", excluded: [], added: [], in_report: true },
      { profile: "cis-controls-v8", level: null, excluded: [], added: [], in_report: false },
    ],
    "GET /compliance/profiles": [{ id: "fstec-117", short: "ФСТЭК №117" }],
    "GET /runs/7/report": (_init: RequestInit | undefined, url: URL) => {
      seen.push({ plan: url.searchParams.get("plan"), compliance: url.searchParams.get("compliance") });
      return new Response("x");
    },
  });
  const save = vi.spyOn(download, "saveBlob").mockImplementation(() => {});
  render(<ReportMenu runId={7} engagementId={5} />);

  const fstec = await screen.findByRole("checkbox", { name: "Соответствие: ФСТЭК №117" });
  expect(fstec).toBeChecked();
  expect(screen.getByRole("checkbox", { name: "Соответствие: cis-controls-v8" })).not.toBeChecked();
  expect(screen.getByRole("checkbox", { name: "План устранения" })).toBeChecked();
  await userEvent.click(screen.getByRole("button", { name: "Скачать отчёт PDF" }));
  await waitFor(() => expect(save).toHaveBeenCalledTimes(1));

  // клиент не ГИС: убираем №117 и план
  await userEvent.click(fstec);
  await userEvent.click(screen.getByRole("checkbox", { name: "План устранения" }));
  await userEvent.click(screen.getByRole("button", { name: "Скачать отчёт PDF" }));
  await waitFor(() => expect(save).toHaveBeenCalledTimes(2));
  expect(seen.slice(0, 2)).toEqual([
    { plan: null, compliance: "fstec-117" },
    { plan: "false", compliance: "none" },
  ]);

  // «Выбрать все» включает план и все профили одним кликом
  const all = screen.getByRole("checkbox", { name: "Выбрать все" });
  expect(all).not.toBeChecked();
  expect((all as HTMLInputElement).indeterminate).toBe(false); // всё снято
  await userEvent.click(all);
  expect(screen.getByRole("checkbox", { name: "План устранения" })).toBeChecked();
  expect(screen.getByRole("checkbox", { name: "Соответствие: ФСТЭК №117" })).toBeChecked();
  expect(screen.getByRole("checkbox", { name: "Соответствие: cis-controls-v8" })).toBeChecked();
  await userEvent.click(screen.getByRole("button", { name: "Скачать отчёт PDF" }));
  await waitFor(() => expect(save).toHaveBeenCalledTimes(3));
  expect(seen[2]).toEqual({ plan: null, compliance: "fstec-117,cis-controls-v8" });
  await userEvent.click(screen.getByRole("checkbox", { name: "Соответствие: cis-controls-v8" }));
  expect((all as HTMLInputElement).indeterminate).toBe(true);
  await userEvent.click(all);
  expect(all).toBeChecked();

  // в кратком отчёте плана нет всегда — флажок недоступен
  await userEvent.click(screen.getByRole("radio", { name: "Краткий" }));
  expect(screen.getByRole("checkbox", { name: "План устранения" })).toBeDisabled();
});
