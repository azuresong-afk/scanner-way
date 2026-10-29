import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { setToken } from "../api/client";
import { mockApi } from "../test/fixtures";
import * as download from "../lib/download";
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
