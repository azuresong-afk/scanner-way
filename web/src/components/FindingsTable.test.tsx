import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { FindingsTable } from "./FindingsTable";
import { finding } from "../test/fixtures";
import type { PriorityOut } from "../api/types";

const prio = (rank: number, score: number, label: PriorityOut["label"]): PriorityOut => ({
  rank,
  score,
  label,
  label_ru: "Критический приоритет",
  reasons: ["CVSS 9.8", "входит в каталог CISA KEV"],
  factors: { cvss: 9.8, in_kev: true, epss: null, epss_percentile: null, exploit_available: false, asset_criticality: "medium" },
});

const ROWS = [
  finding({ id: 1, title: "Низкая по CVSS, но в KEV", severity: "low", cvss: 3.0, priority: prio(1, 90, "critical") }),
  finding({ id: 2, title: "Высокая без факторов", severity: "high", cvss: 8.0, priority: prio(2, 80, "high") }),
  finding({ id: 3, title: "Информационная", severity: "info", cvss: null, priority: null }),
];

describe("FindingsTable: приоритет", () => {
  it("показывает ранг и балл с подсказкой о факторах", () => {
    render(<FindingsTable findings={ROWS} onOpen={() => {}} />);
    const badge = screen.getByText("#1 · 90");
    expect(badge).toHaveAttribute("title", expect.stringContaining("CISA KEV"));
  });

  it("сортируется по приоритету: ранг 1 первым, находки без приоритета в конце", async () => {
    render(<FindingsTable findings={ROWS} onOpen={() => {}} />);
    await userEvent.click(screen.getByRole("button", { name: "Приоритет" }));
    const titles = screen
      .getAllByRole("row")
      .slice(1)
      .map((r) => within(r).getAllByRole("cell")[2].textContent);
    expect(titles).toEqual(["Низкая по CVSS, но в KEV", "Высокая без факторов", "Информационная"]);
  });
});
