import { render, screen, within } from "@testing-library/react";
import type { RunColumn } from "../../lib/summary";
import { RunColumns, RunColumnsTable } from "./RunColumns";

const c = (label: string, critical: number, high: number, medium: number, low: number): RunColumn => ({
  label,
  sub: "04.11",
  counts: { critical, high, medium, low },
});

const POINTS = [c("№129", 11, 39, 89, 42), c("№130", 8, 36, 80, 36), c("№131", 9, 33, 74, 33)];

it("подписывает первый и последний итог и самое большое снижение, остальное — в описании столбца", () => {
  const { container } = render(<RunColumns points={POINTS} />);
  const list = screen.getByRole("list", { name: "Открытые уязвимости по уровням в каждом прогоне" });
  const items = within(list).getAllByRole("listitem");
  expect(items).toHaveLength(3);
  expect(items[1]).toHaveAccessibleName("Прогон №130, 04.11: всего 160; критический 8, высокий 36, средний 80, низкий 36");
  const labels = [...container.querySelectorAll(".runcols-total")].map((e) => e.textContent);
  expect(labels).toEqual(["181", "−21", "149"]);
  // критические у основания столбца: последний сегмент в разметке
  const bar = items[2].querySelector(".runcols-bar")!;
  expect(bar.lastElementChild).toHaveClass("critical");
});

it("таблица повторяет данные графика", () => {
  render(<RunColumnsTable points={POINTS} />);
  const row = screen.getByRole("row", { name: /№131/ });
  expect(within(row).getAllByRole("cell").map((td) => td.textContent)).toEqual(["№131", "04.11", "9", "33", "74", "33", "149"]);
});

it("неделя или месяц: подпись периода и последнего прогона, под осью — не больше 12 подписей", () => {
  const weeks: RunColumn[] = Array.from({ length: 20 }, (_, i) => ({
    label: `w${i}`,
    sub: `№${i + 1}`,
    period: `Неделя ${i}`,
    counts: { critical: 1, high: 0, medium: 0, low: 0 },
  }));
  const { container } = render(<RunColumns points={weeks} />);
  expect(screen.getAllByRole("listitem")[19]).toHaveAccessibleName("Неделя 19, прогон №20: всего 1; критический 1, высокий 0, средний 0, низкий 0");
  const shown = [...container.querySelectorAll(".runcols-x > span")].filter((s) => s.textContent);
  expect(shown.length).toBeLessThanOrEqual(12);
  expect(shown[shown.length - 1].textContent).toBe("w19№20");
});
