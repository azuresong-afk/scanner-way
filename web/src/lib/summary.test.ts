import type { TrendRunOut } from "../api/types";
import { trendColumns } from "./summary";

const DAY = 86_400_000;
const point = (id: number, at: number, critical = 1): TrendRunOut => ({
  scan_run_id: id,
  status: "done",
  started_at: new Date(at).toISOString(),
  finished_at: null,
  counts: { critical, high: 0, medium: 0, low: 0 },
});
// понедельник, середина дня — границы недель и месяцев не зависят от пояса
const MON = Date.UTC(2026, 3, 6, 12);

it("до 26 прогонов — столбец на прогон", () => {
  const { unit, columns } = trendColumns([point(1, MON), point(2, MON + DAY)]);
  expect(unit).toBe("run");
  expect(columns.map((c) => c.label)).toEqual(["№1", "№2"]);
  expect(columns[0].period).toBeUndefined();
});

it("ежедневные прогоны за 3 месяца — по неделям, столбец недели = её последний прогон", () => {
  const pts = Array.from({ length: 70 }, (_, i) => point(i + 1, MON + i * DAY, i));
  const { unit, columns } = trendColumns(pts);
  expect(unit).toBe("week");
  expect(columns).toHaveLength(10);
  expect(columns[0]).toMatchObject({ label: "06.04", sub: "№7", period: "Неделя с 06.04.2026" });
  expect(columns[0].counts.critical).toBe(6);
  expect(columns[9].sub).toBe("№70");
});

it("за год — по месяцам", () => {
  const pts = Array.from({ length: 200 }, (_, i) => point(i + 1, MON + i * DAY));
  const { unit, columns } = trendColumns(pts);
  expect(unit).toBe("month");
  expect(columns.map((c) => c.label)).toEqual(["апр ’26", "май", "июн", "июл", "авг", "сен", "окт"]);
  expect(columns[0]).toMatchObject({ period: "Апрель 2026", sub: "№25" });
});
