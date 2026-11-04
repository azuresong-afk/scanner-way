import type { FixPlanOut, Severity, TrendRunOut } from "../api/types";
import { fmtNumber, parseDate, plural } from "./format";
import type { RunSummary } from "./stats";

/** Сколько действий показывать в «Исправить в первую очередь». */
export const FIX_FIRST = 5;

type Level = Exclude<Severity, "info">;

/** Столбец графика: прогон (или неделя/месяц за период), уровни без информационных. */
export interface RunColumn {
  /** «№131»; у недели — её начало «27.10», у месяца — «ноя». */
  label: string;
  /** Дата прогона; у недели и месяца — последний прогон в нём, «№131». */
  sub: string;
  counts: Record<Level, number>;
  /** Только у недели и месяца: «Неделя с 27.10.2026», «Ноябрь 2026». */
  period?: string;
}

export const columnTotal = (p: RunColumn) => p.counts.critical + p.counts.high + p.counts.medium + p.counts.low;

export const findingsWord = (n: number) => plural(n, ["находку", "находки", "находок"]);
const hostsWord = (n: number) => plural(n, ["хосте", "хостах", "хостах"]);

/** Строка «Главное:» под заголовком сводки: что сделать первым и что изменилось. */
export function summaryHeadline(s: RunSummary, fixes: FixPlanOut | null): string {
  const parts: string[] = [];
  const first = fixes?.items[0];
  if (s.open === 0) parts.push("открытых уязвимостей нет.");
  else if (first) {
    parts.push(
      `первым стоит сделать «${first.title}»: закроет ${fmtNumber(first.finding_count)} ${findingsWord(first.finding_count)} на ${fmtNumber(first.host_count)} ${hostsWord(first.host_count)}.`,
    );
  }
  if (s.newCount > 0) parts.push(`Новых уязвимостей: ${fmtNumber(s.newCount)}.`);
  if (s.regression > 0) parts.push(`Вернулись после исправления: ${fmtNumber(s.regression)}.`);
  return parts.join(" ");
}

/** Период графика на «Сводке». */
export type TrendPeriod = "runs" | "90d" | "365d";
export const TREND_PERIODS: { id: TrendPeriod; label: string; days?: number; phrase: string }[] = [
  { id: "runs", label: "10 прогонов", phrase: "" },
  { id: "90d", label: "3 месяца", days: 90, phrase: "За 3 месяца" },
  { id: "365d", label: "Год", days: 365, phrase: "За год" },
];
/** Больше столбцов не помещается: прогоны собираются в недели, затем в месяцы. */
export const TREND_MAX_COLUMNS = 26;
export type TrendUnit = "run" | "week" | "month";

const MONTH_SHORT = ["янв", "фев", "мар", "апр", "май", "июн", "июл", "авг", "сен", "окт", "ноя", "дек"];
const MONTH_FULL = ["Январь", "Февраль", "Март", "Апрель", "Май", "Июнь", "Июль", "Август", "Сентябрь", "Октябрь", "Ноябрь", "Декабрь"];
const pad = (n: number) => String(n).padStart(2, "0");
/** «04.11». */
export const dayMonth = (d: Date) => `${pad(d.getDate())}.${pad(d.getMonth() + 1)}`;

function bucketStart(d: Date, unit: "week" | "month"): Date {
  if (unit === "month") return new Date(d.getFullYear(), d.getMonth(), 1);
  const day = new Date(d.getFullYear(), d.getMonth(), d.getDate());
  day.setDate(day.getDate() - ((day.getDay() + 6) % 7)); // понедельник
  return day;
}

/**
 * Прогоны периода → столбцы графика. До TREND_MAX_COLUMNS — столбец на прогон;
 * больше — по неделям, а если и недель много — по месяцам. Открытые уязвимости —
 * состояние, а не поток, поэтому столбец недели/месяца — последний прогон в ней.
 */
export function trendColumns(points: TrendRunOut[], max = TREND_MAX_COLUMNS): { columns: RunColumn[]; unit: TrendUnit } {
  const dated = points.map((p) => ({ p, d: parseDate(p.started_at) }));
  if (points.length <= max) {
    return { unit: "run", columns: dated.map(({ p, d }) => ({ label: `№${p.scan_run_id}`, sub: d ? dayMonth(d) : "—", counts: p.counts })) };
  }
  let unit: "week" | "month" = "week";
  let buckets = new Map<number, { start: Date; last: TrendRunOut }>();
  for (const u of ["week", "month"] as const) {
    unit = u;
    buckets = new Map();
    for (const { p, d } of dated) {
      if (!d) continue;
      const start = bucketStart(d, u);
      const b = buckets.get(start.getTime());
      if (b) b.last = p;
      else buckets.set(start.getTime(), { start, last: p });
    }
    if (buckets.size <= max) break;
  }
  const columns = [...buckets.values()]
    .sort((a, b) => a.start.getTime() - b.start.getTime())
    .map(({ start, last }, i) => ({
      // у месяца год — в первом столбце и на январе: «ноя ’25 … янв ’26 … ноя»
      label:
        unit === "week"
          ? dayMonth(start)
          : `${MONTH_SHORT[start.getMonth()]}${i === 0 || start.getMonth() === 0 ? ` ’${String(start.getFullYear()).slice(2)}` : ""}`,
      sub: `№${last.scan_run_id}`,
      counts: last.counts,
      period: unit === "week" ? `Неделя с ${dayMonth(start)}.${start.getFullYear()}` : `${MONTH_FULL[start.getMonth()]} ${start.getFullYear()}`,
    }));
  return { unit, columns };
}
