import type { FixPlanOut, Severity } from "../api/types";
import { fmtNumber, plural } from "./format";
import type { RunSummary } from "./stats";

/** Сколько действий показывать в «Исправить в первую очередь». */
export const FIX_FIRST = 5;

type Level = Exclude<Severity, "info">;

/** Прогон для графика столбцами: уровни опасности без информационных. */
export interface RunColumn {
  /** «№131». */
  label: string;
  /** Дата прогона. */
  sub: string;
  counts: Record<Level, number>;
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
