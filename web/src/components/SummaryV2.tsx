import { useMemo, useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import type { AssetOut, FixPlanOut, FixTaskOut, RunOut, Severity } from "../api/types";
import { api } from "../api/client";
import { fmtDelta, fmtNumber, plural } from "../lib/format";
import { SEVERITY_LABEL } from "../lib/labels";
import { compareRisk, type HostRow, type RunSummary } from "../lib/stats";
import { columnTotal, FIX_FIRST, findingsWord, TREND_PERIODS, trendColumns, type RunColumn, type TrendPeriod, type TrendUnit } from "../lib/summary";
import { useAsync } from "../lib/useAsync";
import { RunColumns, RunColumnsTable } from "./charts/RunColumns";
import { SeverityStack } from "./charts/SeverityBars";
import { RunFeed } from "./RunFeed";
import { Empty, ErrorAlert, Loading } from "./ui";

type Level = Exclude<Severity, "info">;
const LEVELS: Level[] = ["critical", "high", "medium", "low"];

const PRIORITY_PILL: Record<string, string> = {
  critical: "pill-danger",
  high: "pill-warn",
  medium: "pill-info",
  low: "pill-muted",
};

/** Верх сводки: число открытых, изменение к прошлому прогону и крупные плитки уровней. */
function Hero({ s, latest, previous, prevCounts }: { s: RunSummary; latest: RunOut; previous: RunOut | null; prevCounts: Record<Severity, number> | null }) {
  const nav = useNavigate();
  const delta = s.prevOpen === null ? null : s.open - s.prevOpen;
  const issues = LEVELS.reduce((a, l) => a + s.counts[l], 0);
  return (
    <section className="card hero2" aria-labelledby="sum-open">
      <div className="hero2-main">
        <div className="inline" style={{ gap: "var(--s1) var(--s2)" }}>
          <span className="hero-number num">{fmtNumber(s.open)}</span>
          {delta !== null && previous && (
            <span
              className="delta-badge"
              style={{ background: delta <= 0 ? "var(--ok-soft)" : "var(--danger-soft)", color: delta <= 0 ? "var(--ok)" : "var(--danger)", fontWeight: 600 }}
            >
              {fmtDelta(delta)} к прогону №{previous.id}
            </span>
          )}
        </div>
        <h2 id="sum-open" className="hero2-title">
          {plural(s.open, ["открытая уязвимость", "открытые уязвимости", "открытых уязвимостей"])} на {fmtNumber(s.hosts)}{" "}
          {plural(s.hosts, ["хосте", "хостах", "хостах"])}
        </h2>
        <SeverityStack counts={s.counts} />
        <span className="faint" style={{ fontSize: 13 }}>
          Сопоставлено с БДУ ФСТЭК: {s.bduShare === null ? "—" : `${Math.round(s.bduShare * 100)}%`} · информационных находок: {fmtNumber(s.counts.info)}
        </span>
      </div>
      <div className="sev-tiles2">
        {LEVELS.map((sev) => {
          const n = s.counts[sev];
          const share = issues ? Math.round((n / issues) * 100) : 0;
          const d = prevCounts && previous ? `${fmtDelta(n - prevCounts[sev])} к №${previous.id}` : "первый прогон";
          return (
            <button
              key={sev}
              type="button"
              className={`sev-tile2${sev === "critical" && n > 0 ? " hot" : ""}`}
              onClick={() => nav(`/findings?run=${latest.id}&sev=${sev}`)}
              aria-label={`${SEVERITY_LABEL[sev]}: ${n}, ${share}% открытых, ${d}. Показать находки`}
            >
              <span className={`sev sev-${sev}`}>
                <i aria-hidden="true" />
                {SEVERITY_LABEL[sev]}
              </span>
              <b className="num">{fmtNumber(n)}</b>
              <span className="sev-tile2-foot">
                <span className="sev-tile2-share" aria-hidden="true">
                  <span className={`sevbar-fill ${sev}`} style={{ width: `${share}%` }} />
                </span>
                <span className="sev-tile2-meta">
                  <span>{d}</span>
                  <span className="num">{share}%</span>
                </span>
              </span>
            </button>
          );
        })}
      </div>
    </section>
  );
}

function fixMeta(t: FixTaskOut): string {
  const refs = [...t.cves.slice(0, 1), ...t.bdu_ids.slice(0, 1)];
  if (t.cves.length + t.bdu_ids.length > refs.length) refs.push(`ещё ${t.cves.length + t.bdu_ids.length - refs.length}`);
  return refs.length ? refs.join(" · ") : t.kind_label;
}

/** Первые действия из плана «Что исправить» (сервер сортирует по приоритету). */
function FixFirst({ fixes, latest }: { fixes: FixPlanOut | null; latest: RunOut }) {
  const items = fixes?.items.slice(0, FIX_FIRST) ?? [];
  const closes = items.reduce((a, t) => a + t.finding_count, 0);
  const all = `/findings?run=${latest.id}`;
  return (
    <section className="card card-pad grow-2 stack fixfirst" aria-labelledby="sum-fix">
      <div className="inline" style={{ justifyContent: "space-between", alignItems: "baseline" }}>
        <h2 id="sum-fix">Исправить в первую очередь</h2>
        <Link to={all} style={{ fontSize: 13 }}>
          {fixes ? `Все ${fmtNumber(fixes.tasks)} ${plural(fixes.tasks, ["действие", "действия", "действий"])}` : "Что исправить"}
        </Link>
      </div>
      {fixes && items.length > 0 && (
        <span className="muted" style={{ fontSize: 13 }}>
          {items.length < fixes.tasks ? `Первые ${items.length}` : plural(items.length, ["Это действие", "Эти действия", "Эти действия"])} закроют {fmtNumber(closes)}{" "}
          {findingsWord(closes)} из {fmtNumber(fixes.findings)}
        </span>
      )}
      {!fixes && <Empty title="План исправлений недоступен">Откройте раздел «Находки», вкладку «Что исправить».</Empty>}
      {fixes && items.length === 0 && <Empty title="Исправлять нечего" />}
      {items.length > 0 && (
        <ol className="fixfirst-list">
          {items.map((t, i) => (
            <li key={t.key}>
              <span className="mono faint">{i + 1}</span>
              {t.priority ? (
                <span className={`pill ${PRIORITY_PILL[t.priority.label] ?? "pill-muted"}`} title={`Приоритет: ${t.priority.label_ru}, балл ${t.priority.score.toFixed(0)}`}>
                  {t.priority.score.toFixed(0)}
                </span>
              ) : (
                <span className={`sev sev-${t.severity}`} title={SEVERITY_LABEL[t.severity]}>
                  <i aria-hidden="true" />
                </span>
              )}
              <span style={{ minWidth: 0 }}>
                <Link to={`${all}&q=${encodeURIComponent(t.title)}`} className="fixfirst-title">
                  {t.title}
                </Link>
                <span className="faint fixfirst-meta">
                  {fmtNumber(t.host_count)} {plural(t.host_count, ["хост", "хоста", "хостов"])} · {fixMeta(t)}
                </span>
              </span>
              <b className="num right" title={`Закроет ${t.finding_count} ${findingsWord(t.finding_count)}`}>
                −{fmtNumber(t.finding_count)}
              </b>
            </li>
          ))}
        </ol>
      )}
    </section>
  );
}

/** Крупный график по прогонам: столбцы по уровням, рядом с планом исправлений. */
function RunsTrend({ engagementId, recent }: { engagementId: number; recent: RunColumn[] }) {
  const [table, setTable] = useState(false);
  const [period, setPeriod] = useState<TrendPeriod>("runs");
  const def = TREND_PERIODS.find((p) => p.id === period) ?? TREND_PERIODS[0];
  // «10 прогонов» уже загружены сводкой; период — одним запросом к серверу
  const ranged = useAsync(() => api.trend(engagementId, { days: def.days }), [engagementId, period], period !== "runs");
  const picked = useMemo(
    () => (period === "runs" ? { columns: recent, unit: "run" as TrendUnit } : ranged.data ? trendColumns(ranged.data) : null),
    [period, recent, ranged.data],
  );
  const busy = period !== "runs" && ranged.loading;
  const columns = busy ? [] : (picked?.columns ?? []);
  const runCount = period === "runs" ? recent.length : (ranged.data?.length ?? 0);
  const first = columns[0];
  const last = columns[columns.length - 1];
  const t0 = first ? columnTotal(first) : 0;
  const t1 = last ? columnTotal(last) : 0;
  const severe = (c: RunColumn) => c.counts.critical + c.counts.high;
  const pctChange = t0 ? Math.round(((t1 - t0) / t0) * 100) : 0;
  const runsText = `${runCount} ${plural(runCount, ["прогон", "прогона", "прогонов"])}`;
  const scope =
    period === "runs"
      ? `За ${runsText}`
      : `${def.phrase} (${runsText}${picked?.unit === "week" ? ", по неделям" : picked?.unit === "month" ? ", по месяцам" : ""})`;
  return (
    <section className="card card-pad grow-3 stack runs-trend" aria-labelledby="sum-trend">
      <div className="inline" style={{ justifyContent: "space-between" }}>
        <h2 id="sum-trend">Открытые уязвимости по прогонам</h2>
        <span className="inline">
          <div className="seg seg-sm" role="radiogroup" aria-label="Период графика">
            {TREND_PERIODS.map((p) => (
              <button key={p.id} type="button" role="radio" aria-checked={period === p.id} onClick={() => setPeriod(p.id)}>
                {p.label}
              </button>
            ))}
          </div>
          {columns.length > 1 && (
            <button type="button" className="btn btn-sm" aria-pressed={table} onClick={() => setTable((v) => !v)}>
              {table ? "Графиком" : "Таблицей"}
            </button>
          )}
        </span>
      </div>
      {busy && <Loading />}
      {!busy && period !== "runs" && ranged.error && <ErrorAlert error={ranged.error} onRetry={ranged.reload} />}
      {!busy && columns.length > 1 && (
        <>
          <div className="inline" style={{ justifyContent: "space-between", fontSize: 13 }}>
            <span className="muted">
              {scope}:{" "}
              <b style={{ color: t1 <= t0 ? "var(--ok)" : "var(--danger)" }}>
                {fmtDelta(t1 - t0)}
                {t1 !== t0 && t0 ? ` (${pctChange > 0 ? "+" : "−"}${Math.abs(pctChange)}%)` : ""}
              </b>
              , критических и высоких{" "}
              <b style={{ color: severe(last) <= severe(first) ? "var(--ok)" : "var(--danger)" }}>{fmtDelta(severe(last) - severe(first))}</b>
            </span>
            <span className="legend">
              {LEVELS.map((l) => (
                <span key={l} className={`sev sev-${l}`}>
                  <i aria-hidden="true" />
                  {SEVERITY_LABEL[l]}
                </span>
              ))}
            </span>
          </div>
          {table ? <RunColumnsTable points={columns} /> : <RunColumns points={columns} />}
        </>
      )}
      {!busy && !ranged.error && columns.length <= 1 && (
        <Empty title={period === "runs" ? "График появится после второго прогона" : "За этот период меньше двух прогонов"} />
      )}
    </section>
  );
}

/** Самые уязвимые хосты: имя из «Активов», если известно, иначе адрес. */
function Hosts({ hosts, assets, latest }: { hosts: HostRow[]; assets: AssetOut[]; latest: RunOut }) {
  const byAddr = useMemo(() => new Map(assets.map((a) => [a.address, a])), [assets]);
  const top = useMemo(() => [...hosts].sort((a, b) => compareRisk(a.counts, b.counts)).slice(0, 5), [hosts]);
  return (
    <section className="card card-pad grow-2 stack" style={{ gap: 0 }} aria-labelledby="sum-hosts">
      <div className="inline" style={{ justifyContent: "space-between", marginBottom: 8 }}>
        <h2 id="sum-hosts">Самые уязвимые хосты</h2>
        <Link to={`/hosts?run=${latest.id}`} style={{ fontSize: 13 }}>
          Все хосты
        </Link>
      </div>
      {top.length === 0 && <Empty title="Уязвимых хостов нет" />}
      {top.map((h) => {
        const a = byAddr.get(h.host);
        const name = a?.hostname || h.host;
        const os = a?.os_family_label || a?.os_guess || "";
        const sub = [name !== h.host ? h.host : "", os || h.summary].filter(Boolean).join(" · ") || `${h.total} уязв.`;
        return (
          <Link key={h.host} to={`/hosts/${encodeURIComponent(h.host)}?run=${latest.id}`} className="list-row">
            <span style={{ display: "flex", flexDirection: "column", flex: 1, minWidth: 0 }}>
              <span style={{ fontWeight: 600 }} className={name === h.host ? "mono" : undefined}>
                {name}
              </span>
              <span className="faint ellipsis" style={{ fontSize: 12 }}>
                {sub}
              </span>
            </span>
            {h.counts.critical > 0 && <span className="pill pill-danger">{h.counts.critical} крит.</span>}
            {h.counts.high > 0 && <span className="pill pill-warn">{h.counts.high} выс.</span>}
            {!h.counts.critical && !h.counts.high && <span className="pill pill-muted">{h.total} уязв.</span>}
          </Link>
        );
      })}
    </section>
  );
}

export interface SummaryV2Props {
  s: RunSummary;
  latest: RunOut;
  previous: RunOut | null;
  prevCounts: Record<Severity, number> | null;
  engagementId: number;
  /** Прогон для ленты: идущий или последний. */
  feedRun: RunOut;
  /** Идущий прогон завершился — перечитать сводку. */
  onFeedFinished?: () => void;
  columns: RunColumn[];
  fixes: FixPlanOut | null;
  hosts: HostRow[];
  assets: AssetOut[];
}

/** «Сводка 2.0»: без плиток «Новые/Закрытые/Регрессии/Хосты» и без матрицы риска. */
export function SummaryV2(p: SummaryV2Props) {
  return (
    <>
      <Hero s={p.s} latest={p.latest} previous={p.previous} prevCounts={p.prevCounts} />
      <div className="row">
        <FixFirst fixes={p.fixes} latest={p.latest} />
        <RunsTrend engagementId={p.engagementId} recent={p.columns} />
      </div>
      <div className="row">
        <Hosts hosts={p.hosts} assets={p.assets} latest={p.latest} />
        <RunFeed run={p.feedRun} assets={p.assets} onFinished={p.onFeedFinished} />
      </div>
    </>
  );
}
