import { useMemo, useState } from "react";
import { Link } from "react-router-dom";
import { api } from "../api/client";
import type { AssetOut, RunEventOut, RunOut } from "../api/types";
import { parseDate } from "../lib/format";
import { isFinished } from "../lib/labels";
import { useAsync, useInterval } from "../lib/useAsync";
import { Empty, Loading, RunStatusPill } from "./ui";

/** Сколько событий видно сразу; остальное — по кнопке. */
const FEED_SHOWN = 6;
/** Как часто обновлять ленту идущего прогона. */
const FEED_POLL_MS = 10_000;

const pad = (n: number) => String(n).padStart(2, "0");
const hhmm = (s: string | null) => {
  const d = parseDate(s);
  return d ? `${pad(d.getHours())}:${pad(d.getMinutes())}` : "";
};

/** Цвет метки: уровень находок, «закрыто» — зелёный, сбои — тёплые, ход прогона — акцент. */
function tone(e: RunEventOut): string {
  if (e.severity === "ok") return "var(--ok)";
  if (e.severity && ["critical", "high", "medium", "low"].includes(e.severity)) return `var(--sev-${e.severity})`;
  if (e.kind === "module_error") return "var(--danger)";
  if (e.kind === "host_gap" || e.kind === "run_stop" || e.kind === "module_skip") return "var(--warn)";
  if (e.kind.startsWith("run_")) return "var(--accent)";
  return "var(--text-3)";
}

function FeedRow({ e, runId, names }: { e: RunEventOut; runId: number; names: Map<string, string> }) {
  // у событий, восстановленных миграцией, кто = адрес: имя берём из «Активов»
  const who = e.host ? (e.subject !== e.host ? e.subject : (names.get(e.host) ?? e.host)) : e.subject;
  return (
    <li className="feed-row">
      <time className="faint num" dateTime={e.ts ?? undefined}>
        {hhmm(e.ts)}
      </time>
      <i className="feed-dot" style={{ background: tone(e) }} aria-hidden="true" />
      <span className="feed-text">
        {e.host ? (
          <Link to={`/hosts/${encodeURIComponent(e.host)}?run=${runId}`} title={who !== e.host ? e.host : undefined} className={who === e.host ? "mono" : undefined}>
            {who}
          </Link>
        ) : (
          <b>{who}</b>
        )}{" "}
        <span className="muted">{e.message}</span>
      </span>
    </li>
  );
}

/**
 * Лента прогона на «Сводке»: что сканер делает и что нашёл. Идущий прогон
 * обновляется сам; когда он завершится, вызывается onFinished (сводка
 * перечитывает данные).
 */
export function RunFeed({ run, assets, onFinished }: { run: RunOut; assets: AssetOut[]; onFinished?: () => void }) {
  const active = !isFinished(run.status);
  const feed = useAsync(() => api.runEvents(run.id), [run.id]);
  const [all, setAll] = useState(false);
  useInterval(
    () => {
      void feed.reload();
      api
        .run(run.id)
        .then((r) => {
          if (isFinished(r.status)) onFinished?.();
        })
        .catch(() => undefined);
    },
    FEED_POLL_MS,
    active,
  );
  const names = useMemo(() => new Map(assets.filter((a) => a.hostname).map((a) => [a.address, a.hostname as string])), [assets]);
  const events = feed.data ?? [];
  const shown = all ? events : events.slice(0, FEED_SHOWN);

  return (
    <section className="card card-pad grow-2 stack" style={{ gap: 0 }} aria-labelledby="sum-feed">
      <div className="inline" style={{ justifyContent: "space-between", marginBottom: 8 }}>
        <h2 id="sum-feed">Лента прогона №{run.id}</h2>
        <span className="inline">
          <RunStatusPill status={run.status} />
          <Link to="/runs" style={{ fontSize: 13 }}>
            Все прогоны
          </Link>
        </span>
      </div>
      {!feed.data && feed.loading && <Loading />}
      {!feed.data && feed.error && <p className="muted">Ленту не удалось загрузить.</p>}
      {feed.data && events.length === 0 && <Empty title={active ? "Прогон начинается" : "Событий нет"} />}
      {events.length > 0 && (
        <ol className="feed" aria-label={`События прогона №${run.id}, новые сверху`}>
          {shown.map((e) => (
            <FeedRow key={e.id} e={e} runId={run.id} names={names} />
          ))}
        </ol>
      )}
      {events.length > FEED_SHOWN && (
        <button type="button" className="btn btn-sm btn-ghost feed-more" aria-expanded={all} onClick={() => setAll((v) => !v)}>
          {all ? "Свернуть" : `Показать все (${events.length})`}
        </button>
      )}
    </section>
  );
}
