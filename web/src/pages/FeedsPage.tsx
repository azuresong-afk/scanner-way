import { useEffect, useState } from "react";
import { Database, Pencil, RefreshCw } from "lucide-react";
import { api } from "../api/client";
import type { FeedKind, FeedOut } from "../api/types";
import { useAuth } from "../auth/AuthContext";
import { Empty, ErrorAlert, Loading, Modal } from "../components/ui";
import { fmtDate } from "../lib/format";
import { FEED_RESULT_LABEL, SCHEDULE_KINDS, scheduleWhen, WEEKDAYS } from "../lib/labels";
import { useAsync } from "../lib/useAsync";

const KINDS = SCHEDULE_KINDS.filter((k) => k.id !== "once");
const POLL_MS = 5000;

function FeedScheduleModal({ feed, onClose, onSaved }: { feed: FeedOut; onClose: () => void; onSaved: () => void }) {
  const [enabled, setEnabled] = useState(feed.enabled);
  const [kind, setKind] = useState<FeedKind>(feed.kind);
  const [timeOfDay, setTimeOfDay] = useState(feed.time_of_day);
  const [weekdays, setWeekdays] = useState<number[]>(feed.weekdays.length ? feed.weekdays : [0]);
  const [monthDay, setMonthDay] = useState(feed.month_day ?? 1);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const valid = /^\d{2}:\d{2}$/.test(timeOfDay) && (kind !== "weekly" || weekdays.length > 0) && (kind !== "monthly" || (monthDay >= 1 && monthDay <= 31));

  const save = async () => {
    setBusy(true);
    setError(null);
    try {
      await api.updateFeed(feed.source, {
        enabled,
        kind,
        time_of_day: timeOfDay,
        ...(kind === "weekly" ? { weekdays } : {}),
        ...(kind === "monthly" ? { month_day: monthDay } : {}),
      });
      onSaved();
    } catch (e) {
      setError((e as Error).message);
      setBusy(false);
    }
  };

  const toggleDay = (d: number) => setWeekdays((w) => (w.includes(d) ? w.filter((x) => x !== d) : [...w, d].sort()));

  return (
    <Modal
      title={`Автообновление: ${feed.title}`}
      onClose={onClose}
      footer={
        <>
          <button type="button" className="btn" onClick={onClose}>
            Отмена
          </button>
          <button type="button" className="btn btn-primary" disabled={!valid || busy} onClick={() => void save()}>
            Сохранить
          </button>
        </>
      }
    >
      {error && <ErrorAlert error={error} />}
      <label className="inline" style={{ gap: 8 }}>
        <input type="checkbox" checked={enabled} onChange={(e) => setEnabled(e.target.checked)} />
        <span>Обновлять по расписанию</span>
      </label>
      <fieldset className="field" style={{ border: 0, padding: 0, margin: 0 }}>
        <span>Периодичность</span>
        <div className="inline" role="group" aria-label="Периодичность">
          {KINDS.map((k) => (
            <button key={k.id} type="button" className="chip" aria-pressed={kind === k.id} onClick={() => setKind(k.id as FeedKind)}>
              {k.label}
            </button>
          ))}
        </div>
        {kind === "weekly" && (
          <div className="inline" role="group" aria-label="Дни недели">
            {WEEKDAYS.map((d, i) => (
              <button key={d} type="button" className="chip" aria-pressed={weekdays.includes(i)} onClick={() => toggleDay(i)}>
                {d}
              </button>
            ))}
          </div>
        )}
        <div className="inline" style={{ gap: 12, flexWrap: "wrap" }}>
          {kind === "monthly" && (
            <label className="field" style={{ width: 120 }}>
              <span>День месяца</span>
              <input className="input" type="number" min={1} max={31} value={monthDay} onChange={(e) => setMonthDay(Number(e.target.value))} />
            </label>
          )}
          <label className="field" style={{ width: 140 }}>
            <span>Время ({feed.timezone})</span>
            <input className="input" type="time" value={timeOfDay} onChange={(e) => setTimeOfDay(e.target.value)} />
          </label>
        </div>
      </fieldset>
    </Modal>
  );
}

/** Справочники: когда обновлялись, сколько записей, следующий запуск, «Обновить сейчас». */
export function FeedsPage() {
  const { has } = useAuth();
  const feeds = useAsync(() => api.feeds(), []);
  const [editing, setEditing] = useState<FeedOut | null>(null);
  const [busy, setBusy] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const canEdit = has("manage_engagements");
  const list = feeds.data ?? [];
  const anyRunning = list.some((f) => f.running);

  // пока что-то обновляется — подтягиваем статус, чтобы увидеть итог
  useEffect(() => {
    if (!anyRunning) return;
    const t = setInterval(() => void feeds.reload(), POLL_MS);
    return () => clearInterval(t);
  }, [anyRunning, feeds]);

  const runNow = async (source: string) => {
    setBusy(source);
    setError(null);
    try {
      await api.runFeedNow(source);
      await feeds.reload();
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(null);
    }
  };

  return (
    <>
      <div className="page-head">
        <div>
          <span className="crumbs">Администрирование</span>
          <h1>Справочники</h1>
        </div>
      </div>

      {error && <ErrorAlert error={error} />}
      {feeds.error && <ErrorAlert error={feeds.error} onRetry={feeds.reload} />}

      <div className="card" style={{ overflow: "hidden" }}>
        {feeds.loading && !feeds.data ? (
          <Loading />
        ) : list.length === 0 ? (
          <Empty title="Справочников нет" icon={<Database size={28} />} />
        ) : (
          <div className="table-wrap">
            <table className="table" style={{ minWidth: 900 }}>
              <thead>
                <tr>
                  <th>Справочник</th>
                  <th>Расписание</th>
                  <th>Следующий запуск</th>
                  <th>Последнее обновление</th>
                  <th />
                </tr>
              </thead>
              <tbody>
                {list.map((f) => (
                  <tr key={f.source}>
                    <td>
                      <div style={{ fontWeight: 500 }}>{f.title}</div>
                      <small className="muted">{f.description}</small>
                    </td>
                    <td className="nowrap">
                      {f.enabled ? scheduleWhen(f) : <span className="muted">выключено</span>}
                      {f.enabled && (
                        <div>
                          <small className="faint">{f.timezone}</small>
                        </div>
                      )}
                    </td>
                    <td className="muted nowrap">{f.enabled ? fmtDate(f.next_run_at) : "—"}</td>
                    <td>
                      {f.running ? (
                        <span className="muted">Обновляется…</span>
                      ) : f.last_run_at ? (
                        <>
                          <span className="nowrap">{fmtDate(f.last_run_at)}</span>
                          {" · "}
                          <span style={f.last_result === "error" ? { color: "var(--danger)" } : undefined}>{FEED_RESULT_LABEL[f.last_result ?? ""] ?? f.last_result}</span>
                          {f.last_count !== null && <small className="faint"> · записей: {f.last_count.toLocaleString("ru-RU")}</small>}
                          {f.message && (
                            <div>
                              <small className={f.last_result === "error" ? undefined : "faint"} style={f.last_result === "error" ? { color: "var(--danger)" } : undefined}>
                                {f.message}
                              </small>
                            </div>
                          )}
                        </>
                      ) : (
                        <span className="muted">ещё не обновлялось</span>
                      )}
                    </td>
                    <td className="right nowrap">
                      {canEdit && (
                        <div className="inline" style={{ gap: 6, justifyContent: "flex-end" }}>
                          <button type="button" className="btn btn-sm" disabled={f.running || busy === f.source} onClick={() => void runNow(f.source)}>
                            <RefreshCw size={12} /> Обновить сейчас
                          </button>
                          <button type="button" className="btn btn-sm" aria-label={`Расписание: ${f.title}`} onClick={() => setEditing(f)}>
                            <Pencil size={12} />
                          </button>
                        </div>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {editing && (
        <FeedScheduleModal
          feed={editing}
          onClose={() => setEditing(null)}
          onSaved={() => {
            setEditing(null);
            void feeds.reload();
          }}
        />
      )}
    </>
  );
}
