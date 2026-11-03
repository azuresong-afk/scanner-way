import { useEffect, useState } from "react";
import { CheckCircle2, Database, Download, Pencil, RefreshCw, Upload } from "lucide-react";
import { api } from "../api/client";
import type { FeedKind, FeedOut, FeedProgress, FeedReadiness, FeedState } from "../api/types";
import { useAuth } from "../auth/AuthContext";
import { Empty, ErrorAlert, Loading, Modal } from "../components/ui";
import { fmtDate, fmtEta } from "../lib/format";
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

const n = (x: number) => x.toLocaleString("ru-RU");

/** Ход долгой загрузки: этап, загружено/всего, %, скорость, осталось. */
export function FeedProgressView({ progress }: { progress: FeedProgress | null | undefined }) {
  if (!progress) return <span className="muted">Обновляется…</span>;
  const { stage, done, total, percent, rate_per_sec: rate, eta_seconds: eta, elapsed_seconds: elapsed } = progress;
  return (
    <div className="stack" style={{ gap: 4, minWidth: 220 }} role="status">
      <span>{stage ?? "Обновляется"}</span>
      {percent !== null && (
        <div style={{ height: 6, background: "var(--border)", borderRadius: 3, overflow: "hidden" }} aria-label={`Выполнено ${percent}%`}>
          <div style={{ width: `${percent}%`, height: "100%", background: "var(--accent)" }} />
        </div>
      )}
      <small className="muted">
        {done !== null && (total ? `${n(done)} из ${n(total)}` : `загружено ${n(done)}`)}
        {percent !== null && ` · ${percent}%`}
        {rate ? ` · ${n(Math.round(rate))}/с` : ""}
        {eta !== null ? ` · осталось ~${fmtEta(eta)}` : ""}
        {` · идёт ${fmtEta(elapsed)}`}
      </small>
    </div>
  );
}

const STATE_LABEL: Record<FeedState, string> = {
  ready: "Готов",
  missing: "Не загружен",
  running: "Загружается",
  error: "Ошибка",
  stale: "Устарел",
};
const STATE_PILL: Record<FeedState, string> = {
  ready: "pill-ok",
  missing: "pill-danger",
  running: "pill-info",
  error: "pill-danger",
  stale: "pill-warn",
};

/** Мастер первоначальной настройки: что загружено, что нет и что сделать. */
function ReadinessWizard({ data, canEdit, onChanged }: { data: FeedReadiness; canEdit: boolean; onChanged: () => void }) {
  const [busy, setBusy] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const act = async (key: string, fn: () => Promise<unknown>) => {
    setBusy(key);
    setError(null);
    try {
      await fn();
      onChanged();
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(null);
    }
  };
  return (
    <section className="card card-pad stack" style={{ gap: 12 }} aria-label="Готовность справочников">
      <div className="inline" style={{ justifyContent: "space-between", flexWrap: "wrap", gap: 8 }}>
        <h2>Готовность справочников</h2>
        {data.ready ? (
          <span className="pill pill-ok">
            <CheckCircle2 size={12} /> Всё необходимое загружено
          </span>
        ) : (
          <span className="pill pill-warn">Требуется настройка</span>
        )}
      </div>
      {error && <ErrorAlert error={error} />}
      <div className="table-wrap">
        <table className="table">
          <thead>
            <tr>
              <th>Источник</th>
              <th>Состояние</th>
              <th className="right">Записей</th>
              <th>Что сделать</th>
            </tr>
          </thead>
          <tbody>
            {data.sources.map((s) => (
              <tr key={s.source}>
                <td>
                  <div style={{ fontWeight: 500 }}>
                    {s.title}
                    {!s.required && <small className="faint"> · необязательно</small>}
                  </div>
                  <small className="muted">{s.purpose}</small>
                </td>
                <td className="nowrap">
                  <span className={`pill ${STATE_PILL[s.state]}`}>{STATE_LABEL[s.state]}</span>
                  {s.state === "running" && <FeedProgressView progress={s.progress} />}
                </td>
                <td className="right num">{s.records === null ? "—" : n(s.records)}</td>
                <td>
                  {s.hint && <small>{s.hint}</small>}
                  {s.message && (s.state === "error" || s.message_is_previous) && (
                    <div>
                      <small style={s.message_is_previous ? undefined : { color: "var(--danger)" }} className={s.message_is_previous ? "faint" : undefined}>
                        {s.message_is_previous ? "Прошлая попытка: " : ""}
                        {s.message}
                      </small>
                    </div>
                  )}
                  {canEdit && s.source === "bdu" && s.state !== "running" && (
                    <div style={{ marginTop: 6 }}>
                      <label className="btn btn-sm" style={{ cursor: "pointer" }}>
                        <Upload size={12} /> {busy === "bdu-upload" ? "Загрузка файла…" : "Загрузить файл БДУ (vullist.xlsx)"}
                        <input
                          type="file"
                          accept=".xlsx"
                          hidden
                          disabled={busy === "bdu-upload"}
                          onChange={(e) => {
                            const f = e.target.files?.[0];
                            e.target.value = "";
                            if (f) void act("bdu-upload", () => api.uploadBdu(f));
                          }}
                        />
                      </label>
                    </div>
                  )}
                  {canEdit && s.state !== "running" && s.state !== "ready" && s.source !== "bdu" && (
                    <div style={{ marginTop: 6 }}>
                      <button type="button" className="btn btn-sm" disabled={busy === s.source} onClick={() => void act(s.source, () => api.runFeedNow(s.source))}>
                        <RefreshCw size={12} /> Загрузить
                      </button>
                    </div>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      {data.missing_releases.length > 0 && (
        <div className="alert alert-warn stack" style={{ gap: 6 }}>
          <b>Бэкпорты не учтены: нет бюллетеней для выпусков ОС ваших хостов</b>
          {data.missing_releases.map((r) => {
            const key = `${r.family}:${r.release}`;
            return (
              <div key={key} className="inline" style={{ gap: 8, flexWrap: "wrap" }}>
                <span>
                  {r.os ?? key} ({key}) — хосты: {r.hosts.slice(0, 5).join(", ")}
                  {r.hosts.length > 5 ? ` и ещё ${r.hosts.length - 5}` : ""}
                </span>
                {canEdit && (
                  <button type="button" className="btn btn-sm" disabled={busy === key} onClick={() => void act(key, () => api.loadRelease(r.family, r.release))}>
                    <Download size={12} /> Загрузить {key}
                  </button>
                )}
              </div>
            );
          })}
          <small>После загрузки повторите прогон по этим хостам — находки, исправленные бэкпортом, перестанут считаться открытыми.</small>
        </div>
      )}
      {data.releases.length > 0 && (
        <small className="muted">
          Загружены бюллетени: {data.releases.map((r) => `${r.family}:${r.release} (${n(r.records)})`).join(", ")}
        </small>
      )}
    </section>
  );
}

/** Справочники: когда обновлялись, сколько записей, следующий запуск, «Обновить сейчас». */
export function FeedsPage() {
  const { has } = useAuth();
  const feeds = useAsync(() => api.feeds(), []);
  const ready = useAsync(() => api.feedReadiness(), []);
  const [editing, setEditing] = useState<FeedOut | null>(null);
  const [busy, setBusy] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const canEdit = has("manage_engagements");
  const list = feeds.data ?? [];
  const anyRunning = list.some((f) => f.running);
  const reloadAll = () => {
    void feeds.reload();
    void ready.reload();
  };

  // пока что-то обновляется — подтягиваем статус и прогресс, чтобы увидеть итог
  useEffect(() => {
    if (!anyRunning) return;
    const t = setInterval(() => {
      void feeds.reload();
      void ready.reload();
    }, POLL_MS);
    return () => clearInterval(t);
  }, [anyRunning, feeds, ready]);

  const runNow = async (source: string) => {
    setBusy(source);
    setError(null);
    try {
      await api.runFeedNow(source);
      await feeds.reload();
      void ready.reload();
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
      {ready.data && <ReadinessWizard data={ready.data} canEdit={canEdit} onChanged={reloadAll} />}

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
                        <>
                          <FeedProgressView progress={f.progress} />
                          {f.message && (
                            <div>
                              <small className="faint">Прошлая попытка: {f.message}</small>
                            </div>
                          )}
                        </>
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
