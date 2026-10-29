import { useState } from "react";
import { Link } from "react-router-dom";
import { CalendarClock, Pencil, Play, Plus, Trash2 } from "lucide-react";
import { api } from "../api/client";
import type { ScheduleOut } from "../api/types";
import { useAuth } from "../auth/AuthContext";
import { useEngagement } from "../auth/EngagementContext";
import { StartRunModal } from "../components/StartRunModal";
import { Empty, ErrorAlert, Loading } from "../components/ui";
import { fmtDate } from "../lib/format";
import { moduleList, RATE_PROFILES, scheduleResult, scheduleWhen } from "../lib/labels";
import { useAsync } from "../lib/useAsync";

/** Прогоны по расписанию договора: список, включение/выключение, запуск сейчас, правка. */
export function SchedulesPage() {
  const { has } = useAuth();
  const { current } = useEngagement();
  const schedules = useAsync(() => api.schedules(current!.id), [current?.id], !!current);
  const [editing, setEditing] = useState<ScheduleOut | "new" | null>(null);
  const [confirmDelete, setConfirmDelete] = useState<number | null>(null);
  const [busy, setBusy] = useState<number | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const canEdit = has("run_scan");

  if (!current) {
    return (
      <div className="card">
        <Empty title="Выберите или создайте договор" />
      </div>
    );
  }

  const act = async (id: number, fn: () => Promise<unknown>, done?: string) => {
    setBusy(id);
    setError(null);
    setNotice(null);
    try {
      await fn();
      if (done) setNotice(done);
      await schedules.reload();
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(null);
      setConfirmDelete(null);
    }
  };

  const list = schedules.data ?? [];

  return (
    <>
      <div className="page-head">
        <div>
          <span className="crumbs">{current.client ? `${current.client} · ${current.name}` : current.name}</span>
          <h1>Расписания</h1>
        </div>
        <div className="actions">
          {canEdit && (
            <button type="button" className="btn btn-primary" onClick={() => setEditing("new")}>
              <Plus size={16} /> Новое расписание
            </button>
          )}
        </div>
      </div>

      {error && <ErrorAlert error={error} />}
      {notice && <div className="alert alert-ok">{notice}</div>}
      {schedules.error && <ErrorAlert error={schedules.error} onRetry={schedules.reload} />}

      <div className="card" style={{ overflow: "hidden" }}>
        {schedules.loading && !schedules.data ? (
          <Loading />
        ) : list.length === 0 ? (
          <Empty title="Расписаний пока нет" icon={<CalendarClock size={28} />}>
            Регулярные проверки запускаются сами в заданное время — с теми же целями, модулями и правами, что и обычный прогон.
          </Empty>
        ) : (
          <div className="table-wrap">
            <table className="table" style={{ minWidth: 980 }}>
              <thead>
                <tr>
                  <th>Название</th>
                  <th>Когда</th>
                  <th>Следующий запуск</th>
                  <th>Последний запуск</th>
                  <th>Включено</th>
                  <th />
                </tr>
              </thead>
              <tbody>
                {list.map((s) => (
                  <tr key={s.id}>
                    <td>
                      <div style={{ fontWeight: 500 }}>{s.title}</div>
                      <small className="muted">
                        {moduleList(s.modules)} · {RATE_PROFILES.find((p) => p.id === s.rate_profile)?.label ?? s.rate_profile}
                      </small>
                    </td>
                    <td className="nowrap">
                      {scheduleWhen(s)}
                      <div>
                        <small className="faint">{s.timezone}</small>
                      </div>
                    </td>
                    <td className="muted nowrap">{s.enabled ? fmtDate(s.next_run_at ?? s.run_at) : "—"}</td>
                    <td className="muted">
                      {s.last_run_at ? (
                        <>
                          <span className="nowrap">{fmtDate(s.last_run_at)}</span>
                          {s.last_run_id !== null && (
                            <>
                              {" · "}
                              <Link to={`/runs/${s.last_run_id}`}>прогон №{s.last_run_id}</Link>
                            </>
                          )}
                          <div>
                            <small className={s.last_result === "queued" ? "faint" : undefined} style={s.last_result === "queued" ? undefined : { color: "var(--warn)" }}>
                              {scheduleResult(s.last_result)}
                            </small>
                          </div>
                        </>
                      ) : (
                        "ещё не запускалось"
                      )}
                    </td>
                    <td>
                      <label className="inline" style={{ gap: 6 }}>
                        <input
                          type="checkbox"
                          checked={s.enabled}
                          disabled={!canEdit || busy === s.id}
                          aria-label={s.enabled ? "Выключить расписание" : "Включить расписание"}
                          onChange={(e) => void act(s.id, () => api.toggleSchedule(s.id, e.target.checked))}
                        />
                        <span className="muted">{s.enabled ? "Да" : "Нет"}</span>
                      </label>
                    </td>
                    <td className="right nowrap">
                      {canEdit && (
                        <div className="inline" style={{ gap: 6, justifyContent: "flex-end" }}>
                          <button
                            type="button"
                            className="btn btn-sm"
                            disabled={busy === s.id}
                            onClick={() => void act(s.id, () => api.runScheduleNow(s.id), `«${s.title}»: прогон поставлен в очередь`)}
                          >
                            <Play size={12} /> Сейчас
                          </button>
                          <button type="button" className="btn btn-sm" aria-label="Изменить" onClick={() => setEditing(s)}>
                            <Pencil size={12} />
                          </button>
                          {confirmDelete === s.id ? (
                            <button type="button" className="btn btn-sm btn-danger" disabled={busy === s.id} onClick={() => void act(s.id, () => api.deleteSchedule(s.id))}>
                              Удалить?
                            </button>
                          ) : (
                            <button type="button" className="btn btn-sm" aria-label="Удалить" onClick={() => setConfirmDelete(s.id)}>
                              <Trash2 size={12} />
                            </button>
                          )}
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
        <StartRunModal
          engagement={current}
          schedule={editing === "new" ? undefined : editing}
          initialWhen="schedule"
          onClose={() => setEditing(null)}
          onScheduled={(s) => {
            setEditing(null);
            setNotice(`Расписание «${s.title}» сохранено. Следующий запуск — ${fmtDate(s.next_run_at)}.`);
            void schedules.reload();
          }}
        />
      )}
    </>
  );
}
