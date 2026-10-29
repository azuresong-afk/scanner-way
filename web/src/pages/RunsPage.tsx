import { useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { Play, Radar, Square } from "lucide-react";
import { api } from "../api/client";
import type { RunStatus } from "../api/types";
import { useAuth } from "../auth/AuthContext";
import { useEngagement } from "../auth/EngagementContext";
import { StartRunModal } from "../components/StartRunModal";
import { Empty, ErrorAlert, Loading, RunName, RunStatusPill } from "../components/ui";
import { fmtDate, fmtDuration } from "../lib/format";
import { isFinished, RATE_PROFILES, RUN_STATUS_LABEL } from "../lib/labels";
import { useAsync, useInterval } from "../lib/useAsync";

const FILTERS: (RunStatus | "all")[] = ["all", "running", "done", "stopped", "failed"];

export function RunsPage() {
  const { has } = useAuth();
  const { current } = useEngagement();
  const navigate = useNavigate();
  const runs = useAsync(() => api.runs(current!.id), [current?.id], !!current);
  const [filter, setFilter] = useState<RunStatus | "all">("all");
  const [starting, setStarting] = useState(false);
  const [stopError, setStopError] = useState<string | null>(null);
  const list = [...(runs.data ?? [])].sort((a, b) => b.id - a.id);
  const anyActive = list.some((r) => !isFinished(r.status));
  useInterval(() => void runs.reload(), 4000, anyActive);

  if (!current) {
    return (
      <div className="card">
        <Empty title="Выберите или создайте договор" />
      </div>
    );
  }

  const shown = list.filter((r) => filter === "all" || r.status === filter || (filter === "running" && r.status === "pending"));

  const stop = async (id: number) => {
    setStopError(null);
    try {
      await api.stopRun(id);
      await runs.reload();
    } catch (e) {
      setStopError((e as Error).message);
    }
  };

  return (
    <>
      <div className="page-head">
        <div>
          <span className="crumbs">{current.client ? `${current.client} · ${current.name}` : current.name}</span>
          <h1>Прогоны</h1>
        </div>
        <div className="actions">
          {has("run_scan") && (
            <button type="button" className="btn btn-primary" onClick={() => setStarting(true)}>
              <Play size={16} /> Новый прогон
            </button>
          )}
        </div>
      </div>

      <div className="inline" role="group" aria-label="Фильтр по статусу">
        {FILTERS.map((f) => (
          <button key={f} type="button" className="chip" aria-pressed={filter === f} onClick={() => setFilter(f)}>
            {f === "all" ? "Все" : RUN_STATUS_LABEL[f]}
          </button>
        ))}
      </div>
      {stopError && <ErrorAlert error={stopError} />}
      {runs.error && <ErrorAlert error={runs.error} onRetry={runs.reload} />}

      <div className="card" style={{ overflow: "hidden" }}>
        {runs.loading && !runs.data ? (
          <Loading />
        ) : shown.length === 0 ? (
          <Empty title={list.length ? "Нет прогонов с таким статусом" : "Прогонов ещё не было"} icon={<Radar size={28} />} />
        ) : (
          <div className="table-wrap">
            <table className="table" style={{ minWidth: 760 }}>
              <thead>
                <tr>
                  <th>№</th>
                  <th>Название</th>
                  <th>Профиль</th>
                  <th>Статус</th>
                  <th>Начат</th>
                  <th>Завершён</th>
                  <th>Длительность</th>
                  <th />
                </tr>
              </thead>
              <tbody>
                {shown.map((r) => (
                  <tr key={r.id} className="clickable" onClick={() => navigate(`/runs/${r.id}`)}>
                    <td className="mono">
                      <Link to={`/runs/${r.id}`} onClick={(e) => e.stopPropagation()}>
                        #{r.id}
                      </Link>
                    </td>
                    <td>
                      <RunName run={r} />
                    </td>
                    <td className="muted">{RATE_PROFILES.find((p) => p.id === r.rate_profile)?.label ?? r.rate_profile}</td>
                    <td>
                      <RunStatusPill status={r.status} />
                    </td>
                    <td className="muted nowrap">{fmtDate(r.started_at ?? r.created_at)}</td>
                    <td className="muted nowrap">{fmtDate(r.finished_at)}</td>
                    <td className="muted nowrap">{fmtDuration(r.started_at, r.finished_at)}</td>
                    <td className="right">
                      {has("run_scan") && !isFinished(r.status) && (
                        <button
                          type="button"
                          className="btn btn-sm btn-danger"
                          onClick={(e) => {
                            e.stopPropagation();
                            void stop(r.id);
                          }}
                        >
                          <Square size={12} /> Остановить
                        </button>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {starting && (
        <StartRunModal engagement={current} onClose={() => setStarting(false)} onStarted={(run) => navigate(`/runs/${run.id}`, { state: { created: run } })} onScheduled={() => navigate("/schedules")} />
      )}
    </>
  );
}
