import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { api } from "../api/client";
import type { RunOut } from "../api/types";
import { useEngagement } from "../auth/EngagementContext";
import { useAuth } from "../auth/AuthContext";
import { plural } from "../lib/format";
import { chipParts } from "../lib/runProgress";

/** Как часто спрашивать: пока прогон идёт — чаще, без прогонов — реже. */
const POLL_ACTIVE_MS = 5000;
const POLL_IDLE_MS = 20000;

/** Идущий прогон текущего проекта в шапке каждой страницы; ссылка на прогон. */
export function RunProgressChip() {
  const { current } = useEngagement();
  const { has } = useAuth();
  const engagementId = current?.id ?? null;
  const [runs, setRuns] = useState<RunOut[]>([]);
  const canView = has("view_report");

  useEffect(() => {
    setRuns([]);
    if (engagementId == null || !canView) return;
    let alive = true;
    let timer: ReturnType<typeof setTimeout> | undefined;
    let active = false;
    const tick = async () => {
      if (typeof document === "undefined" || document.visibilityState !== "hidden") {
        try {
          const page = await api.runsPage(engagementId, { status: ["running", "pending"], sort: "id", order: "desc", limit: 5 });
          if (!alive) return;
          setRuns(page.items);
          active = page.items.length > 0;
        } catch {
          // сеть моргнула — плашка останется прежней до следующего опроса
        }
      }
      if (alive) timer = setTimeout(tick, active ? POLL_ACTIVE_MS : POLL_IDLE_MS);
    };
    void tick();
    return () => {
      alive = false;
      if (timer) clearTimeout(timer);
    };
  }, [engagementId, canView]);

  if (!runs.length) return null;
  // идущий важнее стоящего в очереди; среди идущих — самый новый
  const run = runs.find((r) => r.status === "running") ?? runs[0];
  const others = runs.length - 1;
  const { main, stage, percent, eta } = chipParts(run);
  const title = [main, stage, others > 0 ? `ещё ${others} ${plural(others, ["прогон", "прогона", "прогонов"])} в работе` : null]
    .filter(Boolean)
    .join(" · ");
  return (
    <Link to={`/runs/${run.id}`} className="run-chip" title={title} aria-label={title}>
      <span className={`run-chip-dot ${run.status}`} aria-hidden="true" />
      <span className="run-chip-text">{main}</span>
      <span className="run-chip-short">
        {/* на телефоне: время, если оно известно (процент — на полосе), иначе процент */}
        №{run.id} · {eta ?? (percent != null ? `${percent}%` : run.status === "pending" ? "в очереди" : "идёт")}
      </span>
      {stage && <span className="run-chip-stage hide-sm">{stage}</span>}
      {others > 0 && <span className="run-chip-more">+{others}</span>}
      {percent != null && (
        <span className="run-chip-bar" aria-hidden="true">
          <span style={{ width: `${Math.max(percent, 2)}%` }} />
        </span>
      )}
    </Link>
  );
}
