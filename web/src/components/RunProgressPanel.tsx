import type { RunOut } from "../api/types";
import { fmtEta, plural } from "../lib/format";
import { etaText, remainingSeconds, stageLabel } from "../lib/runProgress";

/** Ход идущего прогона на его странице: этап, полоса %, хосты, «осталось ≈ …». */
export function RunProgressPanel({ run, now = Date.now() }: { run: RunOut; now?: number }) {
  const p = run.progress;
  if (!p) return null;
  const stage = stageLabel(p.stage);
  const step = stage && p.stages > 1 && p.stage !== "saving" ? `Этап ${p.stage_index} из ${p.stages}: ${stage}` : stage;
  const eta = etaText(remainingSeconds(p, now));
  const started = run.started_at ? Date.parse(run.started_at) : NaN;
  const elapsed = Number.isFinite(started) ? Math.max(0, (now - started) / 1000) : p.elapsed_seconds ?? null;
  return (
    <div className="run-progress" role="status" aria-live="polite">
      <div className="run-progress-head">
        <span className="run-progress-stage">{step ?? "Идёт сканирование"}</span>
        <span className="run-progress-eta">{eta ? (eta === "заканчивается" ? "Заканчивается" : `Осталось ${eta}`) : "Оцениваем время…"}</span>
      </div>
      <div className="run-progress-bar" aria-label={`Выполнено ${p.percent}%`}>
        <span style={{ width: `${Math.max(p.percent, 1)}%` }} />
      </div>
      <div className="run-progress-meta faint">
        <span>{p.percent}%</span>
        {p.hosts_total > 0 && p.stage !== "saving" && (
          <span>
            {p.hosts_done} из {p.hosts_total} {plural(p.hosts_total, ["хоста", "хостов", "хостов"])} на этапе
          </span>
        )}
        {elapsed != null && <span>идёт {fmtEta(elapsed)}</span>}
      </div>
    </div>
  );
}
