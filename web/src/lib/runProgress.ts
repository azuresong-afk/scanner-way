import type { RunOut, RunProgress } from "../api/types";
import { fmtEta, plural } from "./format";
import { MODULE_SHORT } from "./labels";

export function stageLabel(stage: string | null | undefined): string | null {
  if (!stage) return null;
  if (stage === "saving") return "Сохранение результатов";
  return MODULE_SHORT[stage] ?? stage;
}

/** Сколько примерно осталось, с: оценка сервера минус время, прошедшее с
 *  её снимка (между снимками таймер идёт сам). null — оценить пока нельзя. */
export function remainingSeconds(p: RunProgress | null | undefined, now = Date.now()): number | null {
  if (!p || p.eta_seconds == null || p.stage === "saving") return null;
  const at = Date.parse(p.updated_at);
  const since = Number.isFinite(at) ? Math.max(0, (now - at) / 1000) : 0;
  return Math.max(0, p.eta_seconds - since);
}

/** «≈ 12 мин», «< 1 мин», «заканчивается»; null — пока не знаем. */
export function etaText(sec: number | null): string | null {
  if (sec == null) return null;
  if (sec <= 0) return "заканчивается";
  if (sec < 60) return "< 1 мин";
  return `≈ ${fmtEta(sec)}`;
}

/** Текст плашки: «Прогон №131 идёт · 27 из 42 хостов · 63% · ≈ 12 мин». */
export function chipParts(run: RunOut, now = Date.now()): { main: string; stage: string | null; percent: number | null; eta: string | null } {
  if (run.status === "pending") return { main: `Прогон №${run.id} в очереди`, stage: null, percent: null, eta: null };
  const p = run.progress;
  if (!p) return { main: `Прогон №${run.id} идёт`, stage: null, percent: null, eta: null };
  const hosts = p.hosts_total > 0
    ? ` · ${p.hosts_done} из ${p.hosts_total} ${plural(p.hosts_total, ["хоста", "хостов", "хостов"])}`
    : "";
  const stage = stageLabel(p.stage);
  const step = stage && p.stages > 1 && p.stage !== "saving" ? `${stage} (${p.stage_index}/${p.stages})` : stage;
  const eta = etaText(remainingSeconds(p, now));
  return { main: `Прогон №${run.id} идёт${hosts} · ${p.percent}%${eta ? ` · ${eta}` : ""}`, stage: step, percent: p.percent, eta };
}
