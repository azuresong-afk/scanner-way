import type { RunOut } from "../api/types";
import { plural } from "./format";
import { MODULE_SHORT } from "./labels";

export function stageLabel(stage: string | null | undefined): string | null {
  if (!stage) return null;
  if (stage === "saving") return "Сохранение результатов";
  return MODULE_SHORT[stage] ?? stage;
}

/** Текст плашки: «Прогон №131 идёт · 27 из 42 хостов · 63%». */
export function chipParts(run: RunOut): { main: string; stage: string | null; percent: number | null } {
  if (run.status === "pending") return { main: `Прогон №${run.id} в очереди`, stage: null, percent: null };
  const p = run.progress;
  if (!p) return { main: `Прогон №${run.id} идёт`, stage: null, percent: null };
  const hosts = p.hosts_total > 0
    ? ` · ${p.hosts_done} из ${p.hosts_total} ${plural(p.hosts_total, ["хоста", "хостов", "хостов"])}`
    : "";
  const stage = stageLabel(p.stage);
  const step = stage && p.stages > 1 && p.stage !== "saving" ? `${stage} (${p.stage_index}/${p.stages})` : stage;
  return { main: `Прогон №${run.id} идёт${hosts} · ${p.percent}%`, stage: step, percent: p.percent };
}
