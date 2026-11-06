import type { RunOut } from "../api/types";

/** Прогон на автономном узле: назначен на узел с mode = offline (задание на носителе). */
export function isOfflineRun(run: Pick<RunOut, "node_mode">): boolean {
  return run.node_mode === "offline";
}
