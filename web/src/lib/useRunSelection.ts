import { useMemo } from "react";
import { useSearchParams } from "react-router-dom";
import { api } from "../api/client";
import type { RunOut } from "../api/types";
import { useEngagement } from "../auth/EngagementContext";
import { isFinished } from "./labels";
import { useAsync } from "./useAsync";

/** Прогоны текущего договора и выбранный прогон (?run=ID, иначе последний завершённый). */
export function useRunSelection() {
  const { current } = useEngagement();
  const [params, setParams] = useSearchParams();
  const runs = useAsync<RunOut[]>(() => api.runs(current!.id), [current?.id], !!current);
  const list = useMemo(() => [...(runs.data ?? [])].sort((a, b) => b.id - a.id), [runs.data]);
  const requested = Number(params.get("run"));
  const run = useMemo(() => {
    if (requested) return list.find((r) => r.id === requested) ?? null;
    return list.find((r) => isFinished(r.status) && r.status !== "failed") ?? list.find((r) => isFinished(r.status)) ?? null;
  }, [list, requested]);
  const setRun = (id: number) => {
    const next = new URLSearchParams(params);
    next.set("run", String(id));
    setParams(next, { replace: true });
  };
  return { engagement: current, runs: list, run, setRun, loading: runs.loading, error: runs.error, reload: runs.reload };
}
