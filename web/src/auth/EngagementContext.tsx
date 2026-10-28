import { createContext, useCallback, useContext, useEffect, useMemo, useState, type ReactNode } from "react";
import { api } from "../api/client";
import type { EngagementOut } from "../api/types";
import { useAuth } from "./AuthContext";

const KEY = "scanner.engagement";

interface EngagementValue {
  engagements: EngagementOut[];
  current: EngagementOut | null;
  select: (id: number) => void;
  reload: () => Promise<void>;
  loading: boolean;
  error: Error | null;
}

const Ctx = createContext<EngagementValue | null>(null);

function savedId(): number | null {
  try {
    const v = Number(localStorage.getItem(KEY));
    return Number.isInteger(v) && v > 0 ? v : null;
  } catch {
    return null;
  }
}

/** Текущий договор — общий контекст для дашборда, прогонов, находок и хостов. */
export function EngagementProvider({ children }: { children: ReactNode }) {
  const { me, has } = useAuth();
  const [engagements, setEngagements] = useState<EngagementOut[]>([]);
  const [currentId, setCurrentId] = useState<number | null>(savedId);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<Error | null>(null);
  const canView = has("view_engagements");

  const reload = useCallback(async () => {
    if (!canView) {
      setLoading(false);
      return;
    }
    setLoading(true);
    try {
      setEngagements(await api.engagements());
      setError(null);
    } catch (e) {
      setError(e as Error);
    } finally {
      setLoading(false);
    }
  }, [canView]);

  useEffect(() => {
    if (me) void reload();
  }, [me, reload]);

  const select = useCallback((id: number) => {
    setCurrentId(id);
    try {
      localStorage.setItem(KEY, String(id));
    } catch {
      /* ignore */
    }
  }, []);

  const current = useMemo(() => {
    if (!engagements.length) return null;
    return engagements.find((e) => e.id === currentId) ?? engagements[engagements.length - 1];
  }, [engagements, currentId]);

  const value = useMemo(
    () => ({ engagements, current, select, reload, loading, error }),
    [engagements, current, select, reload, loading, error],
  );
  return <Ctx.Provider value={value}>{children}</Ctx.Provider>;
}

export function useEngagement(): EngagementValue {
  const v = useContext(Ctx);
  if (!v) throw new Error("useEngagement outside EngagementProvider");
  return v;
}
