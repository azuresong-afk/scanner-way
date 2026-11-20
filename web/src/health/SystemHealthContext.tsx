import { createContext, useContext, useEffect, useMemo, useState, type ReactNode } from "react";
import { api, ApiError } from "../api/client";
import type { SystemHealth } from "../api/types";

/**
 * Состояние самого сервиса для лампочки «Состояние» в меню: отвечает ли API.
 * on — ответ пришёл; off — ответа нет или сервер ответил 5xx; unknown — ещё не проверяли.
 */
export type ServiceState = "on" | "off" | "unknown";

/** Как часто спрашивать /system/health: лампочка в меню и плашка в шапке берут один общий ответ. */
export const HEALTH_POLL_MS = 30000;

interface SystemHealthValue {
  /** Последний полученный ответ /system/health (для плашки в шапке). */
  health: SystemHealth | null;
  service: ServiceState;
}

const SystemHealthCtx = createContext<SystemHealthValue>({ health: null, service: "unknown" });

/** Опрашивает /system/health раз в 30 секунд, пока вкладка браузера открыта. */
export function SystemHealthProvider({ enabled, children }: { enabled: boolean; children: ReactNode }) {
  const [health, setHealth] = useState<SystemHealth | null>(null);
  const [service, setService] = useState<ServiceState>("unknown");

  useEffect(() => {
    if (!enabled) return;
    let alive = true;
    let timer: ReturnType<typeof setTimeout> | undefined;
    const tick = async () => {
      if (typeof document === "undefined" || document.visibilityState !== "hidden") {
        try {
          const h = await api.systemHealth();
          if (alive) {
            setHealth(h);
            setService("on");
          }
        } catch (e) {
          // нет ответа или 5xx — сервис не работает; 401/403 — это про вход, а не про сервис
          const status = e instanceof ApiError ? e.status : 0;
          if (alive && (status === 0 || status >= 500)) setService("off");
        }
      }
      if (alive) timer = setTimeout(tick, HEALTH_POLL_MS);
    };
    void tick();
    return () => {
      alive = false;
      if (timer) clearTimeout(timer);
    };
  }, [enabled]);

  const value = useMemo(() => ({ health, service }), [health, service]);
  return <SystemHealthCtx.Provider value={value}>{children}</SystemHealthCtx.Provider>;
}

export function useSystemHealth(): SystemHealthValue {
  return useContext(SystemHealthCtx);
}
