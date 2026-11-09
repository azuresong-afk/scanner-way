import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { api } from "../api/client";
import type { SystemHealth } from "../api/types";
import { useAuth } from "../auth/AuthContext";

const POLL_MS = 60000;

/** Плашка в шапке: появляется, только когда со сканером что-то не так, и ведёт на «Состояние». */
export function HealthChip() {
  const { has } = useAuth();
  const canView = has("view_engagements");
  const [health, setHealth] = useState<SystemHealth | null>(null);

  useEffect(() => {
    if (!canView) return;
    let alive = true;
    let timer: ReturnType<typeof setTimeout> | undefined;
    const tick = async () => {
      if (typeof document === "undefined" || document.visibilityState !== "hidden") {
        try {
          const h = await api.systemHealth();
          if (alive) setHealth(h);
        } catch {
          // сеть моргнула — оставляем прежнее состояние до следующего опроса
        }
      }
      if (alive) timer = setTimeout(tick, POLL_MS);
    };
    void tick();
    return () => {
      alive = false;
      if (timer) clearTimeout(timer);
    };
  }, [canView]);

  if (!health || (health.status !== "warn" && health.status !== "error")) return null;
  const bad = health.components.filter((c) => c.status === health.status).map((c) => c.title);
  const label = health.status === "error" ? "Сбой сканера" : "Сканер: внимание";
  const title = `${label}: ${bad.join(", ")}`;
  return (
    <Link to="/health" className={`health-chip ${health.status}`} title={title} aria-label={title}>
      <span className="health-chip-dot" aria-hidden="true" />
      <span>{label}</span>
      <span className="health-chip-what hide-sm">{bad.join(", ")}</span>
    </Link>
  );
}
