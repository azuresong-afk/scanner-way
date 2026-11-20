import { Link } from "react-router-dom";
import { useSystemHealth } from "../health/SystemHealthContext";

/** Плашка в шапке: появляется, только когда со сканером что-то не так, и ведёт на «Состояние». */
export function HealthChip() {
  // опрос /system/health общий с лампочкой «Состояние» в меню (SystemHealthProvider)
  const { health } = useSystemHealth();

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
