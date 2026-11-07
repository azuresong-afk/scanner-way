import { useState } from "react";
import { Activity, RefreshCw } from "lucide-react";
import { api } from "../api/client";
import type { HealthComponent, HealthItem, HealthStatus, SystemHealth } from "../api/types";
import { ErrorAlert, Loading } from "../components/ui";
import { fmtDate } from "../lib/format";
import { useAsync, useInterval } from "../lib/useAsync";

const HEALTH_LABEL: Record<HealthStatus, string> = {
  ok: "В порядке",
  warn: "Требует внимания",
  error: "Не работает",
  unknown: "Не проверено",
};

const HEALTH_PILL: Record<HealthStatus, string> = {
  ok: "pill-ok",
  warn: "pill-warn",
  error: "pill-danger",
  unknown: "pill-muted",
};

const BANNER: Record<HealthStatus, string> = {
  ok: "alert-ok",
  warn: "alert-warn",
  error: "alert-danger",
  unknown: "alert-info",
};

function bytes(n: unknown): string {
  if (typeof n !== "number") return "—";
  const units = ["Б", "КБ", "МБ", "ГБ", "ТБ"];
  let v = n;
  let i = 0;
  while (v >= 1024 && i < units.length - 1) {
    v /= 1024;
    i += 1;
  }
  return `${v.toFixed(i >= 3 ? 1 : 0)} ${units[i]}`;
}

/** Пояснение к строке компонента — своё для каждого вида проверки. */
function itemNote(componentId: string, it: HealthItem): string {
  switch (componentId) {
    case "engines":
      return [it.version ? `версия ${String(it.version)}` : it.status === "ok" ? "версия не определена" : "не установлен", String(it.purpose ?? "")]
        .filter(Boolean)
        .join(" · ");
    case "feeds": {
      const parts: string[] = [];
      if (typeof it.records === "number") parts.push(`записей: ${it.records.toLocaleString("ru-RU")}`);
      if (it.last_success_at) parts.push(`обновлён ${fmtDate(String(it.last_success_at))}`);
      if (it.state === "running") parts.push("идёт загрузка");
      if (it.state === "missing") parts.push(it.required ? "нет данных" : "не загружен (необязательный)");
      if (it.message && it.status !== "ok") parts.push(String(it.message));
      return parts.join(" · ");
    }
    case "disk":
      return it.free_bytes != null ? `свободно ${bytes(it.free_bytes)} из ${bytes(it.total_bytes)} (${String(it.free_percent)}%)` : String(it.error ?? "");
    case "nodes":
      return it.last_seen_at ? `последняя связь ${fmtDate(String(it.last_seen_at))}` : "ещё не подключался";
    case "notifications":
      return Number(it.failed_24h) > 0 ? `не доставлено за сутки: ${String(it.failed_24h)}` : "доставки без ошибок";
    default:
      return "";
  }
}

function ComponentCard({ c }: { c: HealthComponent }) {
  const [open, setOpen] = useState(c.status === "warn" || c.status === "error");
  return (
    <div className="card health-card" data-status={c.status}>
      <div className="health-card-head">
        <h3>{c.title}</h3>
        <span className={`pill ${HEALTH_PILL[c.status]}`}>{HEALTH_LABEL[c.status]}</span>
      </div>
      <p className="health-summary">{c.summary}</p>
      {c.hint && c.status !== "ok" && <p className="health-hint">{c.hint}</p>}
      {c.items.length > 0 && (
        <>
          <button type="button" className="btn btn-sm btn-ghost" onClick={() => setOpen((v) => !v)} aria-expanded={open}>
            {open ? "Скрыть подробности" : `Подробнее (${c.items.length})`}
          </button>
          {open && (
            <ul className="health-items">
              {c.items.map((it) => (
                <li key={String(it.id)}>
                  <span className={`pill ${HEALTH_PILL[it.status] ?? "pill-muted"}`} title={HEALTH_LABEL[it.status]}>
                    {String(it.title)}
                  </span>
                  <span className="faint">{itemNote(c.id, it)}</span>
                </li>
              ))}
            </ul>
          )}
        </>
      )}
    </div>
  );
}

/** «Состояние»: хелсчек самого сканера — что работает, что нет и что сделать. */
export function HealthPage() {
  const [refreshing, setRefreshing] = useState(false);
  const [forced, setForced] = useState<SystemHealth | null>(null);
  const [error, setError] = useState<string | null>(null);
  const health = useAsync(() => api.systemHealth(), []);
  useInterval(
    () => {
      setForced(null);
      void health.reload();
    },
    30000,
    true,
  );
  const data = forced ?? health.data;

  const refresh = async () => {
    setRefreshing(true);
    setError(null);
    try {
      setForced(await api.systemHealth(true));
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setRefreshing(false);
    }
  };

  const problems = data?.components.filter((c) => c.status === "warn" || c.status === "error") ?? [];

  return (
    <>
      <div className="page-head">
        <div>
          <span className="crumbs">Администрирование</span>
          <h1>Состояние сканера</h1>
        </div>
        <button type="button" className="btn" onClick={() => void refresh()} disabled={refreshing}>
          <RefreshCw size={14} className={refreshing ? "spin" : undefined} /> Проверить сейчас
        </button>
      </div>

      {error && <ErrorAlert error={error} />}
      {health.error && !data && <ErrorAlert error={health.error} onRetry={health.reload} />}

      {!data ? (
        <div className="card">
          <Loading label="Проверяем компоненты…" />
        </div>
      ) : (
        <>
          <div className={`alert ${BANNER[data.status]}`} role="status">
            <Activity size={16} />
            <div>
              <strong>{data.status === "ok" ? "Сканер работает штатно" : `Сканер: ${data.status_title}`}</strong>
              {problems.length > 0 && <> — {problems.map((c) => c.title.toLowerCase()).join(", ")}</>}
              <div className="faint" style={{ marginTop: 2 }}>
                Проверено {fmtDate(data.checked_at)}. Страница обновляется сама раз в 30 секунд.
              </div>
            </div>
          </div>
          <div className="health-grid">
            {data.components.map((c) => (
              <ComponentCard key={c.id} c={c} />
            ))}
          </div>
          <p className="faint" style={{ marginTop: 16 }}>
            Для внешнего мониторинга (Zabbix, Prometheus blackbox и т. п.): <code>/api/health/status</code> — статусы компонентов без подробностей
            (503, если что-то не работает), <code>/api/health/ready</code> — готовность службы. О сменах состояния сканер сообщает в каналы
            «Уведомлений», подписанные на событие «Состояние сканера».
          </p>
        </>
      )}
    </>
  );
}
