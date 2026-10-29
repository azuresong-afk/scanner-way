import { useState, type FormEvent } from "react";
import { Radar } from "lucide-react";
import { ApiError, api } from "../api/client";
import type { PortState, ReachabilityOut } from "../api/types";
import { fmtDate } from "../lib/format";
import { isSingleIp, parsePorts } from "../lib/targets";
import { ErrorAlert } from "./ui";

const DEFAULT_PORTS = "22, 80, 443, 445, 3389";
const MAX_PORTS = 10;
const HISTORY = 5;

const PORT_TONE: Record<PortState, string> = { open: "pill-ok", closed: "pill-muted", filtered: "pill-warn" };
const PORT_LABEL: Record<PortState, string> = { open: "открыт", closed: "закрыт", filtered: "нет ответа" };

/** Ответы API — на русском: allowlist, роль, лимит частоты. */
function errorMessage(err: unknown): string {
  if (!(err instanceof ApiError)) return (err as Error).message;
  if (err.status === 403) return "Недостаточно прав: проверка доступности требует права на запуск прогонов.";
  if (err.status === 429) return "Слишком много проверок подряд. Повторите через минуту.";
  if (err.message.includes("allowlist")) return "Адрес не входит в allowlist договора — проверять его нельзя.";
  if (err.message.includes("single IP")) return "Укажите один IP-адрес (без маски подсети и имени хоста).";
  return err.message;
}

/**
 * Проверка доступности одного хоста без полного прогона: ICMP + TCP connect к
 * нескольким портам. API пускает только адреса из allowlist и пишет каждую
 * попытку в журнал аудита.
 */
export function ReachabilityCheck({ engagementId, initialTarget = "" }: { engagementId: number; initialTarget?: string }) {
  const [target, setTarget] = useState(initialTarget);
  const [ports, setPorts] = useState(DEFAULT_PORTS);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [results, setResults] = useState<ReachabilityOut[]>([]);

  const submit = async (ev: FormEvent) => {
    ev.preventDefault();
    const host = target.trim();
    if (!isSingleIp(host)) {
      setError("Укажите один IP-адрес, например 10.0.0.5");
      return;
    }
    const list = parsePorts(ports);
    if (!list || !list.length || list.length > MAX_PORTS) {
      setError(`Порты: от 1 до ${MAX_PORTS} номеров в диапазоне 1–65535 через запятую`);
      return;
    }
    setBusy(true);
    setError(null);
    try {
      const r = await api.checkReachability(engagementId, { target: host, ports: list });
      setResults((prev) => [r, ...prev].slice(0, HISTORY));
    } catch (err) {
      setError(errorMessage(err));
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="stack" style={{ gap: "var(--s3)" }}>
      <form onSubmit={submit} className="inline" style={{ alignItems: "flex-end" }}>
        <label className="field" style={{ flex: "1 1 160px" }}>
          <span>IP-адрес</span>
          <input className="input mono" value={target} onChange={(ev) => setTarget(ev.target.value)} placeholder="10.0.0.5" />
        </label>
        <label className="field" style={{ flex: "2 1 200px" }}>
          <span>TCP-порты</span>
          <input className="input mono" value={ports} onChange={(ev) => setPorts(ev.target.value)} placeholder={DEFAULT_PORTS} />
        </label>
        <button type="submit" className="btn btn-primary" disabled={busy || !target.trim()}>
          <Radar size={16} /> {busy ? "Проверяем…" : "Проверить"}
        </button>
      </form>
      <small className="faint" style={{ fontSize: 12 }}>
        Один ICMP-запрос и TCP-подключение к указанным портам. Только адреса из allowlist; каждая проверка попадает в журнал аудита.
      </small>
      {error && <ErrorAlert error={error} />}
      {results.length > 0 && (
        <ul className="stack" style={{ listStyle: "none", margin: 0, padding: 0, gap: "var(--s2)" }} aria-label="Результаты проверки">
          {results.map((r) => (
            <ReachabilityRow key={r.checked_at + r.target} r={r} />
          ))}
        </ul>
      )}
    </div>
  );
}

function ReachabilityRow({ r }: { r: ReachabilityOut }) {
  const icmp = !r.icmp_available
    ? "ICMP: ping недоступен на сервере"
    : r.icmp_alive
      ? `ICMP: ответ${r.icmp_rtt_ms != null ? ` за ${r.icmp_rtt_ms} мс` : ""}`
      : "ICMP: нет ответа";
  return (
    <li className="stack" style={{ gap: 6, padding: "var(--s2) 0", borderTop: "1px solid var(--border)" }}>
      <div className="inline">
        <span className="mono" style={{ fontWeight: 600 }}>
          {r.target}
        </span>
        <span className={`pill ${r.reachable ? "pill-ok" : "pill-danger"}`}>{r.reachable ? "Доступен" : "Недоступен"}</span>
        <span className="faint" style={{ fontSize: 12, marginLeft: "auto" }}>
          {fmtDate(r.checked_at)} · {Math.round(r.elapsed_ms)} мс
        </span>
      </div>
      <div className="inline" style={{ fontSize: 13 }}>
        <span className="muted">{icmp}</span>
        {r.ports.map((p) => (
          <span key={p.port} className={`pill ${PORT_TONE[p.state]}`} title={p.rtt_ms != null ? `${p.rtt_ms} мс` : undefined}>
            {p.port} {PORT_LABEL[p.state]}
          </span>
        ))}
      </div>
      {!r.reachable && (
        <span className="faint" style={{ fontSize: 12 }}>
          Хост не ответил ни на ICMP, ни на TCP. Он может быть выключен или закрыт межсетевым экраном.
        </span>
      )}
    </li>
  );
}
