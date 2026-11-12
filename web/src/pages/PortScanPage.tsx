import { useEffect, useState, type FormEvent } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { ListChecks, Network, Wifi } from "lucide-react";
import { ApiError, api } from "../api/client";
import type { DeniedTarget, PortMode, PortScanDetail, PortScanOut, PortScanStatus } from "../api/types";
import { useAuth } from "../auth/AuthContext";
import { useEngagement } from "../auth/EngagementContext";
import { HostPicker } from "../components/HostPicker";
import { Empty, ErrorAlert, Kpi, Loading } from "../components/ui";
import { fmtDate, fmtDuration } from "../lib/format";
import { RATE_PROFILES } from "../lib/labels";
import { countPorts, parsePortSpec, PORT_PRESETS, subtractRanges } from "../lib/ports";
import { compactAddresses, mergeTargets, parseTargets, specSize, splitTargets } from "../lib/targets";
import { useAsync, useInterval } from "../lib/useAsync";

const STATUS: Record<PortScanStatus, [string, string]> = {
  queued: ["В очереди", "pill-running"],
  running: ["Идёт", "pill-running"],
  done: ["Готово", "pill-ok"],
  failed: ["Ошибка", "pill-danger"],
  stopped: ["Остановлена", "pill-muted"],
  interrupted: ["Прервана", "pill-warn"],
};
const isActive = (s: PortScanStatus) => s === "queued" || s === "running";

const DENIED_REASON: Record<string, string> = {
  not_in_allowlist: "вне allowlist",
  not_an_ip: "не адрес",
  too_many_targets: "слишком много адресов",
};

function errorMessage(err: unknown): string {
  if (!(err instanceof ApiError)) return (err as Error).message;
  if (err.status === 403) return "Недостаточно прав: проверка доступности требует права на запуск прогонов.";
  if (err.status === 429)
    return err.message.includes("in progress")
      ? "У вас уже идут две проверки — дождитесь окончания одной из них."
      : "Слишком много проверок подряд. Повторите через минуту.";
  if (err.message.includes("allowlist")) return "Ни один адрес не входит в allowlist проекта — проверять их нельзя.";
  return err.message.replace(/^ports: /, "Порты: ");
}

function portsLabel(s: PortScanOut): string {
  const base = s.port_mode === "top" ? "1000 популярных" : (s.ports ?? "");
  return s.exclude_ports ? `${base}, кроме ${s.exclude_ports}` : base;
}

/**
 * Проверка сетевой доступности: какие хосты из allowlist в сети и какие на них
 * открыты TCP-порты (nmap, без прогона). Живые хосты попадают в «Активы» —
 * даже если учётных записей для глубокой проверки к ним пока нет.
 */
export function PortScanPage() {
  const { has } = useAuth();
  const { current } = useEngagement();
  const [params, setParams] = useSearchParams();
  const canRun = has("run_scan");
  const eid = current?.id;

  const allowlist = useAsync(() => api.allowlist(eid!), [eid], !!eid);
  const scans = useAsync(() => api.portScans(eid!), [eid], !!eid);
  const selectedId = Number(params.get("scan")) || scans.data?.[0]?.id || null;
  const detail = useAsync<PortScanDetail | undefined>(() => (selectedId ? api.portScan(selectedId) : Promise.resolve(undefined)), [selectedId]);
  const running = !!detail.data && isActive(detail.data.status);
  useInterval(
    () => {
      void detail.reload();
      void scans.reload();
    },
    2000,
    running,
  );

  if (!current) {
    return (
      <div className="card">
        <Empty title="Выберите или создайте проект" />
      </div>
    );
  }

  const select = (id: number) =>
    setParams((p) => {
      const n = new URLSearchParams(p);
      n.set("scan", String(id));
      return n;
    });

  return (
    <>
      <div className="page-head">
        <div>
          <span className="crumbs">{current.client ? `${current.client} · ${current.name}` : current.name}</span>
          <h1>Сетевой поиск</h1>
        </div>
      </div>

      {canRun && (
        <ScanForm
          engagementId={current.id}
          allowlist={(allowlist.data ?? []).map((a) => a.cidr)}
          initialTarget={params.get("target") ?? ""}
          onStarted={async (id) => {
            await scans.reload();
            select(id);
          }}
        />
      )}

      {scans.error && <ErrorAlert error={scans.error} onRetry={scans.reload} />}
      {scans.loading && !scans.data ? (
        <Loading />
      ) : !scans.data?.length ? (
        <div className="card">
          <Empty title="Проверок пока не было" icon={<Wifi size={28} />}>
            Укажите адреса из allowlist и порты — сканер покажет, какие хосты в сети и что на них открыто, и добавит найденные хосты в «Активы».
          </Empty>
        </div>
      ) : (
        <>
          {detail.error && <ErrorAlert error={detail.error} onRetry={detail.reload} />}
          {detail.data && <ScanResult scan={detail.data} canStop={canRun} onStopped={detail.reload} />}
          <ScanHistory scans={scans.data} selected={selectedId} onSelect={select} />
        </>
      )}
    </>
  );
}

function ScanForm({
  engagementId,
  allowlist,
  initialTarget,
  onStarted,
}: {
  engagementId: number;
  allowlist: string[];
  initialTarget: string;
  onStarted: (id: number) => void | Promise<void>;
}) {
  const [targets, setTargets] = useState(initialTarget);
  const [mode, setMode] = useState<PortMode>("top");
  const [ports, setPorts] = useState("");
  const [exclude, setExclude] = useState("");
  const [noPing, setNoPing] = useState(false);
  const [services, setServices] = useState(false);
  const [rate, setRate] = useState("gentle");
  const [picking, setPicking] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [denied, setDenied] = useState<DeniedTarget[]>([]);

  useEffect(() => {
    if (initialTarget) setTargets((t) => mergeTargets(t, [initialTarget]));
  }, [initialTarget]);

  const parsed = parseTargets(targets);
  const addressCount = parsed.targets.reduce((n, t) => n + specSize(t), 0);
  const portRanges = parsePortSpec(ports);
  const excludeRanges = parsePortSpec(exclude);
  const portError =
    typeof excludeRanges === "string"
      ? `Исключения: ${excludeRanges}`
      : mode === "list"
        ? typeof portRanges === "string"
          ? `Порты: ${portRanges}`
          : portRanges.length && !subtractRanges(portRanges, excludeRanges).length
            ? "После исключений не осталось ни одного порта"
            : null
        : null;
  // в режиме «1000 популярных» исключения могут не пересекаться с набором nmap — число не показываем
  const portCount =
    mode === "list" && typeof portRanges !== "string" && typeof excludeRanges !== "string" && portRanges.length
      ? countPorts(subtractRanges(portRanges, excludeRanges))
      : null;
  const allowSpecs = allowlist;
  const current = new Set(splitTargets(targets));
  const canSubmit =
    parsed.targets.length > 0 &&
    parsed.invalid.length === 0 &&
    !portError &&
    (mode === "top" || (typeof portRanges !== "string" && portRanges.length > 0)) &&
    !busy;

  const submit = async (ev: FormEvent) => {
    ev.preventDefault();
    setBusy(true);
    setError(null);
    setDenied([]);
    try {
      const r = await api.startPortScan(engagementId, {
        targets: parsed.targets,
        port_mode: mode,
        ports: mode === "list" ? ports : undefined,
        exclude_ports: exclude.trim() || undefined,
        no_ping: noPing,
        service_detection: services,
        rate_profile: rate,
      });
      setDenied(r.denied_targets);
      await onStarted(r.id);
    } catch (err) {
      setError(errorMessage(err));
    } finally {
      setBusy(false);
    }
  };

  if (picking) {
    return (
      <HostPicker
        engagementId={engagementId}
        allowlist={allowlist}
        mode="run"
        onClose={() => setPicking(false)}
        onPick={(addrs) => {
          setTargets((t) => mergeTargets(t, compactAddresses(addrs)));
          setPicking(false);
        }}
      />
    );
  }

  return (
    <form className="card card-pad stack" style={{ gap: "var(--s3)" }} onSubmit={submit} aria-label="Новая проверка доступности">
      <div className="row">
        <div className="field grow-3" style={{ flex: "1 1 320px" }}>
          <span id="ps-targets-label">Адреса — IP, подсети и диапазоны, по одной записи в строке</span>
          <textarea
            aria-labelledby="ps-targets-label"
            className="textarea mono"
            rows={4}
            value={targets}
            onChange={(e) => setTargets(e.target.value)}
            placeholder={"10.0.0.0/24\n10.0.1.15\n10.0.2.10-40"}
            spellCheck={false}
          />
          <div className="inline" style={{ gap: 6, flexWrap: "wrap" }}>
            <button type="button" className="btn btn-sm" onClick={() => setPicking(true)}>
              <ListChecks size={14} /> Из активов…
            </button>
            {allowSpecs.map((spec) => (
              <button
                key={spec}
                type="button"
                className="chip mono"
                aria-pressed={current.has(spec)}
                onClick={() =>
                  setTargets((t) =>
                    splitTargets(t).includes(spec)
                      ? splitTargets(t)
                          .filter((x) => x !== spec)
                          .join("\n")
                      : mergeTargets(t, [spec]),
                  )
                }
              >
                {spec}
              </button>
            ))}
            {parsed.targets.length > 0 && <small className="muted">до {addressCount.toLocaleString("ru-RU")} адресов</small>}
          </div>
          {parsed.invalid.length > 0 && <small style={{ color: "var(--danger-text, var(--danger))" }}>Не адрес: {parsed.invalid.join(", ")}</small>}
        </div>

        <div className="stack grow-2" style={{ gap: "var(--s2)", flex: "1 1 320px" }}>
          <div className="field">
            <span>Порты</span>
            <div className="seg" role="radiogroup" aria-label="Какие порты проверять">
              <button type="button" role="radio" aria-checked={mode === "top"} onClick={() => setMode("top")}>
                1000 популярных
              </button>
              <button type="button" role="radio" aria-checked={mode === "list"} onClick={() => setMode("list")}>
                Свой список
              </button>
            </div>
          </div>
          {mode === "list" && (
            <label className="field">
              <span>Порты через запятую, диапазоны через дефис</span>
              <input className="input mono" value={ports} onChange={(e) => setPorts(e.target.value)} placeholder="22, 80, 443, 8000-8100" />
              <div className="inline" style={{ gap: 6, flexWrap: "wrap" }}>
                {PORT_PRESETS.map((p) => (
                  <button key={p.label} type="button" className="chip" aria-pressed={ports === p.ports} onClick={() => setPorts(p.ports)}>
                    {p.label}
                  </button>
                ))}
              </div>
            </label>
          )}
          <label className="field">
            <span>Исключить порты</span>
            <input className="input mono" value={exclude} onChange={(e) => setExclude(e.target.value)} placeholder="например 9100, 515, 631 — принтеры" />
          </label>
          <div
            className="inline"
            style={{
              gap: "var(--s3)",
              flexWrap: "wrap",
              alignItems: "flex-start",
            }}
          >
            <label className="check">
              <input type="checkbox" checked={noPing} onChange={(e) => setNoPing(e.target.checked)} />
              <span>
                <b>Без проверки ping (-Pn)</b>
                <small>если ICMP закрыт; дольше</small>
              </span>
            </label>
            <label className="check">
              <input type="checkbox" checked={services} onChange={(e) => setServices(e.target.checked)} />
              <span>
                <b>Определять сервисы (-sV)</b>
                <small>версии ПО на портах; дольше</small>
              </span>
            </label>
          </div>
        </div>
      </div>

      {error && <ErrorAlert error={error} />}
      {portError && <small style={{ color: "var(--danger-text, var(--danger))" }}>{portError}</small>}
      {denied.length > 0 && (
        <small className="muted">
          Не проверяются: {denied.map((d) => `${d.target} — ${DENIED_REASON[d.reason] ?? d.reason}${d.count > 1 ? ` (${d.count})` : ""}`).join("; ")}
        </small>
      )}

      <div
        className="inline"
        style={{
          justifyContent: "space-between",
          flexWrap: "wrap",
          gap: "var(--s2)",
        }}
      >
        <small className="faint" style={{ fontSize: 12, maxWidth: 640 }}>
          nmap с лимитами профиля интенсивности, только адреса из allowlist; каждая проверка — в журнале аудита. Хосты, ответившие в сети, добавляются в
          «Активы».
        </small>
        <div className="inline" style={{ gap: 8 }}>
          <select className="select" aria-label="Интенсивность" value={rate} onChange={(e) => setRate(e.target.value)}>
            {RATE_PROFILES.map((p) => (
              <option key={p.id} value={p.id}>
                {p.label}
              </option>
            ))}
          </select>
          <button type="submit" className="btn btn-primary" disabled={!canSubmit}>
            <Network size={16} />{" "}
            {busy ? "Запускаем…" : `Проверить${portCount !== null ? ` · ${portCount.toLocaleString("ru-RU")} ${portCount === 1 ? "порт" : "портов"}` : ""}`}
          </button>
        </div>
      </div>
    </form>
  );
}

function ScanResult({ scan, canStop, onStopped }: { scan: PortScanDetail; canStop: boolean; onStopped: () => void }) {
  const [onlyUp, setOnlyUp] = useState(true);
  const [stopping, setStopping] = useState(false);
  const [label, tone] = STATUS[scan.status];
  const active = isActive(scan.status);
  const pct = scan.hosts_total ? Math.round((scan.hosts_done / scan.hosts_total) * 100) : 0;
  const rows = onlyUp ? scan.results.filter((h) => h.up) : scan.results;

  const stop = async () => {
    setStopping(true);
    try {
      await api.stopPortScan(scan.id);
      onStopped();
    } finally {
      setStopping(false);
    }
  };

  return (
    <section className="card card-pad stack" style={{ gap: "var(--s3)" }} aria-label="Результат проверки">
      <div
        className="inline"
        style={{
          justifyContent: "space-between",
          flexWrap: "wrap",
          gap: "var(--s2)",
        }}
      >
        <div className="stack" style={{ gap: 2 }}>
          <h2 className="inline" style={{ gap: 8 }}>
            Проверка от {fmtDate(scan.created_at)} <span className={`pill ${tone}`}>{label}</span>
          </h2>
          <small className="muted">
            {scan.requested_targets.join(", ")} · порты: {portsLabel(scan)}
            {scan.no_ping ? " · без ping" : ""}
            {scan.service_detection ? " · с сервисами" : ""}
            {scan.actor ? ` · ${scan.actor.replace(/^user:/, "")}` : ""}
          </small>
        </div>
        {active && canStop && (
          <button type="button" className="btn" onClick={stop} disabled={stopping}>
            Остановить
          </button>
        )}
      </div>

      {active && (
        <div role="status" className="stack" style={{ gap: 4 }}>
          <div
            style={{
              height: 6,
              background: "var(--border)",
              borderRadius: 3,
              overflow: "hidden",
            }}
            aria-label={`Проверено ${pct}%`}
          >
            <div
              style={{
                width: `${pct}%`,
                height: "100%",
                background: "var(--accent)",
                transition: "width .3s",
              }}
            />
          </div>
          <small className="muted">
            Проверено {scan.hosts_done} из {scan.hosts_total} адресов · идёт {fmtDuration(scan.started_at ?? scan.created_at, null)}
          </small>
        </div>
      )}
      {scan.error && <div className={`alert ${scan.status === "interrupted" ? "alert-warn" : "alert-danger"}`}>{scan.error}</div>}

      <div className="kpis" style={{ gridTemplateColumns: "repeat(auto-fit, minmax(140px, 1fr))" }}>
        <Kpi label="Адресов проверено" value={`${scan.hosts_done} / ${scan.hosts_total}`} />
        <Kpi label="Хостов в сети" value={scan.hosts_up} />
        <Kpi label="Открытых портов" value={scan.open_ports} />
        <Kpi label="Добавлено в «Активы»" value={scan.assets_created} />
      </div>

      <div className="inline" style={{ justifyContent: "space-between" }}>
        <label className="check">
          <input type="checkbox" checked={onlyUp} onChange={(e) => setOnlyUp(e.target.checked)} />
          <span>
            <b>Только хосты в сети</b>
          </span>
        </label>
        {!active && <small className="muted">Длилась {fmtDuration(scan.started_at ?? scan.created_at, scan.finished_at)}</small>}
      </div>

      {rows.length === 0 ? (
        <Empty title={active ? "Пока никто не ответил" : "Ни один хост не ответил"}>
          {active
            ? "Результаты появятся по мере проверки."
            : scan.no_ping
              ? "Хосты выключены или все порты фильтруются межсетевым экраном."
              : "Если ICMP в сети заблокирован — повторите с опцией «Без проверки ping (-Pn)»."}
        </Empty>
      ) : (
        <div className="table-wrap">
          <table className="table">
            <thead>
              <tr>
                <th>Хост</th>
                <th>Состояние</th>
                <th>Открытые порты</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((h) => (
                <tr key={h.host}>
                  <td className="nowrap">
                    {h.up ? (
                      <Link className="mono" to={`/hosts/${encodeURIComponent(h.host)}`}>
                        {h.host}
                      </Link>
                    ) : (
                      <span className="mono muted">{h.host}</span>
                    )}
                    {h.hostname && (
                      <div className="faint" style={{ fontSize: 12 }}>
                        {h.hostname}
                      </div>
                    )}
                  </td>
                  <td className="nowrap">
                    {h.up ? (
                      <span className="pill pill-ok">в сети</span>
                    ) : h.reason === "not_in_allowlist" ? (
                      <span className="pill pill-warn">исключён из allowlist</span>
                    ) : (
                      <span className="pill pill-muted">нет ответа</span>
                    )}
                  </td>
                  <td>
                    {h.ports.length ? (
                      <div className="inline" style={{ gap: 4, flexWrap: "wrap" }}>
                        {h.ports.map((p) => (
                          <span
                            key={`${p.protocol}${p.port}`}
                            className="chip chip-static mono"
                            style={{ whiteSpace: "nowrap" }}
                            title={[p.product, p.version].filter(Boolean).join(" ") || undefined}
                          >
                            {p.port}
                            {p.service ? `/${p.service}` : ""}
                            {p.product ? ` · ${p.product}${p.version ? ` ${p.version}` : ""}` : ""}
                          </span>
                        ))}
                      </div>
                    ) : (
                      <span className="faint">{h.up ? "ответил, открытых портов нет" : "—"}</span>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </section>
  );
}

function ScanHistory({ scans, selected, onSelect }: { scans: PortScanOut[]; selected: number | null; onSelect: (id: number) => void }) {
  return (
    <section className="card" style={{ overflow: "hidden" }} aria-label="История проверок">
      <div className="card-pad" style={{ paddingBottom: 0 }}>
        <h2>История проверок</h2>
      </div>
      <div className="table-wrap">
        <table className="table">
          <thead>
            <tr>
              <th>Когда</th>
              <th>Адреса</th>
              <th>Порты</th>
              <th>В сети</th>
              <th>Статус</th>
            </tr>
          </thead>
          <tbody>
            {scans.map((s) => {
              const [label, tone] = STATUS[s.status];
              return (
                <tr
                  key={s.id}
                  className="clickable"
                  aria-selected={s.id === selected}
                  style={s.id === selected ? { background: "var(--accent-soft)" } : undefined}
                  onClick={() => onSelect(s.id)}
                >
                  <td className="nowrap">{fmtDate(s.created_at)}</td>
                  <td
                    className="mono"
                    style={{
                      maxWidth: 280,
                      overflow: "hidden",
                      textOverflow: "ellipsis",
                      whiteSpace: "nowrap",
                    }}
                  >
                    {s.requested_targets.join(", ")}
                  </td>
                  <td className="muted">{portsLabel(s)}</td>
                  <td>
                    {s.hosts_up} из {s.hosts_total}
                  </td>
                  <td>
                    <span className={`pill ${tone}`}>{label}</span>
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    </section>
  );
}
