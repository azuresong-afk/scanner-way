import { useMemo, useState } from "react";
import { Link, useParams } from "react-router-dom";
import { Radar } from "lucide-react";
import { api } from "../api/client";
import { useAuth } from "../auth/AuthContext";
import { useEngagement } from "../auth/EngagementContext";
import type { FindingOut, PackageOut } from "../api/types";
import { SeverityBars } from "../components/charts/SeverityBars";
import { FindingDrawer } from "../components/FindingDrawer";
import { FindingsTable } from "../components/FindingsTable";
import { ReachabilityCheck } from "../components/ReachabilityCheck";
import { RunPicker } from "../components/RunPicker";
import { ServicesTable } from "../components/ServicesTable";
import { SoftwareTable } from "../components/SoftwareTable";
import { Empty, ErrorAlert, Kpi, Loading, Modal } from "../components/ui";
import { byHost, isFalsePositive, isIssue, replaceFinding } from "../lib/stats";
import { useAsync } from "../lib/useAsync";
import { useRunSelection } from "../lib/useRunSelection";

type VulnView = "software" | "list";
const VIEWS: { id: VulnView; label: string }[] = [
  { id: "software", label: "По ПО" },
  { id: "list", label: "Списком" },
];
const VIEW_KEY = "scanner.host.vulnView";

function loadView(): VulnView {
  try {
    return localStorage.getItem(VIEW_KEY) === "list" ? "list" : "software";
  } catch {
    return "software";
  }
}

function saveView(v: VulnView) {
  try {
    localStorage.setItem(VIEW_KEY, v);
  } catch {
    // без localStorage — просто не запоминаем
  }
}

/** Детальная информация по хосту: сервисы и все его уязвимости в выбранном прогоне. */
export function HostDetailPage() {
  const host = decodeURIComponent(useParams().host ?? "");
  const { runs, run, setRun, loading, error } = useRunSelection();
  const data = useAsync(
    async () => {
      const withPackages = run!.modules.includes("auth_inventory");
      const [findings, services, packages] = await Promise.all([
        api.findings(run!.id),
        api.services(run!.id),
        withPackages ? api.packages(run!.id, host) : Promise.resolve([]),
      ]);
      return { findings: findings.filter((f) => f.host === host), services: services.filter((s) => s.host === host), packages };
    },
    [run?.id, host],
    !!run,
  );
  const [open, setOpen] = useState<FindingOut | null>(null);
  const [checking, setChecking] = useState(false);
  const [view, setView] = useState<VulnView>(loadView);
  const { has } = useAuth();
  const { current } = useEngagement();
  const row = useMemo(() => (data.data ? byHost(data.data.findings.filter(isIssue), data.data.services)[0] : undefined), [data.data]);
  const info = data.data?.findings.filter((f) => f.severity === "info" && !isFalsePositive(f)) ?? [];
  const falsePositives = data.data?.findings.filter(isFalsePositive) ?? [];

  return (
    <>
      <div className="page-head">
        <div>
          <span className="crumbs">
            <Link to={run ? `/hosts?run=${run.id}` : "/hosts"}>Хосты</Link> / {host}
          </span>
          <h1 className="mono" style={{ fontSize: 24 }}>
            {host}
          </h1>
          {row?.summary && <span className="muted">{row.summary}</span>}
        </div>
        <div className="actions">
          {has("run_scan") && current && (
            <button type="button" className="btn" onClick={() => setChecking(true)}>
              <Radar size={15} /> Проверить доступность
            </button>
          )}
          {runs.length > 0 && <RunPicker runs={runs} value={run?.id ?? null} onChange={setRun} />}
        </div>
      </div>
      {error && <ErrorAlert error={error} />}
      {data.error && <ErrorAlert error={data.error} onRetry={data.reload} />}
      {(loading && !runs.length) || (data.loading && !data.data) ? (
        <Loading />
      ) : !run ? (
        <div className="card">
          <Empty title="Нет завершённых прогонов" />
        </div>
      ) : !row ? (
        <div className="card">
          <Empty title="Хост не найден в этом прогоне" />
        </div>
      ) : (
        <>
          <section className="kpis">
            <Kpi label="Уязвимостей" value={row.total} />
            <Kpi label="Критических" value={row.counts.critical} tone={row.counts.critical ? "critical" : undefined} />
            <Kpi label="Высоких" value={row.counts.high} tone={row.counts.high ? "warn" : undefined} />
            <Kpi label="Открытых портов" value={row.services.length} />
            <Kpi label="С привязкой к БДУ" value={row.findings.filter((f) => f.bdu_ids.length).length} />
          </section>
          <section className="row">
            <div className="card card-pad grow-1 stack" style={{ gap: 14, alignSelf: "flex-start" }}>
              <h2>По уровню опасности</h2>
              <SeverityBars counts={row.counts} />
            </div>
            <div className="card grow-2" style={{ overflow: "hidden", alignSelf: "flex-start" }}>
              <div className="card-head">
                <h2>Сервисы</h2>
              </div>
              <ServicesTable services={row.services} />
            </div>
          </section>
          <section className="card" style={{ overflow: "hidden" }}>
            <div className="card-head">
              <h2>Уязвимости хоста</h2>
              <div className="seg seg-sm" role="radiogroup" aria-label="Вид списка уязвимостей">
                {VIEWS.map((v) => (
                  <button
                    key={v.id}
                    type="button"
                    role="radio"
                    aria-checked={view === v.id}
                    onClick={() => {
                      setView(v.id);
                      saveView(v.id);
                    }}
                  >
                    {v.label}
                  </button>
                ))}
              </div>
            </div>
            {!row.findings.length ? (
              <Empty title="Уязвимостей не найдено" />
            ) : view === "software" ? (
              <SoftwareTable findings={row.findings} services={row.services} onOpen={setOpen} selected={open} />
            ) : (
              <FindingsTable findings={row.findings} onOpen={setOpen} selected={open} hideHost />
            )}
          </section>
          {falsePositives.length > 0 && (
            <details className="card">
              <summary style={{ padding: "14px 20px", cursor: "pointer", fontWeight: 600 }}>Ложные срабатывания ({falsePositives.length})</summary>
              <FindingsTable findings={falsePositives} onOpen={setOpen} selected={open} hideHost />
            </details>
          )}
          {data.data!.packages.length > 0 && <PackagesCard packages={data.data!.packages} />}
          {info.length > 0 && (
            <details className="card">
              <summary style={{ padding: "14px 20px", cursor: "pointer", fontWeight: 600 }}>Информационные находки ({info.length})</summary>
              <FindingsTable findings={info} onOpen={setOpen} selected={open} hideHost />
            </details>
          )}
        </>
      )}
      {open && (
        <FindingDrawer
          finding={open}
          onClose={() => setOpen(null)}
          onChanged={(u) => {
            if (data.data) data.setData({ ...data.data, findings: replaceFinding(data.data.findings, u) });
            setOpen(u);
          }}
        />
      )}
      {checking && current && (
        <Modal title="Проверка доступности хоста" onClose={() => setChecking(false)} wide>
          <ReachabilityCheck engagementId={current.id} initialTarget={host} />
        </Modal>
      )}
    </>
  );
}

/** Установленные пакеты хоста (инвентаризация по учётной записи), с поиском. */
function PackagesCard({ packages }: { packages: PackageOut[] }) {
  const [q, setQ] = useState("");
  const needle = q.trim().toLowerCase();
  const shown = needle ? packages.filter((p) => p.name.toLowerCase().includes(needle) || p.version.toLowerCase().includes(needle)) : packages;
  return (
    <details className="card">
      <summary style={{ padding: "14px 20px", cursor: "pointer", fontWeight: 600 }}>
        Установленные пакеты ({packages.length}) — по учётной записи
      </summary>
      <div style={{ padding: "0 20px 12px" }}>
        <input className="input" value={q} onChange={(e) => setQ(e.target.value)} placeholder="Поиск по имени или версии" aria-label="Поиск пакета" />
      </div>
      <div className="table-wrap" style={{ maxHeight: 480, overflowY: "auto" }}>
        <table className="table">
          <thead>
            <tr>
              <th>Пакет</th>
              <th>Версия</th>
              <th>Архитектура</th>
              <th>Менеджер</th>
            </tr>
          </thead>
          <tbody>
            {shown.slice(0, 2000).map((p) => (
              <tr key={`${p.manager}:${p.name}:${p.version}`}>
                <td className="mono">{p.name}</td>
                <td className="mono muted">{p.version}</td>
                <td className="muted">{p.arch ?? "—"}</td>
                <td className="muted">{p.manager}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </details>
  );
}
