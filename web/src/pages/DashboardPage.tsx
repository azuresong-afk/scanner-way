import { useMemo, useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { Plus, Play, Radar, RotateCcw, Check, Server } from "lucide-react";
import { api } from "../api/client";
import type { FindingOut, RunOut, ServiceOut, Severity } from "../api/types";
import { useAuth } from "../auth/AuthContext";
import { useEngagement } from "../auth/EngagementContext";
import { SeverityStack } from "../components/charts/SeverityBars";
import { TrendChart, type TrendPoint } from "../components/charts/TrendChart";
import { FindingDrawer } from "../components/FindingDrawer";
import { ReportMenu } from "../components/ReportMenu";
import { StartRunModal } from "../components/StartRunModal";
import { Empty, ErrorAlert, Loading, RefTags, RunStatusPill, SeverityBadge } from "../components/ui";
import { fmtDate, fmtDelta, fmtNumber, plural } from "../lib/format";
import { isFinished, SEVERITY_LABEL, moduleList } from "../lib/labels";
import { byHost, compareFindings, isIssue, issueTotal, severityCounts, summarize, type HostRow, type RunSummary } from "../lib/stats";
import { useAsync } from "../lib/useAsync";

const TREND_RUNS = 10;

interface DashData {
  runs: RunOut[];
  latest: RunOut | null;
  previous: RunOut | null;
  findings: FindingOut[];
  prevFindings: FindingOut[] | null;
  services: ServiceOut[];
  prevServices: ServiceOut[];
  trend: TrendPoint[];
}

async function loadDashboard(engagementId: number): Promise<DashData> {
  const runs = (await api.runs(engagementId)).sort((a, b) => b.id - a.id);
  const finished = runs.filter((r) => isFinished(r.status) && r.status !== "failed");
  const recent = finished.slice(0, TREND_RUNS).reverse();
  const findingsByRun = await Promise.all(recent.map((r) => api.findings(r.id)));
  const latest = recent[recent.length - 1] ?? null;
  const previous = recent[recent.length - 2] ?? null;
  const [services, prevServices] = await Promise.all([
    latest ? api.services(latest.id) : Promise.resolve([]),
    previous ? api.services(previous.id) : Promise.resolve([]),
  ]);
  const trend = recent.map((r, i) => {
    const c = severityCounts(findingsByRun[i]);
    return { label: `№${r.id}`, sub: fmtDate(r.started_at ?? r.created_at), all: issueTotal(c), severe: c.critical + c.high };
  });
  return {
    runs,
    latest,
    previous,
    findings: findingsByRun[findingsByRun.length - 1] ?? [],
    prevFindings: previous ? findingsByRun[findingsByRun.length - 2] : null,
    services,
    prevServices,
    trend,
  };
}

type Nav = (to: string) => void;

function TrendLegend() {
  return (
    <div className="legend">
      <span>
        <i style={{ background: "var(--series-1)" }} />
        Все
      </span>
      <span>
        <i style={{ background: "var(--series-2)" }} />
        Критические и высокие
      </span>
    </div>
  );
}

function TrendCard({ d }: { d: DashData }) {
  return (
    <div className="card card-pad grow-3">
      <div className="inline" style={{ marginBottom: 8, justifyContent: "space-between" }}>
        <h2>Открытые уязвимости по прогонам</h2>
        <TrendLegend />
      </div>
      {d.trend.length > 1 ? (
        <TrendChart points={d.trend} />
      ) : (
        <Empty title="Тренд появится после второго прогона" />
      )}
    </div>
  );
}

function RunsTable({ runs, nav }: { runs: RunOut[]; nav: Nav }) {
  return (
    <div className="card" style={{ overflow: "hidden" }}>
      <div className="card-head">
        <h2>Последние прогоны</h2>
        <Link to="/runs" style={{ fontSize: 13 }}>
          Все прогоны
        </Link>
      </div>
      <div className="table-wrap">
        <table className="table" style={{ minWidth: 520 }}>
          <thead>
            <tr>
              <th>№</th>
              <th>Модули</th>
              <th>Статус</th>
              <th>Начат</th>
            </tr>
          </thead>
          <tbody>
            {runs.slice(0, 6).map((r) => (
              <tr key={r.id} className="clickable" onClick={() => nav(`/runs/${r.id}`)}>
                <td className="mono">
                  <Link to={`/runs/${r.id}`} onClick={(e) => e.stopPropagation()}>
                    #{r.id}
                  </Link>
                </td>
                <td className="muted">{moduleList(r.modules)}</td>
                <td>
                  <RunStatusPill status={r.status} />
                </td>
                <td className="muted nowrap">{fmtDate(r.started_at ?? r.created_at)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

function TopHosts({ hosts, latest }: { hosts: HostRow[]; latest: RunOut }) {
  return (
    <div className="card card-pad grow-2 stack" style={{ gap: 0 }}>
      <div className="inline" style={{ justifyContent: "space-between", marginBottom: 8 }}>
        <h2>Самые уязвимые хосты</h2>
        <Link to={`/hosts?run=${latest.id}`} style={{ fontSize: 13 }}>
          Все хосты
        </Link>
      </div>
      {hosts.length === 0 && <Empty title="Уязвимых хостов нет" />}
      {hosts.slice(0, 5).map((h) => (
        <Link
          key={h.host}
          to={`/hosts/${encodeURIComponent(h.host)}?run=${latest.id}`}
          className="inline"
          style={{ padding: "9px 0", borderTop: "1px solid var(--border)", color: "inherit", textDecoration: "none", flexWrap: "nowrap" }}
        >
          <span style={{ display: "flex", flexDirection: "column", flex: 1, minWidth: 0 }}>
            <span className="mono">{h.host}</span>
            <span className="faint" style={{ fontSize: 12, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
              {h.summary || `${h.total} уязв.`}
            </span>
          </span>
          {h.counts.critical > 0 && <span className="pill pill-danger">{h.counts.critical} крит.</span>}
          {h.counts.high > 0 && <span className="pill pill-warn">{h.counts.high} выс.</span>}
          {!h.counts.critical && !h.counts.high && <span className="pill pill-muted">{h.total} уязв.</span>}
        </Link>
      ))}
    </div>
  );
}

function PriorityCard({ top, latest, onOpen }: { top: FindingOut[]; latest: RunOut; onOpen: (f: FindingOut) => void }) {
  return (
    <section className="card" style={{ overflow: "hidden" }}>
      <div className="card-head">
        <h2>Приоритетные уязвимости</h2>
        <Link to={`/findings?run=${latest.id}`} style={{ fontSize: 13 }}>
          Все находки
        </Link>
      </div>
      {top.length === 0 ? (
        <Empty title="Уязвимостей не найдено" />
      ) : (
        <div className="table-wrap">
          <table className="table" style={{ minWidth: 760 }}>
            <thead>
              <tr>
                <th>Уязвимость</th>
                <th>Опасность</th>
                <th>БДУ ФСТЭК / CVE</th>
                <th className="right">CVSS</th>
                <th>Хост</th>
              </tr>
            </thead>
            <tbody>
              {top.map((f, i) => (
                <tr key={i} className="clickable" onClick={() => onOpen(f)}>
                  <td style={{ fontWeight: 500 }}>{f.title}</td>
                  <td>
                    <SeverityBadge severity={f.severity} />
                  </td>
                  <td>
                    <RefTags cve={f.cve_ids} bdu={f.bdu_ids} limit={2} />
                  </td>
                  <td className="right num">{f.cvss?.toFixed(1) ?? "—"}</td>
                  <td className="mono nowrap">
                    {f.host}
                    {f.port ? `:${f.port}` : ""}
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

const TILE_SEVERITIES: Severity[] = ["critical", "high", "medium", "low"];

/** Верх сводки: крупное число открытых уязвимостей, распределение и плитки уровней. */
function HeroCard({ s, latest, d, nav }: { s: RunSummary; latest: RunOut; d: DashData; nav: Nav }) {
  const delta = s.prevOpen === null ? null : s.open - s.prevOpen;
  return (
    <div className="card hero grow-3">
      <div className="inline" style={{ alignItems: "baseline", gap: 12 }}>
        <span className="hero-number">{fmtNumber(s.open)}</span>
        <span className="muted" style={{ fontSize: 15 }}>
          {plural(s.open, ["открытая уязвимость", "открытые уязвимости", "открытых уязвимостей"])} на {fmtNumber(s.hosts)}{" "}
          {plural(s.hosts, ["хосте", "хостах", "хостах"])}
        </span>
        {delta !== null && d.previous && (
          <span
            className="delta-badge"
            style={{ marginLeft: "auto", background: delta <= 0 ? "var(--ok-soft)" : "var(--danger-soft)", color: delta <= 0 ? "var(--ok)" : "var(--danger)" }}
          >
            {fmtDelta(delta)} к прогону №{d.previous.id}
          </span>
        )}
      </div>
      <SeverityStack counts={s.counts} />
      <div className="sev-tiles">
        {TILE_SEVERITIES.map((sev) => (
          <button key={sev} type="button" className="sev-tile" onClick={() => nav(`/findings?run=${latest.id}&sev=${sev}`)}>
            <span className={`sev sev-${sev}`} style={{ fontSize: 13, color: "var(--text-2)" }}>
              <i aria-hidden="true" />
              {SEVERITY_LABEL[sev]}
            </span>
            <b className="num">{s.counts[sev]}</b>
          </button>
        ))}
      </div>
      <span className="faint" style={{ fontSize: 12 }}>
        Сопоставлено с БДУ ФСТЭК: {s.bduShare === null ? "—" : `${Math.round(s.bduShare * 100)}% уязвимостей`} · информационных находок: {s.counts.info}
      </span>
    </div>
  );
}

function ChangeTiles({ s, latest, d }: { s: RunSummary; latest: RunOut; d: DashData }) {
  const tiles = [
    { label: "Новые", n: s.newCount, hint: `впервые найдены в №${latest.id}`, icon: <Plus size={16} />, bg: "var(--info-soft)", fg: "var(--accent-text)" },
    { label: "Закрытые", n: s.fixed, hint: d.previous ? `не обнаружены в №${latest.id}` : "нет базы сравнения", icon: <Check size={16} />, bg: "var(--ok-soft)", fg: "var(--ok)" },
    { label: "Регрессии", n: s.regression, hint: "вернулись после исправления", icon: <RotateCcw size={16} />, bg: "var(--warn-soft)", fg: "var(--warn)" },
    {
      label: "Хосты в инвентаре",
      n: s.hosts,
      hint: s.prevHosts === null ? "первый прогон" : `${fmtDelta(s.hosts - s.prevHosts)} к прошлому`,
      icon: <Server size={16} />,
      bg: "var(--muted-soft)",
      fg: "var(--text-2)",
    },
  ];
  return (
    <div className="change-tiles grow-2">
      {tiles.map((t) => (
        <div key={t.label} className="card change-tile">
          <span className="inline muted" style={{ fontSize: 13 }}>
            <span className="ic" style={{ background: t.bg, color: t.fg }} aria-hidden="true">
              {t.icon}
            </span>
            {t.label}
          </span>
          <b className="num">{fmtNumber(t.n)}</b>
          <span className="faint" style={{ fontSize: 12 }}>
            {t.hint}
          </span>
        </div>
      ))}
    </div>
  );
}

export function DashboardPage() {
  const { has } = useAuth();
  const { current, loading: engLoading, error: engError } = useEngagement();
  const navigate = useNavigate();
  const data = useAsync(() => loadDashboard(current!.id), [current?.id], !!current);
  const [starting, setStarting] = useState(false);
  const [open, setOpen] = useState<FindingOut | null>(null);

  const d = data.data;
  const summary = useMemo(() => (d && d.latest ? summarize(d.findings, d.prevFindings, d.services, d.prevServices) : null), [d]);
  const hosts = useMemo(() => (d ? byHost(d.findings.filter(isIssue), d.services).filter((h) => h.total > 0) : []), [d]);
  const top = useMemo(() => (d ? d.findings.filter(isIssue).sort(compareFindings).slice(0, 8) : []), [d]);
  const active = d?.runs.filter((r) => !isFinished(r.status)) ?? [];

  if (engLoading) return <Loading />;
  if (engError) return <ErrorAlert error={engError} />;
  if (!current) {
    return (
      <div className="card">
        <Empty title="Нет договоров" icon={<Radar size={28} />}>
          {has("manage_engagements") ? <Link to="/engagements">Создайте договор и задайте allowlist</Link> : "Попросите администратора создать договор и выдать доступ."}
        </Empty>
      </div>
    );
  }

  const latest = d?.latest;

  return (
    <>
      <div className="page-head">
        <div>
          <span className="crumbs">
            {current.client ?? "Договор"} {current.contract_ref ? `· ${current.contract_ref}` : ""}
            {latest ? ` · последний прогон №${latest.id}, ${fmtDate(latest.finished_at ?? latest.started_at)}` : ""}
          </span>
          <h1>Сводка по договору</h1>
        </div>
        <div className="actions">
          {latest && has("view_report") && <ReportMenu runId={latest.id} runs={d?.runs} compact />}
          {has("run_scan") && (
            <button type="button" className="btn btn-primary" onClick={() => setStarting(true)}>
              <Play size={16} /> Новый прогон
            </button>
          )}
        </div>
      </div>

      {active.map((r) => (
        <div key={r.id} className="alert alert-info">
          <span className="spinner" style={{ width: 14, height: 14 }} aria-hidden="true" />
          <span style={{ flex: 1 }}>
            Прогон №{r.id} {r.status === "pending" ? "в очереди" : "выполняется"}: {moduleList(r.modules)}
          </span>
          <Link to={`/runs/${r.id}`}>Мониторинг</Link>
        </div>
      ))}

      {data.error && <ErrorAlert error={data.error} onRetry={data.reload} />}
      {data.loading && !d && <Loading />}

      {d && !latest && (
        <div className="card">
          <Empty title="Завершённых прогонов пока нет">
            {has("run_scan") ? "Запустите первый прогон по целям из allowlist договора." : "Данные появятся после первого прогона."}
          </Empty>
        </div>
      )}

      {d && latest && summary && (
        <>
          <section className="row">
            <HeroCard s={summary} latest={latest} d={d} nav={navigate} />
            <ChangeTiles s={summary} latest={latest} d={d} />
          </section>
          <section className="row">
            <TrendCard d={d} />
            <TopHosts hosts={hosts} latest={latest} />
          </section>
          <PriorityCard top={top} latest={latest} onOpen={setOpen} />
          <RunsTable runs={d.runs} nav={navigate} />
        </>
      )}

      {starting && (
        <StartRunModal engagement={current} onClose={() => setStarting(false)} onStarted={(run) => navigate(`/runs/${run.id}`, { state: { created: run } })} />
      )}
      {open && (
        <FindingDrawer finding={open} onClose={() => setOpen(null)} onHost={latest ? (h) => navigate(`/hosts/${encodeURIComponent(h)}?run=${latest.id}`) : undefined} />
      )}
    </>
  );
}
