import { useEffect, useMemo, useState } from "react";
import { Link, useLocation, useNavigate, useParams } from "react-router-dom";
import { CheckCircle2, Square } from "lucide-react";
import { api } from "../api/client";
import type { FindingOut, RunCreated } from "../api/types";
import { useAuth } from "../auth/AuthContext";
import { HeatLegend, HostHeatmap } from "../components/charts/HostHeatmap";
import { SeverityBars } from "../components/charts/SeverityBars";
import { FindingDrawer } from "../components/FindingDrawer";
import { FindingsTable } from "../components/FindingsTable";
import { ReportMenu } from "../components/ReportMenu";
import { ServicesTable } from "../components/ServicesTable";
import { Empty, ErrorAlert, Kpi, Loading, RunStatusPill } from "../components/ui";
import { fmtDateFull, fmtDuration } from "../lib/format";
import { isFinished, MODULE_LABEL, RATE_PROFILES } from "../lib/labels";
import { byHost, isIssue, summarize } from "../lib/stats";
import { useAsync, useInterval } from "../lib/useAsync";

type Tab = "findings" | "hosts" | "services";

export function RunDetailPage() {
  const id = Number(useParams().id);
  const { has } = useAuth();
  const navigate = useNavigate();
  const created = (useLocation().state as { created?: RunCreated } | null)?.created;
  const run = useAsync(() => api.run(id), [id]);
  const finished = run.data ? isFinished(run.data.status) : false;
  const findings = useAsync(() => api.findings(id), [id, finished], finished);
  const services = useAsync(() => api.services(id), [id, finished], finished);
  // Прогоны договора — для выбора «Сравнить с» в меню отчёта.
  const engagementId = run.data?.engagement_id;
  const engRuns = useAsync(() => api.runs(engagementId!), [engagementId, finished], finished && engagementId !== undefined);
  const [tab, setTab] = useState<Tab>("findings");
  const [open, setOpen] = useState<FindingOut | null>(null);
  const [stopError, setStopError] = useState<string | null>(null);
  const [, tick] = useState(0);

  useInterval(() => void run.reload(), 3000, !!run.data && !finished);
  useInterval(() => tick((n) => n + 1), 1000, !!run.data && !finished);
  useEffect(() => setOpen(null), [id]);

  const issues = useMemo(() => (findings.data ?? []).filter(isIssue), [findings.data]);
  const summary = useMemo(() => (findings.data ? summarize(findings.data, null, services.data) : null), [findings.data, services.data]);
  const hosts = useMemo(() => byHost(issues, services.data ?? []), [issues, services.data]);

  if (run.loading && !run.data) return <Loading />;
  if (run.error) return <ErrorAlert error={run.error} onRetry={run.reload} />;
  const r = run.data!;

  const stop = async () => {
    setStopError(null);
    try {
      run.setData(await api.stopRun(id));
    } catch (e) {
      setStopError((e as Error).message);
    }
  };

  return (
    <>
      <div className="page-head">
        <div>
          <span className="crumbs">
            <Link to="/runs">Прогоны</Link> / <Link to={`/engagements/${r.engagement_id}`}>договор #{r.engagement_id}</Link>
          </span>
          <h1 className="inline" style={{ gap: 12 }}>
            Прогон №{r.id} <RunStatusPill status={r.status} />
          </h1>
        </div>
        <div className="actions">
          {has("run_scan") && !finished && (
            <button type="button" className="btn btn-danger" onClick={stop}>
              <Square size={14} /> Остановить
            </button>
          )}
          {finished && has("view_report") && <ReportMenu runId={r.id} runs={engRuns.data ?? []} />}
        </div>
      </div>

      {created && created.id === r.id && (
        <div className="alert alert-ok">
          <CheckCircle2 size={16} aria-hidden="true" />
          <span>
            Прогон поставлен в очередь: принято адресов — {created.accepted_targets}.
            {created.denied_targets.length > 0 &&
              ` Отклонено вне allowlist: ${created.denied_targets.map((d) => `${d.target} (${d.reason})`).join(", ")}.`}
          </span>
        </div>
      )}
      {stopError && <ErrorAlert error={stopError} />}

      <section className="card card-pad">
        <dl className="kv" style={{ gridTemplateColumns: "160px minmax(0,1fr)" }}>
          <dt>Модули</dt>
          <dd>{r.modules.map((m) => MODULE_LABEL[m] ?? m).join(", ")}</dd>
          <dt>Профиль нагрузки</dt>
          <dd>{RATE_PROFILES.find((p) => p.id === r.rate_profile)?.label ?? r.rate_profile}</dd>
          <dt>Создан</dt>
          <dd>{fmtDateFull(r.created_at)}</dd>
          <dt>Начат</dt>
          <dd>{fmtDateFull(r.started_at)}</dd>
          <dt>Завершён</dt>
          <dd>{fmtDateFull(r.finished_at)}</dd>
          <dt>Длительность</dt>
          <dd>{fmtDuration(r.started_at, r.finished_at)}</dd>
        </dl>
      </section>

      {!finished && (
        <div className="card">
          <Empty title={r.status === "pending" ? "Прогон в очереди" : "Идёт сканирование"} icon={<span className="spinner" style={{ width: 28, height: 28 }} />}>
            Результаты появятся после завершения. Страница обновляется автоматически.
          </Empty>
        </div>
      )}

      {finished && r.status === "failed" && (
        <ErrorAlert error="Прогон завершился с ошибкой. Подробности — в журнале аудита; сохранённые до сбоя находки показаны ниже." />
      )}

      {finished && (findings.loading && !findings.data ? <Loading /> : findings.error ? <ErrorAlert error={findings.error} onRetry={findings.reload} /> : summary && (
        <>
          <section className="kpis">
            <Kpi label="Хостов" value={summary.hosts} />
            <Kpi label="Уязвимостей" value={summary.open} />
            <Kpi label="Критических" value={summary.counts.critical} tone={summary.counts.critical ? "critical" : undefined} />
            <Kpi label="Новых" value={summary.newCount} />
            <Kpi label="Регрессий" value={summary.regression} tone={summary.regression ? "warn" : undefined} />
            <Kpi label="С привязкой к БДУ" value={summary.bduShare === null ? "—" : `${Math.round(summary.bduShare * 100)}%`} />
          </section>

          <section className="row">
            <div className="card card-pad grow-1 stack" style={{ gap: 14 }}>
              <h2>По уровню опасности</h2>
              <SeverityBars counts={summary.counts} onPick={(s) => navigate(`/findings?run=${r.id}&sev=${s}`)} />
            </div>
            <div className="card card-pad grow-2">
              <div className="inline" style={{ justifyContent: "space-between", marginBottom: 10 }}>
                <h2>Хосты × уровень опасности</h2>
                <HeatLegend />
              </div>
              {hosts.length ? (
                <HostHeatmap rows={hosts} limit={8} onPick={(h) => navigate(`/hosts/${encodeURIComponent(h)}?run=${r.id}`)} />
              ) : (
                <Empty title="Уязвимостей не найдено" />
              )}
            </div>
          </section>

          <section className="card" style={{ overflow: "hidden" }}>
            <div className="tabs" role="tablist" style={{ padding: "0 12px" }}>
              <button type="button" role="tab" className="tab" aria-selected={tab === "findings"} onClick={() => setTab("findings")}>
                Находки <span className="count">{issues.length}</span>
              </button>
              <button type="button" role="tab" className="tab" aria-selected={tab === "hosts"} onClick={() => setTab("hosts")}>
                Хосты <span className="count">{hosts.length}</span>
              </button>
              <button type="button" role="tab" className="tab" aria-selected={tab === "services"} onClick={() => setTab("services")}>
                Сервисы <span className="count">{services.data?.length ?? 0}</span>
              </button>
            </div>
            {tab === "findings" &&
              (issues.length ? <FindingsTable findings={issues} onOpen={setOpen} selected={open} /> : <Empty title="Уязвимостей не найдено" />)}
            {tab === "hosts" && <HostHeatmap rows={hosts} limit={hosts.length} onPick={(h) => navigate(`/hosts/${encodeURIComponent(h)}?run=${r.id}`)} />}
            {tab === "services" && <ServicesTable runId={r.id} services={services.data ?? []} />}
          </section>
        </>
      ))}

      {open && (
        <FindingDrawer finding={open} onClose={() => setOpen(null)} onHost={(h) => navigate(`/hosts/${encodeURIComponent(h)}?run=${r.id}`)} />
      )}
    </>
  );
}
