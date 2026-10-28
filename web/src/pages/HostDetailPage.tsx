import { useMemo, useState } from "react";
import { Link, useParams } from "react-router-dom";
import { api } from "../api/client";
import type { FindingOut } from "../api/types";
import { SeverityBars } from "../components/charts/SeverityBars";
import { FindingDrawer } from "../components/FindingDrawer";
import { FindingsTable } from "../components/FindingsTable";
import { RunPicker } from "../components/RunPicker";
import { ServicesTable } from "../components/ServicesTable";
import { Empty, ErrorAlert, Kpi, Loading } from "../components/ui";
import { byHost, isIssue } from "../lib/stats";
import { useAsync } from "../lib/useAsync";
import { useRunSelection } from "../lib/useRunSelection";

/** Детальная информация по хосту: сервисы и все его уязвимости в выбранном прогоне. */
export function HostDetailPage() {
  const host = decodeURIComponent(useParams().host ?? "");
  const { runs, run, setRun, loading, error } = useRunSelection();
  const data = useAsync(
    async () => {
      const [findings, services] = await Promise.all([api.findings(run!.id), api.services(run!.id)]);
      return { findings: findings.filter((f) => f.host === host), services: services.filter((s) => s.host === host) };
    },
    [run?.id, host],
    !!run,
  );
  const [open, setOpen] = useState<FindingOut | null>(null);
  const row = useMemo(() => (data.data ? byHost(data.data.findings.filter(isIssue), data.data.services)[0] : undefined), [data.data]);
  const info = data.data?.findings.filter((f) => !isIssue(f)) ?? [];

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
        <div className="actions">{runs.length > 0 && <RunPicker runs={runs} value={run?.id ?? null} onChange={setRun} />}</div>
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
            </div>
            {row.findings.length ? <FindingsTable findings={row.findings} onOpen={setOpen} selected={open} hideHost /> : <Empty title="Уязвимостей не найдено" />}
          </section>
          {info.length > 0 && (
            <details className="card">
              <summary style={{ padding: "14px 20px", cursor: "pointer", fontWeight: 600 }}>Информационные находки ({info.length})</summary>
              <FindingsTable findings={info} onOpen={setOpen} selected={open} hideHost />
            </details>
          )}
        </>
      )}
      {open && <FindingDrawer finding={open} onClose={() => setOpen(null)} />}
    </>
  );
}
