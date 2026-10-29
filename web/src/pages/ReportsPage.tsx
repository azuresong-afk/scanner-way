import { Link } from "react-router-dom";
import { BarChart3 } from "lucide-react";
import { api } from "../api/client";
import { useEngagement } from "../auth/EngagementContext";
import { ReportMenu } from "../components/ReportMenu";
import { Empty, ErrorAlert, Loading, RunName, RunStatusPill } from "../components/ui";
import { fmtDate } from "../lib/format";
import { isFinished } from "../lib/labels";
import { useAsync } from "../lib/useAsync";

export function ReportsPage() {
  const { current } = useEngagement();
  const runs = useAsync(() => api.runs(current!.id), [current?.id], !!current);
  const finished = [...(runs.data ?? [])].filter((r) => isFinished(r.status)).sort((a, b) => b.id - a.id);

  if (!current) return <div className="card"><Empty title="Выберите или создайте договор" /></div>;

  return (
    <>
      <div className="page-head">
        <div>
          <span className="crumbs">{current.client ? `${current.client} · ${current.name}` : current.name}</span>
          <h1>Отчёты</h1>
          <span className="muted">
            Отчёт включает рекомендации по устранению, ссылки на БДУ ФСТЭК, NVD и бюллетени производителей, раздел по каждому хосту. По
            умолчанию отчёт строится по одному прогону; сравнение — по выбору «Сравнить с».
          </span>
        </div>
      </div>
      {runs.error && <ErrorAlert error={runs.error} onRetry={runs.reload} />}
      <section className="card" style={{ overflow: "hidden" }}>
        {runs.loading && !runs.data ? (
          <Loading />
        ) : finished.length === 0 ? (
          <Empty title="Отчёты появятся после завершения прогонов" icon={<BarChart3 size={28} />} />
        ) : (
          <div className="table-wrap">
            <table className="table" style={{ minWidth: 860 }}>
              <thead>
                <tr>
                  <th>№</th>
                  <th>Название</th>
                  <th>Статус</th>
                  <th>Завершён</th>
                  <th>Выгрузка</th>
                </tr>
              </thead>
              <tbody>
                {finished.map((r) => (
                  <tr key={r.id}>
                    <td className="mono">
                      <Link to={`/runs/${r.id}`}>#{r.id}</Link>
                    </td>
                    <td>
                      <RunName run={r} />
                    </td>
                    <td>
                      <RunStatusPill status={r.status} />
                    </td>
                    <td className="muted nowrap">{fmtDate(r.finished_at)}</td>
                    <td>
                      <ReportMenu runId={r.id} runs={runs.data ?? []} small />
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>
    </>
  );
}
