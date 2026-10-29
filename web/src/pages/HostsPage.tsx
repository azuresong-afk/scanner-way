import { useMemo, useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { Search, Server } from "lucide-react";
import { api } from "../api/client";
import { SeverityStack } from "../components/charts/SeverityBars";
import { RunPicker } from "../components/RunPicker";
import { Empty, ErrorAlert, Loading, SeverityBadge } from "../components/ui";
import { inventoryRows } from "../lib/stats";
import { useAsync } from "../lib/useAsync";
import { useRunSelection } from "../lib/useRunSelection";

export function HostsPage() {
  const { engagement, runs, run, setRun, loading, error } = useRunSelection();
  const navigate = useNavigate();
  // Список хостов — инвентарь договора по всем прогонам, от выбора прогона не зависит.
  const inventory = useAsync(() => api.hosts(engagement!.id), [engagement?.id], !!engagement);
  // От прогона зависят только счётчики уязвимостей.
  const findings = useAsync(() => api.findings(run!.id), [run?.id], !!run);
  const [query, setQuery] = useState("");
  const hosts = useMemo(
    () => (inventory.data ? inventoryRows(inventory.data, findings.data ?? [], run?.id ?? null) : []),
    [inventory.data, findings.data, run?.id],
  );
  const inRun = hosts.filter((h) => h.inRun).length;
  const shown = hosts.filter((h) => !query || `${h.host} ${h.summary}`.toLowerCase().includes(query.trim().toLowerCase()));

  if (!engagement) return <div className="card"><Empty title="Выберите или создайте договор" /></div>;

  return (
    <>
      <div className="page-head">
        <div>
          <span className="crumbs">{engagement.client ? `${engagement.client} · ${engagement.name}` : engagement.name}</span>
          <h1>Хосты</h1>
        </div>
        <div className="actions">{runs.length > 0 && <RunPicker runs={runs} value={run?.id ?? null} onChange={setRun} />}</div>
      </div>
      {error && <ErrorAlert error={error} />}
      {inventory.error && <ErrorAlert error={inventory.error} onRetry={inventory.reload} />}
      {findings.error && <ErrorAlert error={findings.error} onRetry={findings.reload} />}
      {loading && !runs.length ? (
        <Loading />
      ) : !run ? (
        <div className="card">
          <Empty title="Нет завершённых прогонов" icon={<Server size={28} />} />
        </div>
      ) : (
        <section className="card" style={{ overflow: "hidden" }}>
          <div className="card-head">
            <h2>
              {shown.length} {shown.length === hosts.length ? "" : `из ${hosts.length}`} хостов
              <span className="faint" style={{ fontWeight: 400, fontSize: 13, marginLeft: 8 }}>
                в прогоне №{run.id}: {inRun}
              </span>
            </h2>
            <div className="search" style={{ width: 280, maxWidth: "100%" }}>
              <Search size={15} aria-hidden="true" />
              <input className="input" type="search" placeholder="IP или сервис" aria-label="Поиск хоста" value={query} onChange={(e) => setQuery(e.target.value)} />
            </div>
          </div>
          {(inventory.loading && !inventory.data) || (findings.loading && !findings.data) ? (
            <Loading />
          ) : shown.length === 0 ? (
            <Empty title="Хосты не найдены" />
          ) : (
            <div className="table-wrap">
              <table className="table" style={{ minWidth: 820 }}>
                <thead>
                  <tr>
                    <th>Хост</th>
                    <th>Сервисы</th>
                    <th className="right">Портов</th>
                    <th>Макс. опасность</th>
                    <th>Распределение</th>
                    <th className="right">Уязвимостей</th>
                  </tr>
                </thead>
                <tbody>
                  {shown.map((h) => {
                    const to = `/hosts/${encodeURIComponent(h.host)}?run=${h.inRun ? run.id : (h.lastRunId ?? run.id)}`;
                    return (
                      <tr key={h.host} className="clickable" onClick={() => navigate(to)}>
                        <td className="mono">
                          <Link to={to} onClick={(e) => e.stopPropagation()}>
                            {h.host}
                          </Link>
                        </td>
                        <td className="muted" style={{ maxWidth: 320 }}>
                          {h.summary || "—"}
                        </td>
                        <td className="right num">{h.services.length}</td>
                        {h.inRun ? (
                          <>
                            <td>{h.total ? <SeverityBadge severity={h.maxSeverity} /> : <span className="faint">нет</span>}</td>
                            <td style={{ width: 200 }}>
                              <SeverityStack counts={h.counts} />
                            </td>
                            <td className="right num" style={{ fontWeight: 600 }}>
                              {h.total}
                            </td>
                          </>
                        ) : (
                          <>
                            <td colSpan={2} className="faint" title="Хост не сканировался в выбранном прогоне">
                              не в прогоне №{run.id}
                            </td>
                            <td className="right num faint">—</td>
                          </>
                        )}
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          )}
        </section>
      )}
    </>
  );
}
