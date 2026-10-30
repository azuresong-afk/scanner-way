import { useEffect, useMemo, useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { Search, Server } from "lucide-react";
import { api } from "../api/client";
import { SeverityStack } from "../components/charts/SeverityBars";
import { RunPicker } from "../components/RunPicker";
import { Empty, ErrorAlert, Loading, SeverityBadge } from "../components/ui";
import { osSourceHint } from "../lib/labels";
import { groupByOs, inventoryRows, type InventoryRow } from "../lib/stats";
import { useAsync } from "../lib/useAsync";
import { useRunSelection } from "../lib/useRunSelection";

const GROUP_KEY = "scanner.hosts.byOs";

function readGrouped(): boolean {
  try {
    return localStorage.getItem(GROUP_KEY) === "1";
  } catch {
    return false;
  }
}

export function HostsPage() {
  const { engagement, runs, run, setRun, loading, error } = useRunSelection();
  const navigate = useNavigate();
  // Список хостов — инвентарь договора по всем прогонам, от выбора прогона не зависит.
  const inventory = useAsync(() => api.hosts(engagement!.id), [engagement?.id], !!engagement);
  // От прогона зависят только счётчики уязвимостей.
  const findings = useAsync(() => api.findings(run!.id), [run?.id], !!run);
  const [query, setQuery] = useState("");
  const [osFilter, setOsFilter] = useState<string[]>([]);
  const [grouped, setGrouped] = useState(readGrouped);
  useEffect(() => {
    try {
      localStorage.setItem(GROUP_KEY, grouped ? "1" : "0");
    } catch {
      /* без хранилища выбор живёт до перезагрузки */
    }
  }, [grouped]);
  const hosts = useMemo(
    () => (inventory.data ? inventoryRows(inventory.data, findings.data ?? [], run?.id ?? null) : []),
    [inventory.data, findings.data, run?.id],
  );
  const inRun = hosts.filter((h) => h.inRun).length;
  // Семейства ОС, встречающиеся в договоре, в порядке групп — для чипов фильтра.
  const osFamilies = useMemo(() => groupByOs(hosts).map((g) => ({ family: g.family, label: g.label, count: g.rows.length })), [hosts]);
  const q = query.trim().toLowerCase();
  const shown = hosts.filter(
    (h) =>
      (!osFilter.length || osFilter.includes(h.osFamily)) &&
      (!q || `${h.host} ${h.summary} ${h.osLabel} ${h.osName ?? ""}`.toLowerCase().includes(q)),
  );
  const groups = grouped ? groupByOs(shown) : [];
  const toggleOs = (f: string) => setOsFilter((cur) => (cur.includes(f) ? cur.filter((x) => x !== f) : [...cur, f]));

  function renderRow(h: InventoryRow) {
    const to = `/hosts/${encodeURIComponent(h.host)}?run=${h.inRun ? run!.id : (h.lastRunId ?? run!.id)}`;
    return (
      <tr key={h.host} className="clickable" onClick={() => navigate(to)}>
        <td className="mono">
          <Link to={to} onClick={(e) => e.stopPropagation()}>
            {h.host}
          </Link>
        </td>
        <td style={{ maxWidth: 260 }} title={osSourceHint(h.osSource, h.osAccuracy)}>
          {h.osFamily === "unknown" ? (
            <span className="faint">не определена</span>
          ) : (
            <>
              <span>{h.osLabel}</span>
              {h.osName && h.osName !== h.osLabel && <small className="faint os-name">{h.osName}</small>}
            </>
          )}
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
              не в прогоне №{run!.id}
            </td>
            <td className="right num faint">—</td>
          </>
        )}
      </tr>
    );
  }

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
            <div className="inline" style={{ gap: 13 }}>
              <label className="check" style={{ alignItems: "center" }}>
                <input type="checkbox" checked={grouped} onChange={(e) => setGrouped(e.target.checked)} />
                По ОС
              </label>
              <div className="search" style={{ width: 280, maxWidth: "100%" }}>
                <Search size={15} aria-hidden="true" />
                <input className="input" type="search" placeholder="IP, сервис или ОС" aria-label="Поиск хоста" value={query} onChange={(e) => setQuery(e.target.value)} />
              </div>
            </div>
          </div>
          {osFamilies.length > 0 && (
            <div className="inline os-filter" role="group" aria-label="Фильтр по ОС">
              <span className="faint" style={{ fontSize: 12 }}>
                ОС
              </span>
              {osFamilies.map((f) => (
                <button key={f.family} type="button" className="chip" aria-pressed={osFilter.includes(f.family)} onClick={() => toggleOs(f.family)}>
                  {f.label} <span className="faint">{f.count}</span>
                </button>
              ))}
              {osFilter.length > 0 && (
                <button type="button" className="btn btn-sm btn-ghost" onClick={() => setOsFilter([])}>
                  Все ОС
                </button>
              )}
            </div>
          )}
          {(inventory.loading && !inventory.data) || (findings.loading && !findings.data) ? (
            <Loading />
          ) : shown.length === 0 ? (
            <Empty title="Хосты не найдены" />
          ) : (
            <div className="table-wrap">
              <table className="table" style={{ minWidth: 980 }}>
                <thead>
                  <tr>
                    <th>Хост</th>
                    <th>ОС</th>
                    <th>Сервисы</th>
                    <th className="right">Портов</th>
                    <th>Макс. опасность</th>
                    <th>Распределение</th>
                    <th className="right">Уязвимостей</th>
                  </tr>
                </thead>
                {grouped ? (
                  groups.map((g) => (
                    <tbody key={g.family} aria-label={g.label}>
                      <tr className="os-group">
                        <td colSpan={4}>
                          <b>{g.label}</b>{" "}
                          <span className="faint">
                            {g.rows.length} {plural(g.rows.length)}
                          </span>
                        </td>
                        <td />
                        <td style={{ width: 200 }}>{g.total > 0 && <SeverityStack counts={g.counts} />}</td>
                        <td className="right num">{g.total}</td>
                      </tr>
                      {g.rows.map(renderRow)}
                    </tbody>
                  ))
                ) : (
                  <tbody>{shown.map(renderRow)}</tbody>
                )}
              </table>
            </div>
          )}
        </section>
      )}
    </>
  );
}

function plural(n: number): string {
  const d = n % 10;
  const dd = n % 100;
  if (d === 1 && dd !== 11) return "хост";
  if (d >= 2 && d <= 4 && (dd < 12 || dd > 14)) return "хоста";
  return "хостов";
}
