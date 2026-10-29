import { useMemo, useState } from "react";
import { Link, useNavigate, useSearchParams } from "react-router-dom";
import { Search, ShieldAlert } from "lucide-react";
import { api } from "../api/client";
import type { FindingOut, FindingStatus, Severity } from "../api/types";
import { SeverityStack } from "../components/charts/SeverityBars";
import { FindingDrawer } from "../components/FindingDrawer";
import { FindingsTable } from "../components/FindingsTable";
import { RunPicker } from "../components/RunPicker";
import { Empty, ErrorAlert, Loading } from "../components/ui";
import { MODULE_LABEL, SEVERITIES, SEVERITY_LABEL, STATUS_LABEL } from "../lib/labels";
import { applyFilter, byHost, emptyFilter, isFalsePositive, replaceFinding, type FindingFilter } from "../lib/stats";
import { useAsync } from "../lib/useAsync";
import { useRunSelection } from "../lib/useRunSelection";

const STATUSES: FindingStatus[] = ["new", "open", "regression"];

function toggle<T>(list: T[], v: T): T[] {
  return list.includes(v) ? list.filter((x) => x !== v) : [...list, v];
}

export function FindingsPage() {
  const { engagement, runs, run, setRun, loading, error } = useRunSelection();
  const [params] = useSearchParams();
  const navigate = useNavigate();
  const findings = useAsync(() => api.findings(run!.id), [run?.id], !!run);
  const [filter, setFilter] = useState<FindingFilter>(() => {
    const f = emptyFilter();
    const sev = params.get("sev");
    if (sev && (SEVERITIES as string[]).includes(sev)) f.severities = [sev as Severity];
    const q = params.get("q");
    if (q) f.query = q;
    return f;
  });
  const [includeInfo, setIncludeInfo] = useState(false);
  const [includeFp, setIncludeFp] = useState(false);
  const [grouped, setGrouped] = useState(false);
  const [open, setOpen] = useState<FindingOut | null>(null);

  const all = useMemo(
    () => (findings.data ?? []).filter((f) => (includeInfo || f.severity !== "info") && (includeFp || !isFalsePositive(f))),
    [findings.data, includeInfo, includeFp],
  );
  const fpCount = useMemo(() => (findings.data ?? []).filter(isFalsePositive).length, [findings.data]);
  const shown = useMemo(() => applyFilter(all, filter), [all, filter]);
  const groups = useMemo(() => (grouped ? byHost(shown) : []), [grouped, shown]);
  const sevCounts = useMemo(() => {
    const c: Record<string, number> = {};
    for (const f of all) if (!isFalsePositive(f)) c[f.severity] = (c[f.severity] ?? 0) + 1;
    return c;
  }, [all]);
  const modules = useMemo(() => [...new Set(all.map((f) => f.module))].sort(), [all]);
  const active = filter.severities.length + filter.modules.length + filter.statuses.length + (filter.query ? 1 : 0) + (filter.bduOnly ? 1 : 0);

  if (!engagement) return <div className="card"><Empty title="Выберите или создайте договор" /></div>;

  return (
    <>
      <div className="page-head">
        <div>
          <span className="crumbs">{engagement.client ? `${engagement.client} · ${engagement.name}` : engagement.name}</span>
          <h1>Находки</h1>
        </div>
        <div className="actions">
          {runs.length > 0 && <RunPicker runs={runs} value={run?.id ?? null} onChange={setRun} />}
        </div>
      </div>
      {error && <ErrorAlert error={error} />}
      {loading && !runs.length ? (
        <Loading />
      ) : !run ? (
        <div className="card">
          <Empty title="Нет завершённых прогонов" icon={<ShieldAlert size={28} />} />
        </div>
      ) : (
        <>
          <section className="card card-pad stack" style={{ gap: 14 }}>
            <div className="inline" style={{ gap: 10 }}>
              <div className="search" style={{ flex: "1 1 280px" }}>
                <Search size={15} aria-hidden="true" />
                <input
                  className="input"
                  type="search"
                  placeholder="Поиск: название, хост, CVE, БДУ"
                  aria-label="Поиск по находкам"
                  value={filter.query}
                  onChange={(e) => setFilter({ ...filter, query: e.target.value })}
                />
              </div>
              <label className="check" style={{ alignItems: "center" }}>
                <input type="checkbox" checked={filter.bduOnly} onChange={(e) => setFilter({ ...filter, bduOnly: e.target.checked })} />
                Только с БДУ ФСТЭК
              </label>
              <label className="check" style={{ alignItems: "center" }}>
                <input type="checkbox" checked={includeInfo} onChange={(e) => setIncludeInfo(e.target.checked)} />
                Информационные
              </label>
              <label className="check" style={{ alignItems: "center" }}>
                <input type="checkbox" checked={includeFp} onChange={(e) => setIncludeFp(e.target.checked)} />
                Ложные срабатывания <span className="faint">{fpCount}</span>
              </label>
              <label className="check" style={{ alignItems: "center" }}>
                <input type="checkbox" checked={grouped} onChange={(e) => setGrouped(e.target.checked)} />
                По хостам
              </label>
            </div>
            <div className="inline" role="group" aria-label="Уровень опасности">
              <span className="faint" style={{ fontSize: 12, minWidth: 80 }}>
                Опасность
              </span>
              {SEVERITIES.filter((s) => includeInfo || s !== "info").map((s) => (
                <button key={s} type="button" className="chip" aria-pressed={filter.severities.includes(s)} onClick={() => setFilter({ ...filter, severities: toggle(filter.severities, s) })}>
                  <span className={`sev sev-${s}`}>
                    <i aria-hidden="true" />
                  </span>
                  {SEVERITY_LABEL[s]} <span className="faint">{sevCounts[s] ?? 0}</span>
                </button>
              ))}
            </div>
            <div className="inline" role="group" aria-label="Модуль и статус">
              <span className="faint" style={{ fontSize: 12, minWidth: 80 }}>
                Модуль
              </span>
              {modules.map((m) => (
                <button key={m} type="button" className="chip" aria-pressed={filter.modules.includes(m)} onClick={() => setFilter({ ...filter, modules: toggle(filter.modules, m) })}>
                  {MODULE_LABEL[m] ?? m}
                </button>
              ))}
              <span className="faint" style={{ fontSize: 12, marginLeft: 12 }}>
                Статус
              </span>
              {STATUSES.map((s) => (
                <button key={s} type="button" className="chip" aria-pressed={filter.statuses.includes(s)} onClick={() => setFilter({ ...filter, statuses: toggle(filter.statuses, s) })}>
                  {STATUS_LABEL[s]}
                </button>
              ))}
              {active > 0 && (
                <button type="button" className="btn btn-sm btn-ghost" onClick={() => setFilter(emptyFilter())}>
                  Сбросить ({active})
                </button>
              )}
            </div>
          </section>

          {findings.error && <ErrorAlert error={findings.error} onRetry={findings.reload} />}
          <section className="card" style={{ overflow: "hidden" }}>
            <div className="card-head">
              <h2>
                {shown.length} из {all.length}
              </h2>
              <span className="faint" style={{ fontSize: 12 }}>
                Прогон №{run.id}
              </span>
            </div>
            {findings.loading && !findings.data ? (
              <Loading />
            ) : shown.length === 0 ? (
              <Empty title={all.length ? "Ничего не найдено по фильтрам" : "В прогоне нет находок"} />
            ) : grouped ? (
              <div className="stack" style={{ gap: 0 }}>
                {groups.map((g) => (
                  <details key={g.host} open={groups.length <= 5} style={{ borderTop: "1px solid var(--border)" }}>
                    <summary className="inline" style={{ padding: "12px 20px", cursor: "pointer", flexWrap: "nowrap" }}>
                      <span className="mono" style={{ fontWeight: 600, minWidth: 130 }}>
                        {g.host}
                      </span>
                      <span style={{ flex: "0 1 220px" }}>
                        <SeverityStack counts={g.counts} />
                      </span>
                      <span className="muted" style={{ flex: 1 }}>
                        {g.findings.length} {g.findings.length === 1 ? "находка" : "находок"}
                      </span>
                      <Link to={`/hosts/${encodeURIComponent(g.host)}?run=${run.id}`} onClick={(e) => e.stopPropagation()} style={{ fontSize: 13 }}>
                        Карточка хоста
                      </Link>
                    </summary>
                    <FindingsTable findings={g.findings} onOpen={setOpen} selected={open} hideHost />
                  </details>
                ))}
              </div>
            ) : (
              <FindingsTable findings={shown} onOpen={setOpen} selected={open} />
            )}
          </section>
        </>
      )}
      {open && run && (
        <FindingDrawer
          finding={open}
          onClose={() => setOpen(null)}
          onHost={(h) => navigate(`/hosts/${encodeURIComponent(h)}?run=${run.id}`)}
          onChanged={(u) => {
            findings.setData(replaceFinding(findings.data ?? [], u));
            setOpen(u);
          }}
        />
      )}
    </>
  );
}
