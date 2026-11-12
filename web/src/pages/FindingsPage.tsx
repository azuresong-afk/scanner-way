import { useEffect, useMemo, useState } from "react";
import { Link, useNavigate, useSearchParams } from "react-router-dom";
import { Search, ShieldAlert } from "lucide-react";
import { api } from "../api/client";
import type { FindingOut, FindingQuery, FindingStatus, Severity, TableFormat } from "../api/types";
import { SeverityStack } from "../components/charts/SeverityBars";
import { ExportButtons } from "../components/ExportButtons";
import { FINDINGS_EXPORTS } from "../lib/exports";
import { FindingDrawer } from "../components/FindingDrawer";
import { FixPlan } from "../components/FixPlan";
import { FindingsTable, type SortKey, type SortState } from "../components/FindingsTable";
import { Pager } from "../components/Pager";
import { RunPicker } from "../components/RunPicker";
import { Empty, ErrorAlert, Loading } from "../components/ui";
import { MODULE_LABEL, SEVERITIES, SEVERITY_LABEL, STATUS_LABEL } from "../lib/labels";
import { byHost } from "../lib/stats";
import { useAsync } from "../lib/useAsync";
import { PAGE_SIZES, useDebounced, useFindingsPage } from "../lib/useFindingsPage";
import { useRunSelection } from "../lib/useRunSelection";

const STATUSES: FindingStatus[] = ["new", "open", "regression"];
const SORT_KEYS: SortKey[] = ["severity", "priority", "title", "host", "cvss", "module"];

function toggle<T>(list: T[], v: T): T[] {
  return list.includes(v) ? list.filter((x) => x !== v) : [...list, v];
}

type View = "fix" | "all";
const VIEWS: { id: View; label: string }[] = [
  { id: "fix", label: "Что исправить" },
  { id: "all", label: "Все находки" },
];

/**
 * Находки прогона в двух видах. «Что исправить» (по умолчанию) — помощь
 * администраторам: находки собраны в действия с командами для ОС хостов
 * (FixPlan). «Все находки» — плоский список для разбора. Фильтры, сортировка и страницы выполняются на сервере, а их
 * состояние хранится в адресной строке (?sev=…&module=…&q=…&sort=…&page=…) —
 * его можно переслать ссылкой, и оно сохраняется при переходах «назад».
 */
export function FindingsPage() {
  const { engagement, runs, run, setRun, loading, error } = useRunSelection();
  const [params, setParams] = useSearchParams();
  const navigate = useNavigate();

  const view: View = params.get("view") === "all" ? "all" : "fix";
  const severities = params.getAll("sev").filter((s): s is Severity => (SEVERITIES as string[]).includes(s));
  const modules = params.getAll("module");
  const statuses = params.getAll("status").filter((s): s is FindingStatus => (STATUSES as string[]).includes(s));
  const bduOnly = params.get("bdu") === "1";
  const includeInfo = params.get("info") === "1";
  const includeFp = params.get("fp") === "1";
  const grouped = params.get("group") === "host";
  const sortKey = (SORT_KEYS as string[]).includes(params.get("sort") ?? "") ? (params.get("sort") as SortKey) : "severity";
  const sort: SortState = { key: sortKey, dir: params.get("dir") === "desc" ? -1 : 1 };
  const size = PAGE_SIZES.includes(Number(params.get("size"))) ? Number(params.get("size")) : 50;
  const offset = Math.max(0, (Number(params.get("page")) || 1) - 1) * size;

  const [query, setQuery] = useState(params.get("q") ?? "");
  const q = useDebounced(query.trim());

  /** Меняет параметры адреса; любой фильтр возвращает на первую страницу. */
  const update = (patch: Record<string, string | string[] | null>, keepPage = false) => {
    const next = new URLSearchParams(params);
    for (const [k, v] of Object.entries(patch)) {
      next.delete(k);
      if (Array.isArray(v)) v.forEach((x) => next.append(k, x));
      else if (v !== null && v !== "") next.set(k, v);
    }
    if (!keepPage) next.delete("page");
    setParams(next, { replace: true });
  };
  // поиск после паузы в наборе попадает в адрес (и сбрасывает страницу)
  const urlQ = params.get("q") ?? "";
  useEffect(() => {
    if (q !== urlQ) update({ q: q || null });
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [q]);
  // запрос сменился снаружи (переход из быстрого поиска) — поле поиска следует за адресом
  useEffect(() => {
    if (urlQ !== query.trim()) setQuery(urlQ);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [urlQ]);

  const filter: FindingQuery = {
    severity: severities,
    module: modules,
    status: statuses,
    q: params.get("q") ?? undefined,
    bdu_only: bduOnly || undefined,
    include_info: includeInfo,
    false_positives: includeFp ? "include" : "exclude",
  };
  const findings = useFindingsPage(view === "all" ? run?.id : undefined, filter, { sort, offset, limit: size });
  const summary = useAsync(() => api.findingsSummary(run!.id), [run?.id], !!run && view === "all");

  const items = useMemo(() => findings.data?.items ?? [], [findings.data]);
  const groups = useMemo(() => (grouped ? byHost(items) : []), [grouped, items]);
  const [open, setOpen] = useState<FindingOut | null>(null);
  const sevCounts = summary.data?.counts;
  const moduleList = summary.data?.modules ?? [];
  const active = severities.length + modules.length + statuses.length + (params.get("q") ? 1 : 0) + (bduOnly ? 1 : 0);
  const total = findings.data?.total ?? 0;

  if (!engagement) return <div className="card"><Empty title="Выберите или создайте проект" /></div>;

  const check = (label: React.ReactNode, checked: boolean, key: string, value = "1") => (
    <label className="check" style={{ alignItems: "center" }}>
      <input type="checkbox" checked={checked} onChange={(e) => update({ [key]: e.target.checked ? value : null })} />
      {label}
    </label>
  );

  return (
    <>
      <div className="page-head">
        <div>
          <span className="crumbs">{engagement.client ? `${engagement.client} · ${engagement.name}` : engagement.name}</span>
          <h1>Находки</h1>
        </div>
        <div className="actions">
          <div className="seg" role="radiogroup" aria-label="Вид находок">
            {VIEWS.map((v) => (
              <button
                key={v.id}
                type="button"
                role="radio"
                aria-checked={view === v.id}
                onClick={() => {
                  if (v.id === view) return;
                  setOpen(null);
                  // фильтры, которых нет в другом виде, не переносятся
                  update({ view: v.id === "all" ? "all" : null, module: null, status: null, group: null, kind: null, os: null, size: null });
                }}
              >
                {v.label}
              </button>
            ))}
          </div>
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
      ) : view === "fix" ? (
        <FixPlan key={run.id} runId={run.id} onHost={(h) => navigate(`/hosts/${encodeURIComponent(h)}?run=${run.id}`)} />
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
                  value={query}
                  onChange={(e) => setQuery(e.target.value)}
                />
              </div>
              {check("Только с БДУ ФСТЭК", bduOnly, "bdu")}
              {check("Информационные", includeInfo, "info")}
              {check(
                <>
                  Ложные срабатывания <span className="faint">{summary.data?.false_positives ?? 0}</span>
                </>,
                includeFp,
                "fp",
              )}
              {check("По хостам", grouped, "group", "host")}
            </div>
            <div className="inline" role="group" aria-label="Уровень опасности">
              <span className="faint" style={{ fontSize: 12, minWidth: 80 }}>
                Опасность
              </span>
              {SEVERITIES.filter((s) => includeInfo || s !== "info").map((s) => (
                <button key={s} type="button" className="chip" aria-pressed={severities.includes(s)} onClick={() => update({ sev: toggle<string>(severities, s) })}>
                  <span className={`sev sev-${s}`}>
                    <i aria-hidden="true" />
                  </span>
                  {SEVERITY_LABEL[s]} <span className="faint">{sevCounts?.[s] ?? 0}</span>
                </button>
              ))}
            </div>
            <div className="inline" role="group" aria-label="Модуль и статус">
              <span className="faint" style={{ fontSize: 12, minWidth: 80 }}>
                Модуль
              </span>
              {moduleList.map((m) => (
                <button key={m} type="button" className="chip" aria-pressed={modules.includes(m)} onClick={() => update({ module: toggle(modules, m) })}>
                  {MODULE_LABEL[m] ?? m}
                </button>
              ))}
              <span className="faint" style={{ fontSize: 12, marginLeft: 12 }}>
                Статус
              </span>
              {STATUSES.map((s) => (
                <button key={s} type="button" className="chip" aria-pressed={statuses.includes(s)} onClick={() => update({ status: toggle<string>(statuses, s) })}>
                  {STATUS_LABEL[s]}
                </button>
              ))}
              {active > 0 && (
                <button
                  type="button"
                  className="btn btn-sm btn-ghost"
                  onClick={() => {
                    setQuery("");
                    update({ sev: null, module: null, status: null, q: null, bdu: null });
                  }}
                >
                  Сбросить ({active})
                </button>
              )}
            </div>
          </section>

          {findings.error && <ErrorAlert error={findings.error} onRetry={findings.reload} />}
          <section className="card" style={{ overflow: "hidden" }}>
            <div className="card-head">
              <h2>Найдено: {total.toLocaleString("ru-RU")}</h2>
              <span className="faint" style={{ fontSize: 12 }}>
                Прогон №{run.id}
                {grouped && " · группировка по хостам — в пределах страницы"}
              </span>
              {total > 0 && (
                <ExportButtons
                  what="находки"
                  options={FINDINGS_EXPORTS}
                  load={(fmt) =>
                    api.exportFindings(run.id, fmt as TableFormat, {
                      ...filter,
                      sort: sort.key,
                      order: sort.dir === -1 ? "desc" : "asc",
                    })
                  }
                />
              )}
            </div>
            {findings.loading && !findings.data ? (
              <Loading />
            ) : items.length === 0 ? (
              <Empty title={active || !includeInfo ? "Ничего не найдено по фильтрам" : "В прогоне нет находок"} />
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
                        {g.findings.length} {g.findings.length === 1 ? "находка" : "находок"} на странице
                      </span>
                      <Link to={`/hosts/${encodeURIComponent(g.host)}?run=${run.id}`} onClick={(e) => e.stopPropagation()} style={{ fontSize: 13 }}>
                        Карточка хоста
                      </Link>
                    </summary>
                    <FindingsTable findings={g.findings} onOpen={setOpen} selected={open} hideHost sort={sort} onSort={(s) => update({ sort: s.key, dir: s.dir === -1 ? "desc" : null })} />
                  </details>
                ))}
              </div>
            ) : (
              <FindingsTable findings={items} onOpen={setOpen} selected={open} sort={sort} onSort={(s) => update({ sort: s.key, dir: s.dir === -1 ? "desc" : null })} />
            )}
            {total > 0 && (
              <Pager
                total={total}
                offset={offset}
                limit={size}
                label="Страницы находок"
                onChange={(o) => update({ page: o ? String(Math.floor(o / size) + 1) : null }, true)}
                onLimit={(n) => update({ size: n === 50 ? null : String(n) })}
              />
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
            if (findings.data) findings.setData({ ...findings.data, items: findings.data.items.map((f) => (f.id === u.id ? u : f)) });
            setOpen(u);
            void summary.reload();
          }}
        />
      )}
    </>
  );
}
