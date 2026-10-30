import { useEffect, useMemo, useState } from "react";
import { ClipboardCheck, ExternalLink, RefreshCw } from "lucide-react";
import { api } from "../api/client";
import type { ComplianceControl, ComplianceProfileOut, ComplianceStatus, ComplianceSummary } from "../api/types";
import { useAuth } from "../auth/AuthContext";
import { RunPicker } from "../components/RunPicker";
import { Empty, ErrorAlert, Kpi, Loading } from "../components/ui";
import { useAsync } from "../lib/useAsync";
import { useRunSelection } from "../lib/useRunSelection";

const STATUS_LABEL: Record<ComplianceStatus, string> = {
  passed: "Выполнена",
  failed: "Не выполнена",
  manual: "Вручную",
  na: "Не проверена",
};
const STATUS_PILL: Record<ComplianceStatus, string> = {
  passed: "pill-ok",
  failed: "pill-danger",
  manual: "pill-info",
  na: "pill-muted",
};

const pct = (v: number | null | undefined) => (v === null || v === undefined ? "—" : `${Math.round(v)}%`);

function StatusPill({ status }: { status: ComplianceStatus }) {
  return <span className={`pill ${STATUS_PILL[status]}`}>{STATUS_LABEL[status]}</span>;
}

/** Профили соответствия ФСТЭК №17/21/239 и CIS (R5): процент по прогону, разбивка, провалы. */
export function CompliancePage() {
  const { engagement, runs, run, setRun, loading, error, reload } = useRunSelection();
  const { has } = useAuth();
  const canManage = has("manage_engagements");
  const canRun = has("run_scan");
  const eid = engagement?.id;

  const catalog = useAsync(() => api.complianceCatalog(), []);
  const saved = useAsync(() => api.complianceProfiles(eid!), [eid], !!eid);
  const groups = useAsync(() => api.assetGroups(eid!), [eid], !!eid);

  const [profileId, setProfileId] = useState("fstec-17");
  const [level, setLevel] = useState<string | null>(null);
  const [groupId, setGroupId] = useState<number | null>(null);
  const [onlyFailed, setOnlyFailed] = useState(false);
  const [busy, setBusy] = useState(false);
  const [actionError, setActionError] = useState<Error | null>(null);

  const def = catalog.data?.find((p) => p.id === profileId);
  const savedRow: ComplianceProfileOut | undefined = saved.data?.find((p) => p.profile === profileId);

  // Уровень по умолчанию — сохранённый в договоре, иначе базовый профиля.
  useEffect(() => {
    setLevel(savedRow?.level ?? def?.default_level ?? null);
  }, [profileId, savedRow?.level, def?.default_level]);

  const summary = useAsync<ComplianceSummary>(
    () => api.runCompliance(run!.id, profileId, level, groupId),
    [run?.id, profileId, level, groupId, saved.data],
    !!run && !!def,
  );

  const save = async (patch: Partial<ComplianceProfileOut>) => {
    if (!eid) return;
    setBusy(true);
    setActionError(null);
    try {
      await api.saveComplianceProfile(eid, profileId, {
        level: patch.level !== undefined ? patch.level : level,
        excluded: patch.excluded ?? savedRow?.excluded ?? [],
        added: patch.added ?? savedRow?.added ?? [],
        in_report: patch.in_report ?? savedRow?.in_report ?? true,
      });
      saved.reload();
    } catch (e) {
      setActionError(e as Error);
    } finally {
      setBusy(false);
    }
  };

  const removeFromReport = async () => {
    if (!eid) return;
    setBusy(true);
    setActionError(null);
    try {
      await api.deleteComplianceProfile(eid, profileId);
      saved.reload();
    } catch (e) {
      setActionError(e as Error);
    } finally {
      setBusy(false);
    }
  };

  const recompute = async () => {
    if (!run) return;
    setBusy(true);
    setActionError(null);
    try {
      await api.recomputeCompliance(run.id);
      summary.reload();
    } catch (e) {
      setActionError(e as Error);
    } finally {
      setBusy(false);
    }
  };

  const toggleExcluded = (id: string) => {
    const cur = new Set(savedRow?.excluded ?? []);
    if (cur.has(id)) cur.delete(id);
    else cur.add(id);
    void save({ excluded: [...cur].sort() });
  };

  const s = summary.data;
  const grouped = useMemo(() => {
    const out: { code: string; title: string; items: ComplianceControl[] }[] = [];
    for (const c of s?.controls ?? []) {
      if (onlyFailed && c.status !== "failed") continue;
      let g = out.find((x) => x.code === c.group);
      if (!g) out.push((g = { code: c.group, title: c.group_title, items: [] }));
      g.items.push(c);
    }
    return out;
  }, [s, onlyFailed]);

  if (!engagement) return <div className="card"><Empty title="Выберите или создайте договор" /></div>;

  return (
    <>
      <div className="page-head">
        <div>
          <span className="crumbs">{engagement.client ? `${engagement.client} · ${engagement.name}` : engagement.name}</span>
          <h1>Соответствие требованиям</h1>
          <span className="muted">
            Приказы ФСТЭК России №17, №21, №239 и CIS. Процент — доля выполненных мер среди проверенных автоматически; организационные и
            непроверенные меры в процент не входят и показаны отдельно.
          </span>
        </div>
        <div className="actions">{runs.length > 0 && <RunPicker runs={runs} value={run?.id ?? null} onChange={setRun} />}</div>
      </div>

      {(error || catalog.error) && <ErrorAlert error={(error ?? catalog.error)!} onRetry={reload} />}
      {actionError && <ErrorAlert error={actionError} />}

      <section className="card" style={{ overflow: "hidden" }}>
        <div className="tabs" role="tablist" style={{ padding: "0 12px" }}>
          {(catalog.data ?? []).map((p) => (
            <button key={p.id} type="button" role="tab" className="tab" aria-selected={p.id === profileId} onClick={() => setProfileId(p.id)}>
              {p.short}
              {saved.data?.some((x) => x.profile === p.id && x.in_report) && <span className="count">в отчёте</span>}
            </button>
          ))}
        </div>
        {def && (
          <div className="inline" style={{ padding: 12, gap: 16, flexWrap: "wrap" }}>
            {def.levels.length > 0 && (
              <label className="inline" style={{ gap: 8 }}>
                <span className="faint" style={{ fontSize: 13 }}>{def.level_label}</span>
                <select className="select" style={{ width: "auto", height: 34 }} value={level ?? ""} onChange={(e) => setLevel(e.target.value)}>
                  {def.levels.map((l) => (
                    <option key={l} value={l}>
                      {l}
                    </option>
                  ))}
                </select>
              </label>
            )}
            {(groups.data?.length ?? 0) > 0 && (
              <label className="inline" style={{ gap: 8 }}>
                <span className="faint" style={{ fontSize: 13 }}>Группа активов</span>
                <select
                  className="select"
                  style={{ width: "auto", height: 34 }}
                  value={groupId ?? ""}
                  onChange={(e) => setGroupId(e.target.value ? Number(e.target.value) : null)}
                >
                  <option value="">Все хосты</option>
                  {groups.data!.map((g) => (
                    <option key={g.id} value={g.id}>
                      {g.name}
                    </option>
                  ))}
                </select>
              </label>
            )}
            <label className="inline" style={{ gap: 6 }}>
              <input type="checkbox" checked={onlyFailed} onChange={(e) => setOnlyFailed(e.target.checked)} />
              <span style={{ fontSize: 13 }}>Только невыполненные</span>
            </label>
            <span style={{ marginLeft: "auto" }} className="inline">
              {canManage && (
                <button type="button" className="btn btn-sm" disabled={busy} onClick={() => void save({ in_report: true })}>
                  {savedRow ? "Сохранить уровень для договора" : "Включить в отчёт"}
                </button>
              )}
              {canManage && savedRow && (
                <button type="button" className="btn btn-sm btn-ghost" disabled={busy} onClick={() => void removeFromReport()}>
                  Убрать из отчёта
                </button>
              )}
              {canRun && run && (
                <button type="button" className="btn btn-sm btn-ghost" disabled={busy} onClick={() => void recompute()} title="Пересчитать по сохранённым результатам прогона">
                  <RefreshCw size={14} /> Пересчитать
                </button>
              )}
            </span>
          </div>
        )}
        {def && (
          <p className="muted" style={{ padding: "0 12px 12px", margin: 0, fontSize: 13 }}>
            {def.document}{" "}
            <a href={def.url} target="_blank" rel="noreferrer">
              <ExternalLink size={12} /> документ
            </a>
            {savedRow && savedRow.excluded.length > 0 && <> · исключено из набора мер: {savedRow.excluded.join(", ")}</>}
          </p>
        )}
      </section>

      {loading && !run ? (
        <Loading />
      ) : !run ? (
        <div className="card">
          <Empty title="Нет завершённых прогонов" icon={<ClipboardCheck size={28} />}>
            Запустите аудит конфигураций и (или) инвентаризацию по учётной записи — по ним считается соответствие.
          </Empty>
        </div>
      ) : summary.error ? (
        <ErrorAlert error={summary.error} onRetry={summary.reload} />
      ) : !s ? (
        <Loading />
      ) : (
        <>
          <div className="kpis" style={{ marginTop: 16 }}>
            <Kpi label="Соответствие" value={pct(s.percent)} delta={`проверено мер: ${s.evaluated} из ${s.automated}`} />
            <Kpi label="Выполнено" value={s.counts.passed} />
            <Kpi label="Не выполнено" value={s.counts.failed} tone={s.counts.failed ? "critical" : undefined} />
            <Kpi label="Проверяется вручную" value={s.counts.manual} delta={`не проверено: ${s.counts.na}`} />
          </div>

          {!s.has_results && (
            <div className="card" style={{ marginTop: 16 }}>
              <Empty title="Для этого прогона соответствие не рассчитано">
                Прогон выполнен до появления профилей или без проверок по учётной записи. Нажмите «Пересчитать» или запустите новый прогон.
              </Empty>
            </div>
          )}

          {(s.groups.length > 0 || s.hosts.length > 0) && (
            <section className="card" style={{ marginTop: 16, overflow: "hidden" }}>
              <div className="table-wrap">
                <table className="table">
                  <thead>
                    <tr>
                      <th>{s.groups.length > 0 ? "Группа / хост" : "Хост"}</th>
                      <th className="num">Выполнено</th>
                      <th className="num">Не выполнено</th>
                      <th className="num">Не проверено</th>
                      <th className="num">Соответствие</th>
                    </tr>
                  </thead>
                  <tbody>
                    {s.groups.map((g) => (
                      <tr key={`g-${g.group}`}>
                        <td>
                          <b>{g.group}</b> <span className="faint">· хостов: {g.hosts}</span>
                        </td>
                        <td className="num">{g.passed}</td>
                        <td className="num">{g.failed}</td>
                        <td className="num">{g.na ?? 0}</td>
                        <td className="num">
                          <b>{pct(g.percent)}</b>
                        </td>
                      </tr>
                    ))}
                    {s.hosts.map((h) => (
                      <tr key={h.host}>
                        <td className="mono">{h.host}</td>
                        <td className="num">{h.passed}</td>
                        <td className="num">{h.failed}</td>
                        <td className="num">{h.na ?? 0}</td>
                        <td className="num">
                          <b>{pct(h.percent)}</b>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </section>
          )}

          {grouped.map((g) => (
            <section key={g.code} className="card" style={{ marginTop: 16, overflow: "hidden" }}>
              <h3 style={{ margin: 0, padding: "12px 16px" }}>
                {g.code} · {g.title}
              </h3>
              <div className="table-wrap">
                <table className="table">
                  <tbody>
                    {g.items.map((c) => (
                      <ControlRow key={c.id} c={c} canManage={canManage && !def?.dynamic} onExclude={() => toggleExcluded(c.id)} busy={busy} />
                    ))}
                  </tbody>
                </table>
              </div>
            </section>
          ))}

          {s.manual.length > 0 && !onlyFailed && (
            <section className="card" style={{ marginTop: 16, padding: 16 }}>
              <h3 style={{ marginTop: 0 }}>Проверяется вручную ({s.manual.length})</h3>
              <p className="muted" style={{ fontSize: 13 }}>
                Организационные меры: регламенты, документы, физическая защита. Сканированием не проверяются и на процент не влияют.
              </p>
              <ul style={{ margin: 0, paddingLeft: 18 }}>
                {s.manual.map((m) => (
                  <li key={m.id} style={{ fontSize: 13 }}>
                    <b>{m.id}</b> {m.title}
                    {canManage && !def?.dynamic && (
                      <button type="button" className="btn btn-sm btn-ghost" disabled={busy} onClick={() => toggleExcluded(m.id)} style={{ marginLeft: 6 }}>
                        исключить
                      </button>
                    )}
                  </li>
                ))}
              </ul>
            </section>
          )}
        </>
      )}
    </>
  );
}

function ControlRow({ c, canManage, onExclude, busy }: { c: ComplianceControl; canManage: boolean; onExclude: () => void; busy: boolean }) {
  const [open, setOpen] = useState(false);
  const failed = c.status === "failed";
  return (
    <>
      <tr>
        <td className="mono nowrap" style={{ width: 90 }}>
          {c.id}
        </td>
        <td>
          {c.title}
          {failed && (
            <button type="button" className="btn btn-sm btn-ghost" onClick={() => setOpen(!open)} style={{ marginLeft: 6 }}>
              {open ? "скрыть" : `где и что сделать (${c.failed_hosts?.length ?? 0})`}
            </button>
          )}
        </td>
        <td className="nowrap faint" style={{ fontSize: 12 }}>
          хостов: {c.hosts.passed + c.hosts.failed}
        </td>
        <td className="nowrap">
          <StatusPill status={c.status} />
        </td>
        {canManage && (
          <td className="nowrap">
            <button type="button" className="btn btn-sm btn-ghost" disabled={busy} onClick={onExclude} title="Исключить меру из набора (адаптация)">
              исключить
            </button>
          </td>
        )}
      </tr>
      {open && failed && (
        <tr>
          <td />
          <td colSpan={canManage ? 4 : 3}>
            {(c.recommendations ?? []).map((r) => (
              <div key={r.check} style={{ marginBottom: 8 }}>
                <b>{r.title}</b>
                <div className="muted" style={{ fontSize: 13 }}>
                  {r.remediation}
                  {r.doc && (
                    <>
                      {" "}
                      <a href={r.doc} target="_blank" rel="noreferrer">
                        <ExternalLink size={12} />
                      </a>
                    </>
                  )}
                </div>
              </div>
            ))}
            {(c.failed_hosts ?? []).map((fh) => (
              <div key={fh.host} style={{ fontSize: 13, marginTop: 4 }}>
                <span className="mono">{fh.host}</span>:{" "}
                {fh.checks
                  .flatMap((x) => x.failures)
                  .slice(0, 6)
                  .map((f) => f.title)
                  .join("; ")}
              </div>
            ))}
          </td>
        </tr>
      )}
    </>
  );
}
