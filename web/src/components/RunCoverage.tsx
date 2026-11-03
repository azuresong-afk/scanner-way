import { useState } from "react";
import { Link } from "react-router-dom";
import { AlertTriangle, Download } from "lucide-react";
import { api } from "../api/client";
import type { CoverageOut, FindingsSummary, RunOut, RunWarning } from "../api/types";
import { useAuth } from "../auth/AuthContext";
import { COVERAGE_LABEL, COVERAGE_PILL, HOST_COVERAGE_LABEL, MODULE_LABEL } from "../lib/labels";

/** Предупреждения прогона: «Бэкпорты не учтены» (с загрузкой бюллетеней одним действием),
 * находки только по баннерам и др. */
export function RunWarnings({ warnings }: { warnings: RunWarning[] }) {
  const { has } = useAuth();
  const [state, setState] = useState<Record<string, string>>({});
  if (!warnings.length) return null;
  const load = async (w: RunWarning) => {
    const key = `${w.family}:${w.release}`;
    setState((s) => ({ ...s, [key]: "loading" }));
    try {
      const feed = await api.loadRelease(w.family!, w.release!);
      setState((s) => ({ ...s, [key]: feed.running ? "Загрузка запущена — ход виден в «Справочниках»" : (feed.message ?? "Загружено") }));
    } catch (e) {
      setState((s) => ({ ...s, [key]: `Ошибка: ${(e as Error).message}` }));
    }
  };
  return (
    <div className="stack" style={{ gap: 8 }}>
      {warnings.map((w, i) => {
        const key = `${w.family}:${w.release}`;
        const st = state[key];
        return (
          <div key={i} className="alert alert-warn" role="alert">
            <AlertTriangle size={16} aria-hidden="true" />
            <span className="stack" style={{ gap: 6 }}>
              <span>{w.message}</span>
              {w.kind === "advisories_missing" && w.loadable && w.family && w.release && has("manage_engagements") && (
                <span className="inline" style={{ gap: 8, flexWrap: "wrap" }}>
                  <button type="button" className="btn btn-sm" disabled={st === "loading"} onClick={() => void load(w)}>
                    <Download size={14} /> {st === "loading" ? "Запуск…" : `Загрузить бюллетени ${key}`}
                  </button>
                  <small className="muted">Сканер обратится к источнику вендора; затем повторите прогон, чтобы учесть бэкпорты.</small>
                </span>
              )}
              {st && st !== "loading" && <small>{st}</small>}
            </span>
          </div>
        );
      })}
    </div>
  );
}

/** Сопоставимость с базовым прогоном: какой прогон взят и почему сравнение неполное. */
export function Comparison({ summary }: { summary: FindingsSummary }) {
  const c = summary.comparability;
  if (summary.previous_run_id == null) return null;
  const level = c?.level ?? "same";
  return (
    <div className={`alert ${level === "same" ? "alert-info" : "alert-warn"}`}>
      <span className="stack" style={{ gap: 4 }}>
        <span>
          Сравнение с базовым прогоном <Link to={`/runs/${summary.previous_run_id}`}>№{summary.previous_run_id}</Link>
          {level === "same" ? " — проверены те же хосты и модули." : level === "partial" ? " — сопоставим частично." : " — несопоставим."}
        </span>
        {(c?.warnings ?? []).map((w, i) => (
          <small key={i}>{w}</small>
        ))}
        {!!summary.unverified && (
          <small>
            Не проверено в этом прогоне: {summary.unverified} находок базового прогона — они не считаются ни устранёнными, ни открытыми.
          </small>
        )}
      </span>
    </div>
  );
}

/** Полнота проверки: что реально проверено на каждом хосте каждым модулем. */
export function CoverageTable({ coverage }: { coverage: CoverageOut }) {
  const modules = [...new Set(coverage.entries.map((e) => e.module))];
  const s = coverage.summary;
  const gaps = coverage.entries.filter((e) => !["completed", "not_applicable"].includes(e.status));
  return (
    <div className="stack" style={{ gap: 12 }}>
      <div className="inline" style={{ gap: 16, flexWrap: "wrap" }}>
        <span>
          Хостов: <b>{s.hosts}</b>
        </span>
        <span>
          проверено полностью: <b>{s.hosts_checked}</b>
        </span>
        <span>
          частично: <b style={s.hosts_partial ? { color: "var(--warn)" } : undefined}>{s.hosts_partial}</b>
        </span>
        <span>
          недоступно: <b style={s.hosts_unreachable ? { color: "var(--danger)" } : undefined}>{s.hosts_unreachable}</b>
        </span>
        {coverage.legacy && <small className="muted">Прогон до обновления — полнота оценена по модулям и найденным хостам.</small>}
      </div>
      <div className="table-wrap">
        <table className="table">
          <thead>
            <tr>
              <th>Хост</th>
              <th>Итог</th>
              {modules.map((m) => (
                <th key={m}>{MODULE_LABEL[m] ?? m}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {coverage.hosts.map((h) => (
              <tr key={h.host}>
                <td className="mono">{h.host}</td>
                <td>
                  <span className={`pill ${h.status === "checked" ? "pill-ok" : h.status === "partial" ? "pill-warn" : "pill-danger"}`}>
                    {HOST_COVERAGE_LABEL[h.status] ?? h.status}
                  </span>
                </td>
                {modules.map((m) => {
                  const e = h.modules[m];
                  return (
                    <td key={m} title={e?.reason ?? undefined}>
                      {e ? <span className={`pill ${COVERAGE_PILL[e.status] ?? "pill-muted"}`}>{COVERAGE_LABEL[e.status] ?? e.label}</span> : "—"}
                    </td>
                  );
                })}
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      {gaps.length > 0 && (
        <details>
          <summary style={{ cursor: "pointer", fontWeight: 600 }}>Что не проверено и почему ({gaps.length})</summary>
          <ul className="stack" style={{ gap: 6, marginTop: 8 }}>
            {gaps.map((g) => (
              <li key={`${g.host}-${g.module}`}>
                <span className="mono">{g.host}</span> · {MODULE_LABEL[g.module] ?? g.module} — <b>{COVERAGE_LABEL[g.status] ?? g.label}</b>
                {g.reason ? `: ${g.reason}` : ""}
              </li>
            ))}
          </ul>
        </details>
      )}
    </div>
  );
}

/** Шапка результата прогона: статус «Частично»/недоступность, предупреждения, сравнение. */
export function RunResultNotes({ run, summary }: { run: RunOut; summary?: FindingsSummary | null }) {
  return (
    <>
      {run.status === "partial" && (
        <div className="alert alert-warn" role="alert">
          <AlertTriangle size={16} aria-hidden="true" />
          <span>
            <b>Проверка выполнена не полностью.</b> {run.error_message ?? "Часть хостов или модулей не проверена — см. «Полнота проверки»."} Отсутствие
            находок на непроверенных хостах не означает отсутствия уязвимостей.
          </span>
        </div>
      )}
      <RunWarnings warnings={run.warnings ?? []} />
      {summary && <Comparison summary={summary} />}
    </>
  );
}
