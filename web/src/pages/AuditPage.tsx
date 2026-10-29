import { Fragment, useCallback, useEffect, useMemo, useState, type FormEvent } from "react";
import { Download, ListChecks } from "lucide-react";
import { api } from "../api/client";
import type { AuditExportFormat, AuditFilters, AuditOut } from "../api/types";
import { Empty, ErrorAlert, Loading } from "../components/ui";
import { saveBlob } from "../lib/download";
import { fmtDateFull, localToIso, toLocalInput } from "../lib/format";

const PAGE = 100;

const RESULT_TONE: Record<string, string> = {
  ok: "pill-ok",
  failure: "pill-danger",
  forbidden: "pill-danger",
  locked: "pill-warn",
};

const ACTION_LABEL: Record<string, string> = {
  login: "Вход",
  user_create: "Создание пользователя",
  user_update: "Изменение пользователя",
  user_roles: "Изменение ролей",
  engagement_create: "Создание договора",
  engagement_update: "Изменение договора",
  engagement_delete: "Удаление договора",
  allowlist_add: "Добавление в allowlist",
  allowlist_remove: "Удаление из allowlist",
  scan_request: "Запрос прогона",
  scan_queue: "Постановка прогона в очередь",
  scan_start: "Начало прогона",
  scan_finish: "Завершение прогона",
  scan_stop: "Остановка прогона",
  module_start: "Запуск модуля",
  module_finish: "Завершение модуля",
  module_skip: "Пропуск модуля",
  deny: "Цель отклонена (вне allowlist)",
  nmap_exec: "Запуск nmap",
  nuclei_exec: "Запуск Nuclei",
  config_audit_ssh: "Аудит конфигурации по SSH",
  cred_audit_attempt: "Попытка входа (cred_audit)",
  cred_audit_limit: "Лимит попыток (cred_audit)",
  cred_audit_lockout: "Блокировка учётки (cred_audit)",
  cred_audit_stop: "Остановка cred_audit",
  feed_sync: "Загрузка справочника",
  export: "Выгрузка отчёта",
  access_denied: "Отказ в доступе",
  audit_view: "Просмотр журнала",
  audit_export: "Выгрузка журнала",
};

const PRESETS: { label: string; hours: number }[] = [
  { label: "24 часа", hours: 24 },
  { label: "7 дней", hours: 24 * 7 },
  { label: "30 дней", hours: 24 * 30 },
];

interface FormState {
  subject: string;
  actions: string[];
  since: string;
  until: string;
}

const EMPTY: FormState = { subject: "", actions: [], since: "", until: "" };

function toFilters(f: FormState): AuditFilters {
  return {
    subject: f.subject.trim() || undefined,
    actions: f.actions.length ? f.actions : undefined,
    since: localToIso(f.since),
    until: localToIso(f.until),
  };
}

export function AuditPage() {
  const [rows, setRows] = useState<AuditOut[]>([]);
  const [form, setForm] = useState<FormState>(EMPTY);
  const [applied, setApplied] = useState<AuditFilters>({});
  const [known, setKnown] = useState<string[]>([]);
  const [loading, setLoading] = useState(true);
  const [more, setMore] = useState(false);
  const [error, setError] = useState<Error | null>(null);
  const [expanded, setExpanded] = useState<number | null>(null);
  const [exporting, setExporting] = useState<AuditExportFormat | null>(null);
  const [exportError, setExportError] = useState<string | null>(null);

  // Действия из справочника + те, что реально встречаются в журнале.
  useEffect(() => {
    api.auditActions().then(setKnown, () => setKnown([]));
  }, []);
  const actionOptions = useMemo(() => {
    const all = new Set([...Object.keys(ACTION_LABEL), ...known]);
    return [...all].sort((a, b) => (ACTION_LABEL[a] ?? a).localeCompare(ACTION_LABEL[b] ?? b, "ru"));
  }, [known]);

  const rangeInvalid = !!form.since && !!form.until && form.since >= form.until;

  const load = useCallback(
    async (before?: number) => {
      setLoading(true);
      try {
        const page = await api.audit({ limit: PAGE, before_id: before, ...applied });
        setRows((r) => (before ? [...r, ...page] : page));
        setMore(page.length === PAGE);
        setError(null);
      } catch (e) {
        setError(e as Error);
      } finally {
        setLoading(false);
      }
    },
    [applied],
  );

  useEffect(() => {
    void load();
  }, [load]);

  const submit = (e: FormEvent) => {
    e.preventDefault();
    if (!rangeInvalid) setApplied(toFilters(form));
  };

  const toggleAction = (a: string) =>
    setForm((f) => ({ ...f, actions: f.actions.includes(a) ? f.actions.filter((x) => x !== a) : [...f.actions, a] }));

  const preset = (hours: number) => {
    const now = new Date();
    setForm((f) => ({ ...f, since: toLocalInput(new Date(now.getTime() - hours * 3600_000)), until: "" }));
  };

  // Выгружается то, что сейчас в форме; заодно применяем фильтр к таблице,
  // чтобы на экране было то же, что в файле.
  const download = async (format: AuditExportFormat) => {
    if (rangeInvalid) return;
    const filters = toFilters(form);
    setApplied(filters);
    setExporting(format);
    setExportError(null);
    try {
      const stamp = new Date().toISOString().replace(/[-:]/g, "").slice(0, 15);
      saveBlob(await api.auditExport(format, filters), `audit-${stamp}Z.${format}`);
    } catch (e) {
      setExportError((e as Error).message);
    } finally {
      setExporting(null);
    }
  };

  return (
    <>
      <div className="page-head">
        <div>
          <span className="crumbs">Только чтение · записи нельзя изменить или удалить</span>
          <h1>Журнал аудита</h1>
        </div>
      </div>
      <form className="card card-pad stack" onSubmit={submit} aria-label="Фильтр журнала">
        <div className="inline" style={{ alignItems: "flex-end" }}>
          <label className="field" style={{ flex: "1 1 200px" }}>
            <span>Субъект</span>
            <input
              className="input mono"
              value={form.subject}
              onChange={(e) => setForm({ ...form, subject: e.target.value })}
              placeholder="user:ivanov или system"
            />
          </label>
          <label className="field" style={{ flex: "1 1 190px" }}>
            <span>С</span>
            <input className="input" type="datetime-local" value={form.since} onChange={(e) => setForm({ ...form, since: e.target.value })} />
          </label>
          <label className="field" style={{ flex: "1 1 190px" }}>
            <span>По</span>
            <input className="input" type="datetime-local" value={form.until} onChange={(e) => setForm({ ...form, until: e.target.value })} />
          </label>
        </div>
        <div className="inline" style={{ gap: 6 }}>
          <small className="muted">Период:</small>
          {PRESETS.map((p) => (
            <button key={p.hours} type="button" className="chip" onClick={() => preset(p.hours)}>
              {p.label}
            </button>
          ))}
          <button type="button" className="chip" onClick={() => setForm({ ...form, since: "", until: "" })}>
            Весь журнал
          </button>
        </div>
        {rangeInvalid && <small style={{ color: "var(--danger)" }}>Начало периода должно быть раньше конца.</small>}
        <details>
          <summary className="muted" style={{ cursor: "pointer" }}>
            Действия: {form.actions.length ? `выбрано ${form.actions.length}` : "все"}
          </summary>
          <div className="inline" style={{ gap: 6, marginTop: 10 }} role="group" aria-label="Действия">
            {actionOptions.map((a) => (
              <button key={a} type="button" className="chip" aria-pressed={form.actions.includes(a)} onClick={() => toggleAction(a)} title={a}>
                {ACTION_LABEL[a] ?? a}
              </button>
            ))}
            {form.actions.length > 0 && (
              <button type="button" className="btn btn-sm" onClick={() => setForm({ ...form, actions: [] })}>
                Сбросить
              </button>
            )}
          </div>
        </details>
        <div className="inline" style={{ gap: 6 }}>
          <button type="submit" className="btn btn-primary" disabled={rangeInvalid}>
            Применить
          </button>
          <span style={{ flex: 1 }} />
          {(["csv", "json"] as const).map((f) => (
            <button
              key={f}
              type="button"
              className="btn"
              disabled={rangeInvalid || !!exporting}
              onClick={() => download(f)}
              aria-label={`Выгрузить журнал ${f.toUpperCase()}`}
            >
              {exporting === f ? <span className="spinner" style={{ width: 14, height: 14 }} /> : <Download size={14} />}
              {f.toUpperCase()}
            </button>
          ))}
        </div>
        <small className="muted">Выгрузка учитывает фильтр в форме: субъект, период и выбранные действия. Записи идут от старых к новым, время — UTC.</small>
        {exportError && <small style={{ color: "var(--danger)" }}>{exportError}</small>}
      </form>
      {error && <ErrorAlert error={error} onRetry={() => load()} />}
      <section className="card" style={{ overflow: "hidden" }}>
        {loading && !rows.length ? (
          <Loading />
        ) : rows.length === 0 ? (
          <Empty title="Записей нет" icon={<ListChecks size={28} />} />
        ) : (
          <div className="table-wrap">
            <table className="table" style={{ minWidth: 820 }}>
              <thead>
                <tr>
                  <th>Время</th>
                  <th>Субъект</th>
                  <th>Действие</th>
                  <th>Объект</th>
                  <th>Результат</th>
                </tr>
              </thead>
              <tbody>
                {rows.map((r) => (
                  <Fragment key={r.id}>
                    <tr className="clickable" onClick={() => setExpanded(expanded === r.id ? null : r.id)}>
                      <td className="nowrap muted">{fmtDateFull(r.ts)}</td>
                      <td className="mono">{r.subject}</td>
                      <td>{ACTION_LABEL[r.action] ?? r.action}</td>
                      <td className="mono muted">{r.target ?? "—"}</td>
                      <td>{r.result ? <span className={`pill ${RESULT_TONE[r.result] ?? "pill-muted"}`}>{r.result}</span> : "—"}</td>
                    </tr>
                    {expanded === r.id && r.details && (
                      <tr>
                        <td colSpan={5}>
                          <pre className="evidence" style={{ margin: 0 }}>
                            {JSON.stringify(r.details, null, 2)}
                          </pre>
                        </td>
                      </tr>
                    )}
                  </Fragment>
                ))}
              </tbody>
            </table>
          </div>
        )}
        {more && (
          <div style={{ padding: 12, textAlign: "center" }}>
            <button type="button" className="btn btn-sm" disabled={loading} onClick={() => load(rows[rows.length - 1]?.id)}>
              Загрузить ещё
            </button>
          </div>
        )}
      </section>
    </>
  );
}
