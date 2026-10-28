import { Fragment, useCallback, useEffect, useState, type FormEvent } from "react";
import { ListChecks } from "lucide-react";
import { api } from "../api/client";
import type { AuditOut } from "../api/types";
import { Empty, ErrorAlert, Loading } from "../components/ui";
import { fmtDateFull } from "../lib/format";

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
};

export function AuditPage() {
  const [rows, setRows] = useState<AuditOut[]>([]);
  const [subject, setSubject] = useState("");
  const [action, setAction] = useState("");
  const [applied, setApplied] = useState({ subject: "", action: "" });
  const [loading, setLoading] = useState(true);
  const [more, setMore] = useState(false);
  const [error, setError] = useState<Error | null>(null);
  const [expanded, setExpanded] = useState<number | null>(null);

  const load = useCallback(
    async (before?: number) => {
      setLoading(true);
      try {
        const page = await api.audit({ limit: PAGE, before_id: before, subject: applied.subject || undefined, action: applied.action || undefined });
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
    setApplied({ subject: subject.trim(), action: action.trim() });
  };

  return (
    <>
      <div className="page-head">
        <div>
          <span className="crumbs">Только чтение · записи нельзя изменить или удалить</span>
          <h1>Журнал аудита</h1>
        </div>
      </div>
      <form className="card card-pad inline" style={{ alignItems: "flex-end" }} onSubmit={submit}>
        <label className="field" style={{ flex: "1 1 220px" }}>
          <span>Субъект</span>
          <input className="input mono" value={subject} onChange={(e) => setSubject(e.target.value)} placeholder="user:ivanov или system" />
        </label>
        <label className="field" style={{ flex: "1 1 220px" }}>
          <span>Действие</span>
          <select className="select" value={action} onChange={(e) => setAction(e.target.value)}>
            <option value="">Все</option>
            {Object.entries(ACTION_LABEL).map(([k, v]) => (
              <option key={k} value={k}>
                {v}
              </option>
            ))}
          </select>
        </label>
        <button type="submit" className="btn btn-primary">
          Применить
        </button>
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
