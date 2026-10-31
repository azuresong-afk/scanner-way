import { useState } from "react";
import { Bell, Pencil, Play, Plus, RotateCw, Trash2 } from "lucide-react";
import { api } from "../api/client";
import type { ChannelFilters, ChannelIn, ChannelOut, ChannelType, DeliveryOut, NotifyEvent, Severity } from "../api/types";
import { useAuth } from "../auth/AuthContext";
import { Empty, ErrorAlert, Loading, Modal } from "../components/ui";
import { fmtDate } from "../lib/format";
import { SEVERITIES, SEVERITY_LABEL } from "../lib/labels";
import { useAsync } from "../lib/useAsync";

interface FieldDef {
  key: string;
  label: string;
  required?: boolean;
  placeholder?: string;
  options?: [string, string][];
  /** Список через запятую. */
  list?: boolean;
  number?: boolean;
  default?: string;
}

interface TypeDef {
  label: string;
  hint: string;
  events: NotifyEvent[];
  fields: FieldDef[];
  secret?: { key: string; label: string; required?: boolean };
}

const ALL_EVENTS: NotifyEvent[] = ["run_finished", "new_critical", "feed_stale"];
const EVENT_LABEL: Record<NotifyEvent | "test", string> = {
  run_finished: "Прогон завершён",
  new_critical: "Новые критичные находки",
  feed_stale: "Справочник не обновился",
  test: "Проверка канала",
};
const PRIORITIES: [string, string][] = [
  ["critical", "критический"],
  ["high", "высокий"],
  ["medium", "средний"],
  ["low", "низкий"],
];

const TYPES: Record<ChannelType, TypeDef> = {
  smtp: {
    label: "Почта (SMTP)",
    hint: "Письмо с сводкой и ссылкой на отчёт. Вход по паролю — только по зашифрованному соединению.",
    events: ALL_EVENTS,
    fields: [
      { key: "host", label: "SMTP-сервер", required: true, placeholder: "mail.corp.local" },
      { key: "port", label: "Порт", number: true, placeholder: "587" },
      { key: "security", label: "Шифрование", default: "starttls", options: [["starttls", "STARTTLS"], ["ssl", "SSL/TLS"], ["none", "Без шифрования (без пароля)"]] },
      { key: "username", label: "Логин", placeholder: "scanner" },
      { key: "sender", label: "От кого", required: true, placeholder: "scanner@corp.local" },
      { key: "to", label: "Кому (через запятую)", required: true, list: true, placeholder: "sec@corp.local, soc@corp.local" },
    ],
    secret: { key: "password", label: "Пароль SMTP" },
  },
  telegram: {
    label: "Telegram",
    hint: "Сообщение от бота в чат или канал. Бот должен быть добавлен в чат.",
    events: ALL_EVENTS,
    fields: [
      { key: "chat_id", label: "Чат (id или @канал)", required: true, placeholder: "-1001234567890" },
      { key: "api_base", label: "Адрес Bot API", placeholder: "https://api.telegram.org" },
    ],
    secret: { key: "bot_token", label: "Токен бота", required: true },
  },
  syslog_cef: {
    label: "Syslog (CEF)",
    hint: "События в SIEM: RFC 5424, тело в формате CEF. Передача без шифрования — только внутри контура.",
    events: ALL_EVENTS,
    fields: [
      { key: "host", label: "Сервер syslog", required: true, placeholder: "siem.corp.local" },
      { key: "port", label: "Порт", number: true, placeholder: "514" },
      { key: "protocol", label: "Протокол", default: "udp", options: [["udp", "UDP"], ["tcp", "TCP"]] },
      { key: "facility", label: "Facility", default: "local4", options: ["user", "auth", "authpriv", ...Array.from({ length: 8 }, (_, i) => `local${i}`)].map((f) => [f, f] as [string, string]) },
      { key: "app_name", label: "Имя приложения", placeholder: "scanner" },
    ],
  },
  jira: {
    label: "Jira",
    hint: "Задача на каждую новую критичную находку; повторно на ту же находку задача не создаётся.",
    events: ["new_critical"],
    fields: [
      { key: "base_url", label: "Адрес Jira", required: true, placeholder: "https://jira.corp.local" },
      { key: "project_key", label: "Ключ проекта", required: true, placeholder: "SEC" },
      { key: "issue_type", label: "Тип задачи", placeholder: "Task" },
      { key: "auth_type", label: "Вход", default: "basic", options: [["basic", "Логин + токен API"], ["bearer", "Персональный токен (Bearer)"]] },
      { key: "username", label: "Логин (email)", placeholder: "scanner@corp.local" },
      { key: "labels", label: "Метки (через запятую)", list: true, placeholder: "pentest, scanner" },
      { key: "max_issues", label: "Задач за событие, не более", number: true, placeholder: "20" },
    ],
    secret: { key: "api_token", label: "Токен API", required: true },
  },
};

const csv = (s: string): string[] => s.split(/[,;\n]+/).map((x) => x.trim()).filter(Boolean);

function filterSummary(f: ChannelFilters): string {
  const parts: string[] = [];
  if (f.min_severity) parts.push(`опасность ≥ ${SEVERITY_LABEL[f.min_severity].toLowerCase()}`);
  if (f.min_priority) parts.push(`приоритет ≥ ${PRIORITIES.find(([k]) => k === f.min_priority)?.[1]}`);
  if (f.groups.length) parts.push(`группы: ${f.groups.join(", ")}`);
  if (f.owners.length) parts.push(`владельцы: ${f.owners.join(", ")}`);
  return parts.join(" · ") || "все находки";
}

function ChannelModal({ channel, onClose, onSaved }: { channel: ChannelOut | null; onClose: () => void; onSaved: () => void }) {
  const [type, setType] = useState<ChannelType>(channel?.type ?? "smtp");
  const [name, setName] = useState(channel?.name ?? "");
  const [enabled, setEnabled] = useState(channel?.enabled ?? true);
  const [cfg, setCfg] = useState<Record<string, string>>(() => {
    const out: Record<string, string> = {};
    for (const [k, v] of Object.entries(channel?.config ?? {})) out[k] = Array.isArray(v) ? v.join(", ") : String(v ?? "");
    return out;
  });
  const [secret, setSecret] = useState("");
  const [events, setEvents] = useState<NotifyEvent[]>(channel?.events ?? ALL_EVENTS);
  const [minSeverity, setMinSeverity] = useState<string>(channel?.filters.min_severity ?? "");
  const [minPriority, setMinPriority] = useState<string>(channel?.filters.min_priority ?? "");
  const [groups, setGroups] = useState((channel?.filters.groups ?? []).join(", "));
  const [owners, setOwners] = useState((channel?.filters.owners ?? []).join(", "));
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const def = TYPES[type];
  const allowed = def.events;
  const activeEvents = events.filter((e) => allowed.includes(e));
  const secretNeeded = !!def.secret?.required && !channel;
  const valid =
    name.trim() !== "" &&
    activeEvents.length > 0 &&
    def.fields.every((f) => !f.required || (cfg[f.key] ?? f.default ?? "").trim() !== "") &&
    (!secretNeeded || secret !== "");

  const changeType = (t: ChannelType) => {
    setType(t);
    setCfg({});
    setSecret("");
  };

  const save = async () => {
    setBusy(true);
    setError(null);
    const config: Record<string, unknown> = {};
    for (const f of def.fields) {
      const raw = (cfg[f.key] ?? f.default ?? "").trim();
      if (!raw) continue;
      config[f.key] = f.list ? csv(raw) : f.number ? Number(raw) : raw;
    }
    const filters: ChannelFilters = {
      min_severity: (minSeverity || null) as Severity | null,
      min_priority: (minPriority || null) as ChannelFilters["min_priority"],
      groups: csv(groups),
      owners: csv(owners),
      engagements: channel?.filters.engagements ?? [],
    };
    const secrets = def.secret && secret ? { [def.secret.key]: secret } : {};
    try {
      if (channel) {
        await api.updateChannel(channel.id, { name: name.trim(), enabled, config, events: activeEvents, filters, ...(secret ? { secrets } : {}) });
      } else {
        const body: ChannelIn = { name: name.trim(), type, enabled, config, secrets, events: activeEvents, filters };
        await api.createChannel(body);
      }
      onSaved();
    } catch (e) {
      setError((e as Error).message);
      setBusy(false);
    }
  };

  const toggleEvent = (e: NotifyEvent) => setEvents((cur) => (cur.includes(e) ? cur.filter((x) => x !== e) : [...cur, e]));
  const thresholds = activeEvents.includes("new_critical");

  return (
    <Modal
      wide
      title={channel ? `Канал: ${channel.name}` : "Новый канал уведомлений"}
      onClose={onClose}
      footer={
        <>
          <button type="button" className="btn" onClick={onClose}>
            Отмена
          </button>
          <button type="button" className="btn btn-primary" disabled={!valid || busy} onClick={() => void save()}>
            Сохранить
          </button>
        </>
      }
    >
      {error && <ErrorAlert error={error} />}
      <div className="inline" style={{ gap: 12, flexWrap: "wrap" }}>
        <label className="field" style={{ flex: "1 1 220px" }}>
          <span>Название</span>
          <input className="input" value={name} onChange={(e) => setName(e.target.value)} maxLength={100} placeholder="SOC: критичные" />
        </label>
        <label className="field" style={{ flex: "1 1 220px" }}>
          <span>Тип</span>
          <select className="select" value={type} disabled={!!channel} onChange={(e) => changeType(e.target.value as ChannelType)}>
            {(Object.keys(TYPES) as ChannelType[]).map((t) => (
              <option key={t} value={t}>
                {TYPES[t].label}
              </option>
            ))}
          </select>
        </label>
      </div>
      <p className="muted" style={{ margin: "4px 0 8px" }}>
        {def.hint}
      </p>

      <div className="inline" style={{ gap: 12, flexWrap: "wrap" }}>
        {def.fields.map((f) => (
          <label className="field" key={`${type}-${f.key}`} style={{ flex: "1 1 220px" }}>
            <span>{f.label}</span>
            {f.options ? (
              <select className="select" value={cfg[f.key] ?? f.default ?? ""} onChange={(e) => setCfg({ ...cfg, [f.key]: e.target.value })}>
                {f.options.map(([v, l]) => (
                  <option key={v} value={v}>
                    {l}
                  </option>
                ))}
              </select>
            ) : (
              <input
                className="input"
                value={cfg[f.key] ?? ""}
                onChange={(e) => setCfg({ ...cfg, [f.key]: e.target.value })}
                placeholder={f.placeholder}
                inputMode={f.number ? "numeric" : undefined}
              />
            )}
          </label>
        ))}
        {def.secret && (
          <label className="field" style={{ flex: "1 1 220px" }}>
            <span>{def.secret.label}</span>
            <input
              className="input"
              type="password"
              value={secret}
              onChange={(e) => setSecret(e.target.value)}
              autoComplete="new-password"
              placeholder={channel?.has_secret ? "задан — оставьте пустым, чтобы не менять" : undefined}
            />
          </label>
        )}
      </div>

      <fieldset className="field" style={{ border: 0, padding: 0, margin: "12px 0 0" }}>
        <span>События</span>
        <div className="inline" role="group" aria-label="События" style={{ gap: 8, flexWrap: "wrap" }}>
          {allowed.map((e) => (
            <button key={e} type="button" className="chip" aria-pressed={events.includes(e)} onClick={() => toggleEvent(e)}>
              {EVENT_LABEL[e]}
            </button>
          ))}
        </div>
      </fieldset>

      <fieldset className="field" style={{ border: 0, padding: 0, margin: "12px 0 0" }}>
        <span>Что отправлять</span>
        <div className="inline" style={{ gap: 12, flexWrap: "wrap" }}>
          {thresholds && (
            <>
              <label className="field" style={{ flex: "1 1 180px" }}>
                <span>Порог опасности</span>
                <select className="select" value={minSeverity} onChange={(e) => setMinSeverity(e.target.value)}>
                  <option value="">по умолчанию (критическая)</option>
                  {[...SEVERITIES].reverse().map((s) => (
                    <option key={s} value={s}>
                      не ниже: {SEVERITY_LABEL[s].toLowerCase()}
                    </option>
                  ))}
                </select>
              </label>
              <label className="field" style={{ flex: "1 1 180px" }}>
                <span>Порог приоритета</span>
                <select className="select" value={minPriority} onChange={(e) => setMinPriority(e.target.value)}>
                  <option value="">не учитывать</option>
                  {PRIORITIES.map(([k, l]) => (
                    <option key={k} value={k}>
                      не ниже: {l}
                    </option>
                  ))}
                </select>
              </label>
            </>
          )}
          <label className="field" style={{ flex: "1 1 220px" }}>
            <span>Группы активов (через запятую)</span>
            <input className="input" value={groups} onChange={(e) => setGroups(e.target.value)} placeholder="все группы" />
          </label>
          <label className="field" style={{ flex: "1 1 220px" }}>
            <span>Владельцы активов (через запятую)</span>
            <input className="input" value={owners} onChange={(e) => setOwners(e.target.value)} placeholder="все владельцы" />
          </label>
        </div>
        <small className="faint">Если заданы группы или владельцы, в сообщение попадают только их хосты. Без порогов «критичная» — критическая по опасности или по приоритету.</small>
      </fieldset>

      <label className="inline" style={{ gap: 8, marginTop: 12 }}>
        <input type="checkbox" checked={enabled} onChange={(e) => setEnabled(e.target.checked)} />
        <span>Канал включён</span>
      </label>
    </Modal>
  );
}

const STATUS_LABEL: Record<string, string> = { pending: "в очереди", retry: "повтор", sent: "доставлено", failed: "ошибка" };

/** Каналы уведомлений (почта, Telegram, syslog/CEF, Jira) и журнал доставки. */
export function IntegrationsPage() {
  const { has } = useAuth();
  const channels = useAsync(() => api.channels(), []);
  const log = useAsync(() => api.deliveries(50), []);
  const [editing, setEditing] = useState<ChannelOut | "new" | null>(null);
  const [busy, setBusy] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [testResult, setTestResult] = useState<{ id: number; delivery: DeliveryOut } | null>(null);
  const canEdit = has("manage_engagements");
  const list = channels.data ?? [];

  const act = async (key: string, fn: () => Promise<unknown>) => {
    setBusy(key);
    setError(null);
    try {
      await fn();
      await Promise.all([channels.reload(), log.reload()]);
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(null);
    }
  };

  const remove = (c: ChannelOut) => {
    if (window.confirm(`Удалить канал «${c.name}» вместе с журналом его доставок?`)) void act(`del-${c.id}`, () => api.deleteChannel(c.id));
  };

  return (
    <>
      <div className="page-head">
        <div>
          <span className="crumbs">Администрирование</span>
          <h1>Уведомления</h1>
        </div>
        {canEdit && (
          <button type="button" className="btn btn-primary" onClick={() => setEditing("new")}>
            <Plus size={14} /> Новый канал
          </button>
        )}
      </div>

      {error && <ErrorAlert error={error} />}
      {channels.error && <ErrorAlert error={channels.error} onRetry={channels.reload} />}
      {testResult && (
        <div className={testResult.delivery.status === "sent" ? "alert alert-ok" : "alert alert-danger"} role="status">
          Проверка канала: {testResult.delivery.status === "sent" ? "доставлено" : `ошибка — ${testResult.delivery.last_error ?? ""}`}
        </div>
      )}

      <div className="card" style={{ overflow: "hidden" }}>
        {channels.loading && !channels.data ? (
          <Loading />
        ) : list.length === 0 ? (
          <Empty title="Каналов пока нет" icon={<Bell size={28} />}>
            Добавьте почту, Telegram, syslog (CEF) или Jira, чтобы получать итоги прогонов и новые критичные находки.
          </Empty>
        ) : (
          <div className="table-wrap">
            <table className="table" style={{ minWidth: 900 }}>
              <thead>
                <tr>
                  <th>Канал</th>
                  <th>События</th>
                  <th>Фильтры</th>
                  <th>Состояние</th>
                  <th />
                </tr>
              </thead>
              <tbody>
                {list.map((c) => (
                  <tr key={c.id}>
                    <td>
                      <div style={{ fontWeight: 500 }}>{c.name}</div>
                      <small className="muted">{TYPES[c.type].label}</small>
                    </td>
                    <td>{c.events.map((e) => EVENT_LABEL[e]).join(", ")}</td>
                    <td className="muted">{filterSummary(c.filters)}</td>
                    <td className="nowrap">{c.enabled ? "включён" : <span className="muted">выключен</span>}</td>
                    <td className="right nowrap">
                      {canEdit && (
                        <div className="inline" style={{ gap: 6, justifyContent: "flex-end" }}>
                          <button
                            type="button"
                            className="btn btn-sm"
                            disabled={busy === `test-${c.id}`}
                            onClick={() => void act(`test-${c.id}`, async () => setTestResult({ id: c.id, delivery: await api.testChannel(c.id) }))}
                          >
                            <Play size={12} /> Проверить
                          </button>
                          <button type="button" className="btn btn-sm" aria-label={`Изменить: ${c.name}`} onClick={() => setEditing(c)}>
                            <Pencil size={12} />
                          </button>
                          <button type="button" className="btn btn-sm" aria-label={`Удалить: ${c.name}`} onClick={() => remove(c)}>
                            <Trash2 size={12} />
                          </button>
                        </div>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      <h2 style={{ margin: "24px 0 8px" }}>Журнал доставки</h2>
      <div className="card" style={{ overflow: "hidden" }}>
        {log.error && <ErrorAlert error={log.error} onRetry={log.reload} />}
        {(log.data ?? []).length === 0 ? (
          <Empty title="Отправок ещё не было" />
        ) : (
          <div className="table-wrap">
            <table className="table" style={{ minWidth: 900 }}>
              <thead>
                <tr>
                  <th>Время</th>
                  <th>Канал</th>
                  <th>Событие</th>
                  <th>Итог</th>
                  <th />
                </tr>
              </thead>
              <tbody>
                {(log.data ?? []).map((d) => (
                  <tr key={d.id}>
                    <td className="muted nowrap">{fmtDate(d.created_at)}</td>
                    <td>{d.channel_name ?? `#${d.channel_id}`}</td>
                    <td>
                      {EVENT_LABEL[d.event]}
                      {d.summary && (
                        <div>
                          <small className="faint">{d.summary}</small>
                        </div>
                      )}
                    </td>
                    <td>
                      <span style={d.status === "failed" ? { color: "var(--danger)" } : undefined}>{STATUS_LABEL[d.status] ?? d.status}</span>
                      {d.attempts > 1 && <small className="faint"> · попыток: {d.attempts}</small>}
                      {d.external_ref && <small className="faint"> · {d.external_ref}</small>}
                      {d.status === "retry" && d.next_attempt_at && <small className="faint"> · следующая {fmtDate(d.next_attempt_at)}</small>}
                      {d.last_error && (
                        <div>
                          <small style={{ color: "var(--danger)" }}>{d.last_error}</small>
                        </div>
                      )}
                    </td>
                    <td className="right">
                      {canEdit && d.status === "failed" && (
                        <button type="button" className="btn btn-sm" disabled={busy === `retry-${d.id}`} onClick={() => void act(`retry-${d.id}`, () => api.retryDelivery(d.id))}>
                          <RotateCw size={12} /> Повторить
                        </button>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {editing && (
        <ChannelModal
          channel={editing === "new" ? null : editing}
          onClose={() => setEditing(null)}
          onSaved={() => {
            setEditing(null);
            void Promise.all([channels.reload(), log.reload()]);
          }}
        />
      )}
    </>
  );
}
