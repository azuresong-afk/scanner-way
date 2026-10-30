import { useState, type FormEvent } from "react";
import { ShieldCheck } from "lucide-react";
import { api, ApiError } from "../api/client";
import type { DeniedTarget, EngagementOut, RunCreated, ScheduleIn, ScheduleKind, ScheduleOut } from "../api/types";
import { useAuth, type Perm } from "../auth/AuthContext";
import { localToIso, toLocalInput } from "../lib/format";
import { CREDENTIAL_MODULES, ENGINE_MODULES, MODULES, RATE_PROFILES, SCHEDULE_KINDS, VULN_ENGINES, WEEKDAYS, runTitle, type EngineInfo } from "../lib/labels";
import { parseTargets } from "../lib/targets";
import { useAsync } from "../lib/useAsync";
import { ErrorAlert, Modal } from "./ui";

type When = "now" | "schedule";

/** Движок по сохранённому списку модулей (для редактирования расписания). */
function engineOf(modules: string[]): EngineInfo["id"] {
  const v = modules.includes("vuln");
  const a = modules.includes("auth_inventory");
  return v && a ? "both" : v ? "nuclei" : a ? "credentialed" : "none";
}

function browserTimezone(): string {
  try {
    return Intl.DateTimeFormat().resolvedOptions().timeZone || "UTC";
  } catch {
    return "UTC";
  }
}

function inHour(): string {
  const d = new Date(Date.now() + 3600_000);
  d.setMinutes(0, 0, 0);
  return toLocalInput(d);
}

/** Форма запуска прогона — сразу или по расписанию: цели, движок поиска уязвимостей
 * (Nuclei / учётная запись), прочие модули (cred_audit — только при праве), профиль
 * нагрузки, имя (по умолчанию — по выбранным опциям). С `schedule` — правка расписания. */
export function StartRunModal({
  engagement,
  onClose,
  onStarted,
  onScheduled,
  initialWhen = "now",
  schedule,
}: {
  engagement: EngagementOut;
  onClose: () => void;
  onStarted?: (run: RunCreated) => void;
  onScheduled?: (schedule: ScheduleOut) => void;
  initialWhen?: When;
  schedule?: ScheduleOut;
}) {
  const { has } = useAuth();
  const allowlist = useAsync(() => api.allowlist(engagement.id), [engagement.id]);
  const [when, setWhen] = useState<When>(schedule ? "schedule" : initialWhen);
  const [targets, setTargets] = useState(schedule ? schedule.targets.join("\n") : "");
  const [modules, setModules] = useState<string[]>(schedule ? schedule.modules.filter((m) => !ENGINE_MODULES.includes(m)) : ["discovery"]);
  const [engine, setEngine] = useState<EngineInfo["id"]>(schedule ? engineOf(schedule.modules) : "nuclei");
  const [credIds, setCredIds] = useState<number[]>(schedule?.credential_ids ?? []);
  const canCreds = has("host_credentials");
  const creds = useAsync(() => api.credentials(engagement.id), [engagement.id], canCreds);
  const [credSetIds, setCredSetIds] = useState<number[]>(schedule?.cred_set_ids ?? []);
  const canCredAudit = has("cred_audit");
  const credSets = useAsync(() => api.credSets(engagement.id), [engagement.id], canCredAudit);
  const [profile, setProfile] = useState(schedule?.rate_profile ?? "gentle");
  const [name, setName] = useState(schedule?.name ?? "");
  const [kind, setKind] = useState<ScheduleKind>(schedule?.kind ?? "daily");
  const [timeOfDay, setTimeOfDay] = useState(schedule?.time_of_day ?? "03:00");
  const [weekdays, setWeekdays] = useState<number[]>(schedule?.weekdays.length ? schedule.weekdays : [0]);
  const [monthDay, setMonthDay] = useState(schedule?.month_day ?? 1);
  const [runAt, setRunAt] = useState(schedule?.run_at ? toLocalInput(new Date(schedule.run_at)) : inHour());
  const timezone = schedule?.timezone ?? browserTimezone();
  const [confirmed, setConfirmed] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [denied, setDenied] = useState<DeniedTarget[]>([]);

  const available = MODULES.filter((m) => !ENGINE_MODULES.includes(m.id) && (!m.permission || has(m.permission as Perm)));
  const eng = VULN_ENGINES.find((x) => x.id === engine)!;
  const allModules = [...modules, ...eng.modules];
  const parsed = parseTargets(targets);
  const configAudit = modules.includes("config_audit");
  // Учётки нужны движку «по учётной записи» и модулям из CREDENTIAL_MODULES (аудит конфигураций).
  const needsCreds = eng.credentials || modules.some((m) => CREDENTIAL_MODULES.includes(m));
  const credsOk = !needsCreds || credIds.length > 0;
  const scheduled = when === "schedule";
  const whenOk =
    !scheduled ||
    (kind === "once" ? !!localToIso(runAt) : /^\d{2}:\d{2}$/.test(timeOfDay) && (kind !== "weekly" || weekdays.length > 0) && (kind !== "monthly" || (monthDay >= 1 && monthDay <= 31)));
  const canSubmit = parsed.targets.length > 0 && parsed.invalid.length === 0 && allModules.length > 0 && credsOk && whenOk && confirmed && !busy;
  const autoName = runTitle(allModules, parsed.targets);
  const toggleDay = (d: number) => setWeekdays((w) => (w.includes(d) ? w.filter((x) => x !== d) : [...w, d].sort()));

  const toggle = (id: string) => setModules((m) => (m.includes(id) ? m.filter((x) => x !== id) : [...m, id]));
  const toggleCred = (id: number) => setCredIds((c) => (c.includes(id) ? c.filter((x) => x !== id) : [...c, id]));
  const toggleCredSet = (id: number) => setCredSetIds((c) => (c.includes(id) ? c.filter((x) => x !== id) : [...c, id]));
  const credAuditOn = modules.includes("cred_audit");

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    if (!canSubmit) return;
    setBusy(true);
    setError(null);
    setDenied([]);
    try {
      const base = {
        targets: parsed.targets,
        modules: allModules,
        rate_profile: profile,
        credential_ids: needsCreds ? credIds : [],
        cred_set_ids: credAuditOn ? credSetIds : [],
        name: name.trim() || undefined,
      };
      if (scheduled) {
        const data: ScheduleIn = {
          ...base,
          kind,
          timezone,
          enabled: schedule?.enabled ?? true,
          ...(kind === "once" ? { run_at: localToIso(runAt) } : { time_of_day: timeOfDay }),
          ...(kind === "weekly" ? { weekdays } : {}),
          ...(kind === "monthly" ? { month_day: monthDay } : {}),
        };
        const saved = schedule ? await api.updateSchedule(schedule.id, data) : await api.createSchedule(engagement.id, data);
        onScheduled?.(saved);
      } else {
        onStarted?.(await api.startRun(engagement.id, base));
      }
    } catch (err) {
      const ex = err as ApiError;
      const d = ex.detail as { denied_targets?: DeniedTarget[] } | undefined;
      if (d && typeof d === "object" && Array.isArray(d.denied_targets)) setDenied(d.denied_targets);
      setError(ex.status === 422 && d?.denied_targets ? "Ни одна цель не входит в allowlist договора" : ex.message);
    } finally {
      setBusy(false);
    }
  };

  return (
    <Modal
      title={schedule ? "Изменить расписание" : scheduled ? "Новое расписание" : "Новый прогон"}
      onClose={onClose}
      footer={
        <>
          <button type="button" className="btn" onClick={onClose}>
            Отмена
          </button>
          <button type="submit" form="start-run" className="btn btn-primary" disabled={!canSubmit}>
            {busy ? "Сохранение…" : scheduled ? (schedule ? "Сохранить" : "Запланировать") : "Запустить"}
          </button>
        </>
      }
    >
      <form id="start-run" className="stack" style={{ gap: 18 }} onSubmit={submit}>
        <div className="muted" style={{ fontSize: 13 }}>
          Договор: <b style={{ color: "var(--text)" }}>{engagement.client ? `${engagement.client} · ${engagement.name}` : engagement.name}</b>
          {engagement.contract_ref ? ` · ${engagement.contract_ref}` : ""}
        </div>

        {!schedule && (
          <div className="inline" role="group" aria-label="Когда запускать">
            <button type="button" className="chip" aria-pressed={when === "now"} onClick={() => setWhen("now")}>
              Сейчас
            </button>
            <button type="button" className="chip" aria-pressed={when === "schedule"} onClick={() => setWhen("schedule")}>
              По расписанию
            </button>
          </div>
        )}

        {scheduled && (
          <fieldset className="field" style={{ border: 0, padding: 0, margin: 0 }}>
            <span>Расписание</span>
            <div className="inline" role="group" aria-label="Периодичность">
              {SCHEDULE_KINDS.map((k) => (
                <button key={k.id} type="button" className="chip" aria-pressed={kind === k.id} onClick={() => setKind(k.id)}>
                  {k.label}
                </button>
              ))}
            </div>
            {kind === "weekly" && (
              <div className="inline" role="group" aria-label="Дни недели">
                {WEEKDAYS.map((d, i) => (
                  <button key={d} type="button" className="chip" aria-pressed={weekdays.includes(i)} onClick={() => toggleDay(i)}>
                    {d}
                  </button>
                ))}
              </div>
            )}
            <div className="inline" style={{ gap: 12, flexWrap: "wrap" }}>
              {kind === "once" ? (
                <label className="field" style={{ minWidth: 220 }}>
                  <span>Дата и время</span>
                  <input className="input" type="datetime-local" value={runAt} onChange={(e) => setRunAt(e.target.value)} />
                </label>
              ) : (
                <>
                  {kind === "monthly" && (
                    <label className="field" style={{ width: 120 }}>
                      <span>Число месяца</span>
                      <input className="input" type="number" min={1} max={31} value={monthDay} onChange={(e) => setMonthDay(Number(e.target.value))} />
                    </label>
                  )}
                  <label className="field" style={{ width: 140 }}>
                    <span>Время</span>
                    <input className="input" type="time" value={timeOfDay} onChange={(e) => setTimeOfDay(e.target.value)} />
                  </label>
                </>
              )}
            </div>
            <small className="muted">
              Часовой пояс — {timezone}.{kind === "monthly" && monthDay > 28 ? " В коротких месяцах — в последний день месяца." : ""} Если предыдущий прогон
              этого расписания ещё идёт, очередной запуск пропускается.
            </small>
          </fieldset>
        )}

        <label className="field">
          <span>Цели (IP-адреса и подсети, по одной в строке)</span>
          <textarea
            className="textarea"
            value={targets}
            onChange={(e) => setTargets(e.target.value)}
            placeholder={"10.0.0.0/24\n10.0.1.15"}
            spellCheck={false}
          />
          <small>
            Цели вне allowlist будут отклонены, подсети урезаны до разрешённых диапазонов.
            {allowlist.data && allowlist.data.length > 0 && (
              <>
                {" "}
                <button
                  type="button"
                  className="btn btn-sm btn-ghost"
                  style={{ height: "auto", padding: 0, color: "var(--accent-text)" }}
                  onClick={() => setTargets(allowlist.data!.map((a) => a.cidr).join("\n"))}
                >
                  Подставить весь allowlist ({allowlist.data.length})
                </button>
              </>
            )}
          </small>
          {allowlist.data && allowlist.data.length === 0 && (
            <small style={{ color: "var(--warn)" }}>У договора пустой allowlist — запуск будет отклонён.</small>
          )}
          {parsed.invalid.length > 0 && (
            <small style={{ color: "var(--danger)" }}>
              Не IP/подсеть: {parsed.invalid.slice(0, 5).join(", ")}
              {parsed.invalid.length > 5 ? "…" : ""}. Имена хостов не принимаются.
            </small>
          )}
        </label>

        <fieldset className="field" style={{ border: 0, padding: 0, margin: 0 }}>
          <span>Поиск уязвимостей — движок</span>
          <div className="grid-2">
            {VULN_ENGINES.map((x) => {
              const locked = x.credentials && !canCreds;
              return (
                <label key={x.id} className="option-card" aria-disabled={locked || undefined} style={locked ? { opacity: 0.55 } : undefined}>
                  <input type="radio" name="engine" checked={engine === x.id} disabled={locked} onChange={() => setEngine(x.id)} />
                  <span>
                    <b style={{ fontWeight: 500 }}>{x.label}</b>
                    <small>{locked ? "Нужно право host_credentials" : x.description}</small>
                  </span>
                </label>
              );
            })}
          </div>
        </fieldset>

        <fieldset className="field" style={{ border: 0, padding: 0, margin: 0 }}>
          <span>Модули</span>
          <div className="grid-2">
            {available.map((m) => (
              <label key={m.id} className="option-card">
                <input type="checkbox" checked={modules.includes(m.id)} onChange={() => toggle(m.id)} />
                <span>
                  <b style={{ fontWeight: 500 }}>{m.label}</b>
                  <small>{m.description}</small>
                </span>
              </label>
            ))}
          </div>
          {credAuditOn && (
            <small style={{ color: "var(--warn)" }}>
              Аудит учётных данных выполняется только в рамках согласованного договора, с лимитом попыток и остановкой при блокировках.
            </small>
          )}
          {credAuditOn && (
            <div className="stack" style={{ gap: 8, marginTop: 4 }}>
              <span>Наборы проверки учёток</span>
              {credSets.loading && !credSets.data ? (
                <small className="muted">Загрузка наборов…</small>
              ) : credSets.error ? (
                <ErrorAlert error={credSets.error} onRetry={credSets.reload} />
              ) : (credSets.data ?? []).length === 0 ? (
                <small style={{ color: "var(--warn)" }}>
                  У договора нет наборов проверки учёток — добавьте их на странице договора в разделе «Наборы проверки учёток». Без набора модуль
                  запишет осознанный пропуск и не сделает ни одной попытки.
                </small>
              ) : (
                <div className="grid-2">
                  {credSets.data!.map((s) => (
                    <label key={s.id} className="option-card">
                      <input type="checkbox" checked={credSetIds.includes(s.id)} onChange={() => toggleCredSet(s.id)} />
                      <span>
                        <b style={{ fontWeight: 500 }}>{s.name}</b>
                        <small>
                          {s.entry_count} записей · {s.services.length ? s.services.join(", ") : "все поддерживаемые"}
                        </small>
                      </span>
                    </label>
                  ))}
                </div>
              )}
              <small className="muted">
                Проверка создаёт нагрузку входами на хосты и может приводить к блокировке учёток — запускайте только по согласованию. Пароли в
                журнал не пишутся.
              </small>
            </div>
          )}
        </fieldset>

        {needsCreds && (
          <fieldset className="field" style={{ border: 0, padding: 0, margin: 0 }}>
            <span>Учётные записи для входа на хосты</span>
            {creds.loading && !creds.data ? (
              <small className="muted">Загрузка учётных записей…</small>
            ) : creds.error ? (
              <ErrorAlert error={creds.error} onRetry={creds.reload} />
            ) : (creds.data ?? []).length === 0 ? (
              <small style={{ color: "var(--warn)" }}>
                У договора нет учётных записей — добавьте их на странице договора в разделе «Учётные записи активов».
              </small>
            ) : (
              <div className="grid-2">
                {creds.data!.map((c) => (
                  <label key={c.id} className="option-card">
                    <input type="checkbox" checked={credIds.includes(c.id)} onChange={() => toggleCred(c.id)} />
                    <span>
                      <b style={{ fontWeight: 500 }}>{c.name}</b>
                      <small>
                        {c.username} · {c.auth === "key" ? "ключ SSH" : "пароль"} · порт {c.port} · {c.become === "none" ? "без sudo" : "sudo"} ·{" "}
                        {c.targets.length ? c.targets.join(", ") : "все цели прогона"}
                      </small>
                    </span>
                  </label>
                ))}
              </div>
            )}
            {eng.credentials && (
              <small className="muted">
                Поиск уязвимостей по учётной записи: на хосте выполняется одна команда только на чтение (ОС и список пакетов), без sudo.
              </small>
            )}
            {configAudit && (
              <small className="muted">
                Аудиту конфигураций нужны права root: учётка с повышением прав sudo (пароль учётки подаётся sudo через stdin, для ключа нужен
                NOPASSWD) или вход под root. OpenSCAP и Lynis передаются во временный каталог и удаляются после проверки.
              </small>
            )}
            <small className="muted">На хост пробуется не больше трёх учёток — сначала с самой узкой областью действия.</small>
          </fieldset>
        )}

        <fieldset className="field" style={{ border: 0, padding: 0, margin: 0 }}>
          <span>Профиль нагрузки</span>
          <div className="grid-2" style={{ gridTemplateColumns: "repeat(auto-fit, minmax(160px, 1fr))" }}>
            {RATE_PROFILES.map((p) => (
              <label key={p.id} className="option-card">
                <input type="radio" name="profile" checked={profile === p.id} onChange={() => setProfile(p.id)} />
                <span>
                  <b style={{ fontWeight: 500 }}>{p.label}</b>
                  <small>{p.description}</small>
                </span>
              </label>
            ))}
          </div>
        </fieldset>

        <label className="field">
          <span>Название</span>
          <input className="input" value={name} maxLength={200} onChange={(e) => setName(e.target.value)} placeholder={autoName} />
          <small>Пусто — название по выбранным опциям: «{autoName}».</small>
        </label>

        <label className="check alert alert-info" style={{ color: "var(--text)" }}>
          <input type="checkbox" checked={confirmed} onChange={(e) => setConfirmed(e.target.checked)} />
          <span>
            <b>
              <ShieldCheck size={14} style={{ verticalAlign: -2, marginRight: 4 }} />
              Подтверждаю, что цели входят в объём работ по договору
            </b>
            <small>Есть письменное разрешение владельца систем; действие будет записано в журнал аудита.</small>
          </span>
        </label>

        {error && <ErrorAlert error={error} />}
        {denied.length > 0 && (
          <div className="table-wrap card">
            <table className="table">
              <thead>
                <tr>
                  <th>Отклонённая цель</th>
                  <th>Причина</th>
                  <th className="right">Адресов</th>
                </tr>
              </thead>
              <tbody>
                {denied.map((d) => (
                  <tr key={d.target}>
                    <td className="mono">{d.target}</td>
                    <td>{d.reason}</td>
                    <td className="right num">{d.count}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </form>
    </Modal>
  );
}
