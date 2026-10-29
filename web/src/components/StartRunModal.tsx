import { useState, type FormEvent } from "react";
import { ShieldCheck } from "lucide-react";
import { api, ApiError } from "../api/client";
import type { DeniedTarget, EngagementOut, RunCreated } from "../api/types";
import { useAuth, type Perm } from "../auth/AuthContext";
import { ENGINE_MODULES, MODULES, RATE_PROFILES, VULN_ENGINES, type EngineInfo } from "../lib/labels";
import { parseTargets } from "../lib/targets";
import { useAsync } from "../lib/useAsync";
import { ErrorAlert, Modal } from "./ui";

/** Форма запуска прогона: цели, движок поиска уязвимостей (Nuclei / учётная запись),
 * прочие модули (cred_audit — только при праве), профиль нагрузки. */
export function StartRunModal({
  engagement,
  onClose,
  onStarted,
}: {
  engagement: EngagementOut;
  onClose: () => void;
  onStarted: (run: RunCreated) => void;
}) {
  const { has } = useAuth();
  const allowlist = useAsync(() => api.allowlist(engagement.id), [engagement.id]);
  const [targets, setTargets] = useState("");
  const [modules, setModules] = useState<string[]>(["discovery"]);
  const [engine, setEngine] = useState<EngineInfo["id"]>("nuclei");
  const [credIds, setCredIds] = useState<number[]>([]);
  const canCreds = has("host_credentials");
  const creds = useAsync(() => api.credentials(engagement.id), [engagement.id], canCreds);
  const [profile, setProfile] = useState("gentle");
  const [confirmed, setConfirmed] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [denied, setDenied] = useState<DeniedTarget[]>([]);

  const available = MODULES.filter((m) => !ENGINE_MODULES.includes(m.id) && (!m.permission || has(m.permission as Perm)));
  const eng = VULN_ENGINES.find((x) => x.id === engine)!;
  const allModules = [...modules, ...eng.modules];
  const parsed = parseTargets(targets);
  const credsOk = !eng.credentials || credIds.length > 0;
  const canSubmit = parsed.targets.length > 0 && parsed.invalid.length === 0 && allModules.length > 0 && credsOk && confirmed && !busy;

  const toggle = (id: string) => setModules((m) => (m.includes(id) ? m.filter((x) => x !== id) : [...m, id]));
  const toggleCred = (id: number) => setCredIds((c) => (c.includes(id) ? c.filter((x) => x !== id) : [...c, id]));

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    if (!canSubmit) return;
    setBusy(true);
    setError(null);
    setDenied([]);
    try {
      const run = await api.startRun(engagement.id, {
        targets: parsed.targets,
        modules: allModules,
        rate_profile: profile,
        credential_ids: eng.credentials ? credIds : [],
      });
      onStarted(run);
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
      title="Новый прогон"
      onClose={onClose}
      footer={
        <>
          <button type="button" className="btn" onClick={onClose}>
            Отмена
          </button>
          <button type="submit" form="start-run" className="btn btn-primary" disabled={!canSubmit}>
            {busy ? "Запуск…" : "Запустить"}
          </button>
        </>
      }
    >
      <form id="start-run" className="stack" style={{ gap: 18 }} onSubmit={submit}>
        <div className="muted" style={{ fontSize: 13 }}>
          Договор: <b style={{ color: "var(--text)" }}>{engagement.client ? `${engagement.client} · ${engagement.name}` : engagement.name}</b>
          {engagement.contract_ref ? ` · ${engagement.contract_ref}` : ""}
        </div>

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
          {eng.credentials && (
            <div className="stack" style={{ gap: 8, marginTop: 4 }}>
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
                          {c.username} · {c.auth === "key" ? "ключ SSH" : "пароль"} · порт {c.port} ·{" "}
                          {c.targets.length ? c.targets.join(", ") : "все цели прогона"}
                        </small>
                      </span>
                    </label>
                  ))}
                </div>
              )}
              <small className="muted">
                На хосте выполняется одна команда только на чтение (ОС и список пакетов), без sudo. На хост пробуется не больше трёх учёток —
                сначала с самой узкой областью действия.
              </small>
            </div>
          )}
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
          {modules.includes("cred_audit") && (
            <small style={{ color: "var(--warn)" }}>
              Аудит учётных данных выполняется только в рамках согласованного договора, с лимитом попыток и остановкой при блокировках.
            </small>
          )}
        </fieldset>

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
