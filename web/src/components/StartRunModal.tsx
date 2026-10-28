import { useState, type FormEvent } from "react";
import { ShieldCheck } from "lucide-react";
import { api, ApiError } from "../api/client";
import type { DeniedTarget, EngagementOut, RunCreated } from "../api/types";
import { useAuth } from "../auth/AuthContext";
import { MODULES, RATE_PROFILES } from "../lib/labels";
import { parseTargets } from "../lib/targets";
import { useAsync } from "../lib/useAsync";
import { ErrorAlert, Modal } from "./ui";

/** Форма запуска прогона: цели, модули (cred_audit — только при праве), профиль нагрузки. */
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
  const [modules, setModules] = useState<string[]>(["discovery", "vuln"]);
  const [profile, setProfile] = useState("gentle");
  const [confirmed, setConfirmed] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [denied, setDenied] = useState<DeniedTarget[]>([]);

  const available = MODULES.filter((m) => !m.permission || has(m.permission as "cred_audit"));
  const parsed = parseTargets(targets);
  const canSubmit = parsed.targets.length > 0 && parsed.invalid.length === 0 && modules.length > 0 && confirmed && !busy;

  const toggle = (id: string) => setModules((m) => (m.includes(id) ? m.filter((x) => x !== id) : [...m, id]));

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    if (!canSubmit) return;
    setBusy(true);
    setError(null);
    setDenied([]);
    try {
      const run = await api.startRun(engagement.id, { targets: parsed.targets, modules, rate_profile: profile });
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
