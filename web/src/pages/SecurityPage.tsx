import { useState, type FormEvent } from "react";
import { KeyRound, ShieldCheck, ShieldOff } from "lucide-react";
import { api } from "../api/client";
import type { MfaSetupOut } from "../api/types";
import { useAuth } from "../auth/AuthContext";
import { CodeField, MfaSetupBox, RecoveryCodesBox } from "../components/Mfa";
import { SessionsCard } from "../components/SessionsCard";
import { codeLooksValid } from "../lib/mfa";
import { ErrorAlert, Loading } from "../components/ui";
import { useAsync } from "../lib/useAsync";

type Action = "setup" | "recovery" | "disable" | null;

/** Профиль: способ входа, своя двухфакторная аутентификация и сеансы входа. */
export function SecurityPage() {
  const { me } = useAuth();
  const status = useAsync(() => api.myMfa(), []);
  const [action, setAction] = useState<Action>(null);
  const [setup, setSetup] = useState<MfaSetupOut | null>(null);
  const [code, setCode] = useState("");
  const [codes, setCodes] = useState<string[] | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const s = status.data;
  const ldap = me?.auth_source === "ldap";

  const reset = () => {
    setAction(null);
    setSetup(null);
    setCode("");
    setError(null);
  };

  const start = async (a: Action) => {
    reset();
    setCodes(null);
    setAction(a);
    if (a !== "setup") return;
    setBusy(true);
    try {
      setSetup(await api.myMfaSetup());
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  };

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      const c = code.trim();
      if (action === "setup") setCodes((await api.myMfaConfirm(c)).recovery_codes);
      else if (action === "recovery") setCodes((await api.myMfaRecoveryCodes(c)).recovery_codes);
      else if (action === "disable") await api.myMfaDisable(c);
      reset();
      await status.reload();
    } catch (err) {
      const m = (err as Error).message;
      setError(m === "invalid code" ? "Неверный код. Проверьте время на телефоне и введите новый код." : m);
    } finally {
      setBusy(false);
    }
  };

  return (
    <>
      <div className="page-head">
        <div>
          <span className="crumbs">Профиль</span>
          <h1>Безопасность входа</h1>
        </div>
      </div>
      <section className="card stack" style={{ gap: 13, maxWidth: 720 }}>
        <h2 style={{ margin: 0, fontSize: 16 }}>Учётная запись</h2>
        <div className="inline" style={{ gap: 8 }}>
          <span className="mono">{me?.username}</span>
          <span className={`pill ${ldap ? "pill-info" : "pill-muted"}`}>{ldap ? "Домен (AD)" : "Локальная"}</span>
        </div>
        <span className="muted" style={{ fontSize: 13 }}>
          {ldap
            ? "Вы входите учётной записью домена: пароль меняется в домене, роли назначаются по группам AD при каждом входе."
            : "Пароль меняет администратор «Сканера» в разделе «Пользователи и роли»."}
        </span>
      </section>
      <section className="card stack" style={{ gap: 13, maxWidth: 720, marginTop: 21 }}>
        <h2 style={{ margin: 0, fontSize: 16 }}>Двухфакторный вход</h2>
        {status.error && <ErrorAlert error={status.error} onRetry={status.reload} />}
        {!s ? (
          !status.error && <Loading />
        ) : s.mode === "off" ? (
          <span className="muted">Двухфакторный вход на этом сервере выключен. Его включает администратор стенда (SCANNER_API_MFA).</span>
        ) : (
          <>
            <div className="inline" style={{ gap: 8 }}>
              {s.enabled ? <span className="pill pill-ok">Включён</span> : <span className="pill pill-muted">Не настроен</span>}
              {s.required && <span className="pill pill-warn">Обязателен на этом сервере</span>}
            </div>
            <span className="muted" style={{ fontSize: 13 }}>
              {s.enabled
                ? `При входе после пароля нужен код из приложения на телефоне. Осталось кодов восстановления: ${s.recovery_codes_left}.`
                : "После пароля «Сканер» будет спрашивать 6-значный код из приложения на телефоне. Украденного пароля станет недостаточно для входа."}
            </span>
            {codes && <RecoveryCodesBox codes={codes} username={me?.username ?? "user"} />}
            {action === null && (
              <div className="inline" style={{ gap: 8, flexWrap: "wrap" }}>
                {!s.enabled && (
                  <button type="button" className="btn btn-primary" onClick={() => void start("setup")}>
                    <ShieldCheck size={16} /> Включить
                  </button>
                )}
                {s.enabled && (
                  <button type="button" className="btn" onClick={() => void start("recovery")}>
                    <KeyRound size={16} /> Новые коды восстановления
                  </button>
                )}
                {s.enabled && !s.required && (
                  <button type="button" className="btn" onClick={() => void start("disable")}>
                    <ShieldOff size={16} /> Отключить
                  </button>
                )}
              </div>
            )}
            {action && (
              <form className="stack" style={{ gap: 13 }} onSubmit={submit} aria-label="Подтверждение кодом">
                {action === "setup" && setup && <MfaSetupBox setup={setup} />}
                {action === "recovery" && <span className="muted">Старые коды восстановления перестанут действовать.</span>}
                {(action !== "setup" || setup) && (
                  <CodeField value={code} onChange={setCode} allowRecovery={action === "disable"} autoFocus={action !== "setup"} />
                )}
                {error && <ErrorAlert error={error} />}
                <div className="inline" style={{ gap: 8 }}>
                  <button type="submit" className="btn btn-primary" disabled={busy || !codeLooksValid(code, action === "disable")}>
                    {action === "setup" ? "Подтвердить и включить" : action === "recovery" ? "Получить новые коды" : "Отключить 2FA"}
                  </button>
                  <button type="button" className="btn" onClick={reset}>
                    Отмена
                  </button>
                </div>
              </form>
            )}
          </>
        )}
      </section>
      <SessionsCard />
    </>
  );
}
