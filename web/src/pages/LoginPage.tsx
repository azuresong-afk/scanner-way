import { useState, type FormEvent } from "react";
import { Navigate, useLocation } from "react-router-dom";
import { FileCheck2, KeyRound, Lock, Radar, ScrollText, ShieldCheck } from "lucide-react";
import { api, ApiError } from "../api/client";
import type { MfaSetupOut } from "../api/types";
import { useAuth } from "../auth/AuthContext";
import { CodeField, MfaSetupBox, RecoveryCodesBox } from "../components/Mfa";
import { codeLooksValid } from "../lib/mfa";
import { ErrorAlert } from "../components/ui";

type Step = "password" | "code" | "enroll" | "recovery";

function loginError(ex: ApiError, step: Step): string {
  if (ex.status === 429) return "Слишком много неудачных попыток. Повторите позже.";
  if (step === "password") {
    if (ex.status === 401) return "Неверное имя пользователя или пароль";
    if (ex.status === 503) return "Каталог пользователей (AD) недоступен. Повторите позже или войдите локальной учётной записью.";
  } else if (ex.status === 400) {
    return "Неверный код. Проверьте время на телефоне и введите новый код.";
  }
  return ex.message;
}

export function LoginPage() {
  const { me, login, acceptToken, config } = useAuth();
  const location = useLocation();
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [step, setStep] = useState<Step>("password");
  const [mfaToken, setMfaToken] = useState("");
  const [setup, setSetup] = useState<MfaSetupOut | null>(null);
  const [code, setCode] = useState("");
  const [recovery, setRecovery] = useState<{ token: string; codes: string[] } | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  if (me) {
    const from = (location.state as { from?: string } | null)?.from ?? "/";
    return <Navigate to={from} replace />;
  }

  const restart = (msg: string | null) => {
    setStep("password");
    setPassword("");
    setCode("");
    setMfaToken("");
    setSetup(null);
    setError(msg);
  };

  const run = async (fn: () => Promise<void>) => {
    setBusy(true);
    setError(null);
    try {
      await fn();
    } catch (err) {
      const ex = err as ApiError;
      if (step !== "password" && ex.status === 401) restart("Время на ввод кода истекло. Введите пароль ещё раз.");
      else setError(loginError(ex, step));
    } finally {
      setBusy(false);
    }
  };

  const submit = (e: FormEvent) => {
    e.preventDefault();
    void run(async () => {
      if (step === "password") {
        const t = await login(username.trim(), password);
        if (!t.mfa_required || !t.mfa_token) return;
        setMfaToken(t.mfa_token);
        setCode("");
        if (t.mfa_enroll) {
          setSetup(await api.mfaEnrollStart(t.mfa_token));
          setStep("enroll");
        } else {
          setStep("code");
        }
      } else if (step === "code") {
        const t = await api.mfaVerify(mfaToken, code.trim());
        if (t.access_token) await acceptToken(t.access_token);
      } else if (step === "enroll") {
        const t = await api.mfaEnrollConfirm(mfaToken, code.trim());
        if (t.access_token) setRecovery({ token: t.access_token, codes: t.recovery_codes ?? [] });
        setStep("recovery");
      } else if (recovery) {
        await acceptToken(recovery.token);
      }
    });
  };

  const title =
    step === "password" ? "Вход" : step === "code" ? "Подтверждение входа" : step === "enroll" ? "Настройка двухфакторного входа" : "Коды восстановления";
  const subtitle =
    step === "password"
      ? config.ldap
        ? "Войдите учётной записью домена или выданной администратором."
        : "Используйте учётную запись, выданную администратором."
      : step === "code"
        ? "Введите код из приложения-аутентификатора на телефоне."
        : step === "enroll"
          ? "На этом сервере вход защищён вторым фактором. Настройте его один раз."
          : "Двухфакторный вход включён.";
  const canSubmit =
    step === "password"
      ? !!username && !!password
      : step === "recovery"
        ? true
        : codeLooksValid(code, step === "code");

  return (
    <div className="login">
      <section className="login-art">
        <div className="brand" style={{ padding: 0 }}>
          <div className="brand-mark" aria-hidden="true">
            <Radar size={18} />
          </div>
          <span className="brand-name" style={{ color: "#e6eaf0" }}>
            Scanner
          </span>
        </div>
        <div className="stack" style={{ gap: 18 }}>
          <h1>Аудит защищённости инфраструктуры по договору</h1>
          <p>Инвентаризация, поиск уязвимостей с привязкой к БДУ ФСТЭК и CVE, аудит конфигураций и отчёты о динамике устранения.</p>
          <ul>
            <li>
              <ShieldCheck size={18} aria-hidden="true" /> Сканирование только целей из allowlist договора
            </li>
            <li>
              <FileCheck2 size={18} aria-hidden="true" /> Сопоставление находок с БДУ ФСТЭК
            </li>
            <li>
              <ScrollText size={18} aria-hidden="true" /> Все действия записываются в журнал аудита
            </li>
          </ul>
        </div>
        <span style={{ color: "#7d8794", fontSize: 12 }}>Использование против систем без письменного разрешения владельца недопустимо.</span>
      </section>
      <section className="login-form">
        <form onSubmit={submit} aria-label="Вход в систему">
          <div className="stack" style={{ gap: 6 }}>
            <h1>{title}</h1>
            <span className="muted">{subtitle}</span>
          </div>
          {step === "password" && (
            <>
              <label className="field">
                <span>Имя пользователя</span>
                <input className="input" autoComplete="username" value={username} onChange={(e) => setUsername(e.target.value)} required autoFocus />
              </label>
              <label className="field">
                <span>Пароль</span>
                <input
                  className="input"
                  type="password"
                  autoComplete="current-password"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  required
                />
              </label>
            </>
          )}
          {step === "code" && <CodeField value={code} onChange={setCode} allowRecovery />}
          {step === "enroll" && setup && (
            <>
              <MfaSetupBox setup={setup} />
              <CodeField value={code} onChange={setCode} autoFocus={false} />
            </>
          )}
          {step === "recovery" && recovery && <RecoveryCodesBox codes={recovery.codes} username={username.trim()} />}
          {error && <ErrorAlert error={error} />}
          <button type="submit" className="btn btn-primary" style={{ height: 42 }} disabled={busy || !canSubmit}>
            {step === "password" ? <Lock size={16} aria-hidden="true" /> : <KeyRound size={16} aria-hidden="true" />}
            {busy ? "Проверка…" : step === "password" ? "Войти" : step === "recovery" ? "Я сохранил коды, продолжить" : "Подтвердить"}
          </button>
          {(step === "code" || step === "enroll") && (
            <button type="button" className="btn btn-ghost" onClick={() => restart(null)}>
              Войти под другим именем
            </button>
          )}
        </form>
      </section>
    </div>
  );
}
