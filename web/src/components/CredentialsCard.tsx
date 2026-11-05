import { useState, type ChangeEvent, type FormEvent } from "react";
import { KeyRound, Plus, Trash2 } from "lucide-react";
import { api } from "../api/client";
import type { CredentialAuth, CredentialBecome, CredentialOut, CredentialProtocol, DbProtocol } from "../api/types";
import { fmtDate } from "../lib/format";
import { DB_PROTOCOLS, PROTOCOL_LABEL, isDbProtocol } from "../lib/labels";

const DEFAULT_PORT: Record<CredentialProtocol, string> = {
  ssh: "22",
  winrm: "5986",
  ...(Object.fromEntries(DB_PROTOCOLS.map((d) => [d.id, d.port])) as Record<DbProtocol, string>),
};
import { parseTargets } from "../lib/targets";
import { useAsync } from "../lib/useAsync";
import { Empty, ErrorAlert, Loading, Modal } from "./ui";

/** Учётные записи активов договора: поиск уязвимостей по учётной записи и аудит конфигураций (SSH). */
export function CredentialsCard({ engagementId }: { engagementId: number }) {
  const list = useAsync(() => api.credentials(engagementId), [engagementId]);
  const [adding, setAdding] = useState(false);
  const [removing, setRemoving] = useState<CredentialOut | null>(null);

  return (
    <section className="card" style={{ overflow: "hidden" }}>
      <div className="card-head">
        <h2>Учётные записи активов</h2>
        <button type="button" className="btn btn-sm" onClick={() => setAdding(true)}>
          <Plus size={15} /> Добавить
        </button>
      </div>
      <p className="muted" style={{ margin: "0 20px 14px", fontSize: 13 }}>
        Для движка «По учётной записи»: Linux по SSH (пакеты → БДУ ФСТЭК и CVE) и Windows по WinRM (обновления и ПО → KB/CVE и БДУ), для
        аудита конфигураций (CIS, ФСТЭК/ГОСТ — нужен sudo) и для аудита СУБД (учётка СУБД только на чтение). Пароли и ключи хранятся
        зашифрованными и никогда не показываются.
      </p>
      {list.loading && !list.data ? (
        <Loading />
      ) : list.error ? (
        <div style={{ padding: "0 20px 16px" }}>
          <ErrorAlert error={list.error} onRetry={list.reload} />
        </div>
      ) : list.data!.length === 0 ? (
        <Empty title="Учётных записей нет" icon={<KeyRound size={20} />}>
          Добавьте учётку, чтобы искать уязвимости по пакетам и проверять конфигурации хостов.
        </Empty>
      ) : (
        <div className="table-wrap">
          <table className="table">
            <thead>
              <tr>
                <th>Название</th>
                <th>Логин</th>
                <th>Вход</th>
                <th>Повышение прав</th>
                <th>Область действия</th>
                <th>Добавлена</th>
                <th />
              </tr>
            </thead>
            <tbody>
              {list.data!.map((c) => (
                <tr key={c.id}>
                  <td>{c.name}</td>
                  <td className="mono">
                    {c.username}
                    {c.port !== Number(DEFAULT_PORT[c.protocol ?? "ssh"]) ? `:${c.port}` : ""}
                  </td>
                  <td className="muted">
                    {c.protocol === "winrm"
                      ? "WinRM · пароль"
                      : isDbProtocol(c.protocol)
                        ? `${PROTOCOL_LABEL[c.protocol]}${c.db_name ? ` · ${c.db_name}` : ""}`
                        : c.auth === "key"
                          ? "SSH · ключ"
                          : "SSH · пароль"}
                    {c.key_fingerprint && (
                      <div className="mono faint" style={{ fontSize: 11 }} title={c.key_fingerprint}>
                        {c.key_fingerprint.slice(0, 22)}…
                      </div>
                    )}
                  </td>
                  <td className="muted">{c.protocol !== "ssh" ? "—" : c.become === "none" ? "нет" : "sudo"}</td>
                  <td className="mono muted">{c.targets.length ? c.targets.join(", ") : "все цели прогона"}</td>
                  <td className="muted nowrap">{fmtDate(c.created_at)}</td>
                  <td className="right">
                    <button type="button" className="btn btn-sm btn-ghost" aria-label={`Удалить ${c.name}`} onClick={() => setRemoving(c)}>
                      <Trash2 size={14} />
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      {adding && (
        <CredentialForm
          engagementId={engagementId}
          onClose={() => setAdding(false)}
          onDone={async () => {
            setAdding(false);
            await list.reload();
          }}
        />
      )}
      {removing && (
        <RemoveCredential
          engagementId={engagementId}
          credential={removing}
          onClose={() => setRemoving(null)}
          onDone={async () => {
            setRemoving(null);
            await list.reload();
          }}
        />
      )}
    </section>
  );
}

function CredentialForm({ engagementId, onClose, onDone }: { engagementId: number; onClose: () => void; onDone: () => void }) {
  const [name, setName] = useState("");
  const [protocol, setProtocol] = useState<CredentialProtocol>("ssh");
  const [username, setUsername] = useState("");
  const [domain, setDomain] = useState("");
  const [port, setPort] = useState(DEFAULT_PORT.ssh);
  const [portTouched, setPortTouched] = useState(false);
  const [auth, setAuth] = useState<CredentialAuth>("password");
  const [password, setPassword] = useState("");
  const [key, setKey] = useState("");
  const [passphrase, setPassphrase] = useState("");
  const [scope, setScope] = useState("");
  const [become, setBecome] = useState<CredentialBecome>("sudo");
  const [dbName, setDbName] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const isWinrm = protocol === "winrm";
  const isDb = isDbProtocol(protocol);
  const dbInfo = DB_PROTOCOLS.find((d) => d.id === protocol);
  // WinRM и СУБД входят только по паролю; при переключении на них возвращаем пароль.
  const effectiveAuth: CredentialAuth = isWinrm || isDb ? "password" : auth;

  const switchProtocol = (p: CredentialProtocol) => {
    setProtocol(p);
    if (!portTouched) setPort(DEFAULT_PORT[p]);   // порт по умолчанию, пока его не трогали
    setDbName(DB_PROTOCOLS.find((d) => d.id === p)?.dbName ?? "");
  };

  const parsed = parseTargets(scope);
  const portNum = Number(port);
  const portOk = Number.isInteger(portNum) && portNum > 0 && portNum < 65536;
  const secretOk = effectiveAuth === "password" ? password.length > 0 : key.trim().length > 0;
  const dbOk = protocol !== "oracle" || dbName.trim().length > 0;   // Oracle: имя сервиса обязательно
  const canSubmit = name.trim() && username.trim() && portOk && secretOk && dbOk && parsed.invalid.length === 0 && !busy;

  const readKey = async (ev: ChangeEvent<HTMLInputElement>) => {
    const file = ev.target.files?.[0];
    if (file) setKey(await file.text());
    ev.target.value = "";
  };

  const submit = async (ev: FormEvent) => {
    ev.preventDefault();
    if (!canSubmit) return;
    setBusy(true);
    setError(null);
    try {
      await api.createCredential(engagementId, {
        name: name.trim(),
        username: username.trim(),
        port: portNum,
        auth: effectiveAuth,
        protocol,
        ...(isWinrm && domain.trim() ? { domain: domain.trim() } : {}),
        ...(isDb && dbName.trim() ? { db_name: dbName.trim() } : {}),
        ...(effectiveAuth === "password" ? { password } : { private_key: key, passphrase: passphrase || undefined }),
        targets: parsed.targets,
        // WinRM и СУБД не повышают права — sudo только для SSH-аудита конфигураций.
        become: protocol === "ssh" ? become : "none",
      });
      onDone();
    } catch (err) {
      setError((err as Error).message);
      setBusy(false);
    }
  };

  return (
    <Modal
      title="Новая учётная запись актива"
      onClose={onClose}
      footer={
        <>
          <button type="button" className="btn" onClick={onClose}>
            Отмена
          </button>
          <button type="submit" form="credential-form" className="btn btn-primary" disabled={!canSubmit}>
            {busy ? "Сохранение…" : "Сохранить"}
          </button>
        </>
      }
    >
      <form id="credential-form" className="stack" style={{ gap: 16 }} onSubmit={submit} autoComplete="off">
        <label className="field">
          <span>Название</span>
          <input className="input" value={name} onChange={(e) => setName(e.target.value)} placeholder="Сервисная учётка серверов ДМЗ" maxLength={128} />
        </label>
        <fieldset className="field" style={{ border: 0, padding: 0, margin: 0 }}>
          <span>Способ входа</span>
          <div className="grid-3">
            <label className="option-card">
              <input type="radio" name="protocol" checked={protocol === "ssh"} onChange={() => switchProtocol("ssh")} />
              <span>
                <b style={{ fontWeight: 500 }}>SSH</b>
                <small>Linux: пакеты, аудит конфигураций</small>
              </span>
            </label>
            <label className="option-card">
              <input type="radio" name="protocol" checked={isWinrm} onChange={() => switchProtocol("winrm")} />
              <span>
                <b style={{ fontWeight: 500 }}>WinRM</b>
                <small>Windows: обновления и ПO (HTTPS, NTLM)</small>
              </span>
            </label>
            <label className="option-card">
              <input type="radio" name="protocol" checked={isDb} onChange={() => switchProtocol(isDb ? protocol : "postgresql")} />
              <span>
                <b style={{ fontWeight: 500 }}>СУБД</b>
                <small>Аудит баз данных: версия → CVE/БДУ, конфигурация по CIS</small>
              </span>
            </label>
          </div>
        </fieldset>
        {isDb && (
          <label className="field">
            <span>СУБД</span>
            <select className="input" value={protocol} onChange={(e) => switchProtocol(e.target.value as CredentialProtocol)}>
              {DB_PROTOCOLS.map((d) => (
                <option key={d.id} value={d.id}>
                  {d.label} ({d.hint})
                </option>
              ))}
            </select>
          </label>
        )}
        <div className="inline" style={{ alignItems: "flex-end" }}>
          <label className="field" style={{ flex: "3 1 200px" }}>
            <span>{isWinrm ? "Логин Windows" : isDb ? "Логин СУБД" : "Логин на хосте"}</span>
            <input
              className="input mono"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              placeholder={isWinrm ? "svc_scan" : isDb ? "scan_ro" : "audit"}
              maxLength={128}
            />
          </label>
          <label className="field" style={{ flex: "1 1 90px" }}>
            <span>{isWinrm ? "Порт WinRM" : isDb ? "Порт СУБД" : "Порт SSH"}</span>
            <input
              className="input mono"
              value={port}
              onChange={(e) => {
                setPortTouched(true);
                setPort(e.target.value);
              }}
              inputMode="numeric"
            />
          </label>
        </div>
        {isWinrm && (
          <label className="field">
            <span>Домен Windows (необязательно)</span>
            <input className="input mono" value={domain} onChange={(e) => setDomain(e.target.value)} placeholder="CORP" maxLength={64} />
            <small>Логин будет сохранён как ДОМЕН\user. Пусто — локальная учётная запись хоста.</small>
          </label>
        )}
        {isDb && dbInfo && (
          <label className="field">
            <span>{dbInfo.dbLabel}</span>
            <input className="input mono" value={dbName} onChange={(e) => setDbName(e.target.value)} placeholder={protocol === "oracle" ? "ORCLPDB1" : dbInfo.dbName} maxLength={128} />
            <small>
              Учётке СУБД нужны только права на чтение системных представлений — список прав для каждой СУБД в руководстве администратора.
            </small>
          </label>
        )}
        {protocol === "ssh" && (
          <fieldset className="field" style={{ border: 0, padding: 0, margin: 0 }}>
            <span>Аутентификация</span>
            <div className="grid-2">
              <label className="option-card">
                <input type="radio" name="auth" checked={auth === "password"} onChange={() => setAuth("password")} />
                <span>
                  <b style={{ fontWeight: 500 }}>Пароль</b>
                </span>
              </label>
              <label className="option-card">
                <input type="radio" name="auth" checked={auth === "key"} onChange={() => setAuth("key")} />
                <span>
                  <b style={{ fontWeight: 500 }}>Ключ SSH</b>
                  <small>Ed25519, ECDSA или RSA</small>
                </span>
              </label>
            </div>
          </fieldset>
        )}
        {effectiveAuth === "password" ? (
          <label className="field">
            <span>{isWinrm ? "Пароль Windows" : isDb ? "Пароль СУБД" : "Пароль"}</span>
            <input className="input" type="password" value={password} onChange={(e) => setPassword(e.target.value)} autoComplete="new-password" />
          </label>
        ) : (
          <>
            <label className="field">
              <span>Закрытый ключ (OpenSSH или PEM)</span>
              <textarea
                className="textarea mono"
                value={key}
                onChange={(e) => setKey(e.target.value)}
                placeholder="-----BEGIN OPENSSH PRIVATE KEY-----"
                spellCheck={false}
                style={{ fontSize: 12 }}
              />
              <small>
                <label className="btn btn-sm btn-ghost" style={{ height: "auto", padding: 0, color: "var(--accent-text)", cursor: "pointer" }}>
                  Загрузить из файла
                  <input type="file" hidden onChange={readKey} />
                </label>
              </small>
            </label>
            <label className="field">
              <span>Парольная фраза ключа (если есть)</span>
              <input className="input" type="password" value={passphrase} onChange={(e) => setPassphrase(e.target.value)} autoComplete="new-password" />
            </label>
          </>
        )}
        {protocol === "ssh" && (
        <fieldset className="field" style={{ border: 0, padding: 0, margin: 0 }}>
          <span>Повышение прав (для аудита конфигураций)</span>
          <div className="grid-2">
            <label className="option-card">
              <input type="radio" name="become" checked={become === "sudo"} onChange={() => setBecome("sudo")} />
              <span>
                <b style={{ fontWeight: 500 }}>sudo</b>
                <small>{auth === "password" ? "Пароль учётки подаётся sudo скрыто, через stdin" : "Для ключа нужен NOPASSWD в sudoers"}</small>
              </span>
            </label>
            <label className="option-card">
              <input type="radio" name="become" checked={become === "none"} onChange={() => setBecome("none")} />
              <span>
                <b style={{ fontWeight: 500 }}>Нет</b>
                <small>Вход сразу под root или проверка без root (часть правил не проверится)</small>
              </span>
            </label>
          </div>
        </fieldset>
        )}
        <label className="field">
          <span>Область действия (необязательно)</span>
          <textarea className="textarea mono" value={scope} onChange={(e) => setScope(e.target.value)} placeholder={"10.0.0.0/24\n10.0.1.15"} spellCheck={false} />
          <small>IP и подсети из allowlist проекта, к которым подходит учётка. Пусто — все цели прогона.</small>
          {parsed.invalid.length > 0 && <small style={{ color: "var(--danger)" }}>Не IP/подсеть: {parsed.invalid.slice(0, 5).join(", ")}</small>}
        </label>
        <small className="muted">
          Поиску уязвимостей по учётной записи хватает обычных прав: команды только на чтение, без sudo. Аудиту конфигураций нужны права root —
          через sudo. Вход, sudo и их результат пишутся в журнал аудита — без пароля и ключа.
        </small>
        {error && <ErrorAlert error={error} />}
      </form>
    </Modal>
  );
}

function RemoveCredential({
  engagementId,
  credential,
  onClose,
  onDone,
}: {
  engagementId: number;
  credential: CredentialOut;
  onClose: () => void;
  onDone: () => void;
}) {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const confirm = async () => {
    setBusy(true);
    try {
      await api.deleteCredential(engagementId, credential.id);
      onDone();
    } catch (err) {
      setError((err as Error).message);
      setBusy(false);
    }
  };
  return (
    <Modal
      title="Удалить учётную запись?"
      onClose={onClose}
      footer={
        <>
          <button type="button" className="btn" onClick={onClose}>
            Отмена
          </button>
          <button type="button" className="btn btn-danger" disabled={busy} onClick={confirm}>
            Удалить
          </button>
        </>
      }
    >
      <p style={{ margin: 0 }}>
        Учётка «{credential.name}» ({credential.username}) будет удалена вместе с паролем или ключом. Прошедшие прогоны и их результаты сохранятся.
      </p>
      {error && <ErrorAlert error={error} />}
    </Modal>
  );
}
