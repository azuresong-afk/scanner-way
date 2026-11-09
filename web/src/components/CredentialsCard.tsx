import { useState, type ChangeEvent, type FormEvent } from "react";
import { KeyRound, Pencil, Plus, Trash2 } from "lucide-react";
import { api } from "../api/client";
import type { CredentialAuth, CredentialBecome, CredentialOut, CredentialProtocol, DbProtocol, NetdevPlatform } from "../api/types";
import { fmtDate } from "../lib/format";
import { DB_PROTOCOLS, PROTOCOL_LABEL, isDbProtocol } from "../lib/labels";
import { parseTargets } from "../lib/targets";
import { useAsync } from "../lib/useAsync";
import { Empty, ErrorAlert, Loading, Modal } from "./ui";

const DEFAULT_PORT: Record<CredentialProtocol, string> = {
  ssh: "22",
  winrm: "5986",
  netssh: "22",
  snmp: "161",
  ...(Object.fromEntries(DB_PROTOCOLS.map((d) => [d.id, d.port])) as Record<DbProtocol, string>),
};

const PLATFORMS: { id: NetdevPlatform; label: string }[] = [
  { id: "auto", label: "Определить автоматически" },
  { id: "cisco_ios", label: "Cisco IOS" },
  { id: "cisco_xe", label: "Cisco IOS XE" },
  { id: "cisco_nxos", label: "Cisco NX-OS" },
  { id: "cisco_asa", label: "Cisco ASA" },
  { id: "junos", label: "Juniper Junos" },
  { id: "routeros", label: "MikroTik RouterOS" },
  { id: "huawei_vrp", label: "Huawei VRP" },
  { id: "eltex_esr", label: "Eltex ESR" },
  { id: "eltex_mes", label: "Eltex MES" },
];
const PLATFORM_LABEL = Object.fromEntries(PLATFORMS.map((p) => [p.id, p.label]));
const SNMP_AUTH = ["sha", "sha256", "sha512", "sha224", "sha384", "md5"];
const SNMP_PRIV = [
  { id: "aes", label: "AES-128" },
  { id: "aes256", label: "AES-256" },
  { id: "aes192", label: "AES-192" },
  { id: "aes256c", label: "AES-256 (Cisco)" },
  { id: "aes192c", label: "AES-192 (Cisco)" },
  { id: "des", label: "DES (устаревший)" },
  { id: "none", label: "Без шифрования" },
];

const KEEP_HINT = "•••••• сохранён — оставьте пустым, чтобы не менять";

/** Подпись способа входа в таблице учёток. */
function loginLabel(c: CredentialOut): string {
  const o = c.options ?? {};
  if (c.protocol === "winrm") return "WinRM · пароль";
  if (isDbProtocol(c.protocol)) return `${PROTOCOL_LABEL[c.protocol]}${c.db_name ? ` · ${c.db_name}` : ""}`;
  if (c.protocol === "snmp") return o.snmp_version === "2c" ? "SNMP v2c · community" : `SNMPv3 · ${(o.auth_proto ?? "sha").toUpperCase()}/${(o.priv_proto ?? "aes").toUpperCase()}`;
  if (c.protocol === "netssh") {
    const p = o.platform && o.platform !== "auto" ? PLATFORM_LABEL[o.platform] ?? o.platform : "сетевое устройство";
    return `SSH · ${p}`;
  }
  return c.auth === "key" ? "SSH · ключ" : "SSH · пароль";
}

/** Учётные записи активов договора: серверы (SSH, WinRM), сетевое оборудование (SSH, SNMP) и СУБД. */
export function CredentialsCard({ engagementId }: { engagementId: number }) {
  const list = useAsync(() => api.credentials(engagementId), [engagementId]);
  const [adding, setAdding] = useState(false);
  const [editing, setEditing] = useState<CredentialOut | null>(null);
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
        Для движка «По учётной записи»: Linux по SSH (пакеты → БДУ ФСТЭК и CVE), Windows по WinRM (обновления и ПО → KB/CVE и БДУ), сетевое
        оборудование по SSH или SNMP (версия ОС устройства → CVE/БДУ, аудит конфигурации) и СУБД (учётка СУБД только на чтение: версия →
        CVE/БДУ, конфигурация по CIS), а также для аудита конфигураций серверов (CIS, ФСТЭК/ГОСТ — нужен sudo). Пароли, ключи и community
        хранятся зашифрованными и никогда не показываются.
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
                    {loginLabel(c)}
                    {c.key_fingerprint && (
                      <div className="mono faint" style={{ fontSize: 11 }} title={c.key_fingerprint}>
                        {c.key_fingerprint.slice(0, 22)}…
                      </div>
                    )}
                  </td>
                  <td className="muted">{c.protocol === "ssh" && c.become !== "none" ? "sudo" : "нет"}</td>
                  <td className="mono muted">{c.targets.length ? c.targets.join(", ") : "все цели прогона"}</td>
                  <td className="muted nowrap">{fmtDate(c.created_at)}</td>
                  <td className="right nowrap">
                    <button type="button" className="btn btn-sm btn-ghost" aria-label={`Изменить ${c.name}`} title="Изменить" onClick={() => setEditing(c)}>
                      <Pencil size={14} />
                    </button>
                    <button type="button" className="btn btn-sm btn-ghost" aria-label={`Удалить ${c.name}`} title="Удалить" onClick={() => setRemoving(c)}>
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
      {editing && (
        <CredentialForm
          engagementId={engagementId}
          initial={editing}
          onClose={() => setEditing(null)}
          onDone={async () => {
            setEditing(null);
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

/** Логин WinRM хранится как ДОМЕН\user — в форме правки домен отдельным полем. */
function splitDomain(c: CredentialOut | undefined): [string, string] {
  if (!c) return ["", ""];
  const i = c.username.indexOf("\\");
  return c.protocol === "winrm" && i > 0 ? [c.username.slice(i + 1), c.username.slice(0, i)] : [c.username, ""];
}

/**
 * Форма учётки: новая или правка существующей (initial). При правке секреты не
 * показываются и не обязательны — пустое поле оставляет сохранённый пароль, ключ
 * или парольную фразу. Сменили способ входа — секрет нужно ввести заново.
 */
function CredentialForm({
  engagementId,
  initial,
  onClose,
  onDone,
}: {
  engagementId: number;
  initial?: CredentialOut;
  onClose: () => void;
  onDone: () => void;
}) {
  const o = initial?.options ?? {};
  const [initUser, initDomain] = splitDomain(initial);
  const [name, setName] = useState(initial?.name ?? "");
  const [protocol, setProtocol] = useState<CredentialProtocol>(initial?.protocol ?? "ssh");
  const [username, setUsername] = useState(initUser);
  const [domain, setDomain] = useState(initDomain);
  const [port, setPort] = useState(initial ? String(initial.port) : DEFAULT_PORT.ssh);
  const [portTouched, setPortTouched] = useState(!!initial && initial.port !== Number(DEFAULT_PORT[initial.protocol ?? "ssh"]));
  const [auth, setAuth] = useState<CredentialAuth>(initial?.auth ?? "password");
  const [password, setPassword] = useState("");
  const [key, setKey] = useState("");
  const [passphrase, setPassphrase] = useState("");
  const [scope, setScope] = useState(initial?.targets.join("\n") ?? "");
  const [become, setBecome] = useState<CredentialBecome>(initial ? (initial.become === "none" ? "none" : "sudo") : "sudo");
  const [dbName, setDbName] = useState(initial?.db_name ?? "");
  const [platform, setPlatform] = useState<NetdevPlatform>((o.platform as NetdevPlatform) ?? "auto");
  const [snmpVersion, setSnmpVersion] = useState<"2c" | "3">(o.snmp_version === "2c" ? "2c" : "3");
  const [authProto, setAuthProto] = useState(o.auth_proto ?? "sha");
  const [privProto, setPrivProto] = useState(o.priv_proto ?? "aes");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const isWinrm = protocol === "winrm";
  const isDb = isDbProtocol(protocol);
  const dbInfo = DB_PROTOCOLS.find((d) => d.id === protocol);
  const isNetssh = protocol === "netssh";
  const isSnmp = protocol === "snmp";
  const isV2c = isSnmp && snmpVersion === "2c";
  const needPriv = isSnmp && !isV2c && privProto !== "none";
  // WinRM (NTLM) и СУБД входят только по паролю, SNMP — community или ключами USM.
  const effectiveAuth: CredentialAuth = isWinrm || isSnmp || isDb ? "password" : auth;
  // Правка без смены способа входа: сохранённый секрет остаётся, вводить не обязательно.
  const keepSecret =
    !!initial && initial.protocol === protocol && initial.auth === effectiveAuth && (!isSnmp || (o.snmp_version ?? "3") === snmpVersion);

  const switchProtocol = (p: CredentialProtocol) => {
    setProtocol(p);
    if (!portTouched) setPort(DEFAULT_PORT[p]);   // порт по умолчанию, пока его не трогали
    setDbName(DB_PROTOCOLS.find((d) => d.id === p)?.dbName ?? "");
  };

  const parsed = parseTargets(scope);
  const portNum = Number(port);
  const portOk = Number.isInteger(portNum) && portNum > 0 && portNum < 65536;
  const secretOk =
    effectiveAuth === "password"
      ? (keepSecret ? true : password.length > 0) &&
        (!isSnmp || isV2c || password.length === 0 || password.length >= 8) &&
        (!needPriv || (keepSecret && passphrase.length === 0) || passphrase.length >= 8)
      : keepSecret || key.trim().length > 0;
  const userOk = isV2c || username.trim().length > 0;
  const dbOk = protocol !== "oracle" || dbName.trim().length > 0;   // Oracle: имя сервиса обязательно
  const canSubmit = name.trim() && userOk && portOk && secretOk && dbOk && parsed.invalid.length === 0 && !busy;

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
      const data = {
        name: name.trim(),
        username: isV2c ? "community" : username.trim(),
        port: portNum,
        auth: effectiveAuth,
        protocol,
        ...(isWinrm && domain.trim() ? { domain: domain.trim() } : {}),
        ...(isDb && dbName.trim() ? { db_name: dbName.trim() } : {}),
        ...(isNetssh ? { platform } : {}),
        ...(isSnmp
          ? { snmp_version: snmpVersion, ...(isV2c ? {} : { snmp_auth_proto: authProto, snmp_priv_proto: privProto }) }
          : {}),
        // Пустые секреты при правке не отправляются — сервер оставит сохранённые.
        ...(effectiveAuth === "password"
          ? { ...(password ? { password } : {}), ...(needPriv && passphrase ? { passphrase } : {}) }
          : { ...(key.trim() ? { private_key: key } : {}), ...(passphrase ? { passphrase } : {}) }),
        targets: parsed.targets,
        // sudo — только для SSH-аудита конфигураций серверов; WinRM, сетевые устройства и СУБД права не повышают.
        become: protocol === "ssh" ? become : "none",
      } as const;
      if (initial) await api.updateCredential(engagementId, initial.id, data);
      else await api.createCredential(engagementId, data);
      onDone();
    } catch (err) {
      setError((err as Error).message);
      setBusy(false);
    }
  };

  const userLabel = isWinrm ? "Логин Windows" : isNetssh ? "Логин на устройстве" : isSnmp ? "Пользователь SNMPv3" : isDb ? "Логин СУБД" : "Логин на хосте";
  const portLabel = isWinrm ? "Порт WinRM" : isSnmp ? "Порт SNMP (UDP)" : isDb ? "Порт СУБД" : "Порт SSH";
  const passwordLabel = isWinrm ? "Пароль Windows" : isV2c ? "Community" : isSnmp ? "Ключ аутентификации (auth)" : isDb ? "Пароль СУБД" : "Пароль";

  return (
    <Modal
      title={initial ? `Изменить учётную запись «${initial.name}»` : "Новая учётная запись актива"}
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
        {initial && (
          <small className="muted">
            {keepSecret
              ? "Пароль, ключ и community не показываются. Оставьте поле секрета пустым — сохранится прежний; введите новый, чтобы заменить."
              : "Способ входа изменён — введите пароль или ключ заново."}
          </small>
        )}
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
              <input type="radio" name="protocol" checked={isNetssh} onChange={() => switchProtocol("netssh")} />
              <span>
                <b style={{ fontWeight: 500 }}>Сетевое устройство</b>
                <small>Коммутатор, маршрутизатор по SSH: версия и конфигурация</small>
              </span>
            </label>
            <label className="option-card">
              <input type="radio" name="protocol" checked={isSnmp} onChange={() => switchProtocol("snmp")} />
              <span>
                <b style={{ fontWeight: 500 }}>SNMP</b>
                <small>Коммутатор, маршрутизатор: только версия ОС (v3 или v2c)</small>
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
        {isSnmp && (
          <fieldset className="field" style={{ border: 0, padding: 0, margin: 0 }}>
            <span>Версия SNMP</span>
            <div className="grid-2">
              <label className="option-card">
                <input type="radio" name="snmp-version" checked={!isV2c} onChange={() => setSnmpVersion("3")} />
                <span>
                  <b style={{ fontWeight: 500 }}>SNMPv3</b>
                  <small>Логин и ключи, с шифрованием — рекомендуется</small>
                </span>
              </label>
              <label className="option-card">
                <input type="radio" name="snmp-version" checked={isV2c} onChange={() => setSnmpVersion("2c")} />
                <span>
                  <b style={{ fontWeight: 500 }}>SNMPv2c</b>
                  <small>Community открытым текстом — сканер отметит это как нарушение</small>
                </span>
              </label>
            </div>
          </fieldset>
        )}
        <div className="inline" style={{ alignItems: "flex-end" }}>
          {!isV2c && (
            <label className="field" style={{ flex: "3 1 200px" }}>
              <span>{userLabel}</span>
              <input
                className="input mono"
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                placeholder={isWinrm ? "svc_scan" : isSnmp ? "nms" : isDb ? "scan_ro" : "audit"}
                maxLength={128}
              />
            </label>
          )}
          <label className="field" style={{ flex: "1 1 90px" }}>
            <span>{portLabel}</span>
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
        {isNetssh && (
          <label className="field">
            <span>Платформа устройства</span>
            <select className="input" value={platform} onChange={(e) => setPlatform(e.target.value as NetdevPlatform)}>
              {PLATFORMS.map((p) => (
                <option key={p.id} value={p.id}>
                  {p.label}
                </option>
              ))}
            </select>
            <small>Автоматически — по приглашению CLI и выводу show version / display version. Укажите явно, если устройство не распознаётся.</small>
          </label>
        )}
        {(protocol === "ssh" || isNetssh) && (
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
        {isSnmp && !isV2c && (
          <div className="inline" style={{ alignItems: "flex-end" }}>
            <label className="field" style={{ flex: "1 1 140px" }}>
              <span>Аутентификация</span>
              <select className="input" value={authProto} onChange={(e) => setAuthProto(e.target.value)}>
                {SNMP_AUTH.map((a) => (
                  <option key={a} value={a}>
                    {a.toUpperCase()}
                  </option>
                ))}
              </select>
            </label>
            <label className="field" style={{ flex: "1 1 140px" }}>
              <span>Шифрование</span>
              <select className="input" value={privProto} onChange={(e) => setPrivProto(e.target.value)}>
                {SNMP_PRIV.map((p) => (
                  <option key={p.id} value={p.id}>
                    {p.label}
                  </option>
                ))}
              </select>
            </label>
          </div>
        )}
        {effectiveAuth === "password" ? (
          <>
            <label className="field">
              <span>{passwordLabel}</span>
              <input
                className="input"
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                autoComplete="new-password"
                placeholder={keepSecret ? KEEP_HINT : undefined}
              />
              {isSnmp && !isV2c && <small>Не короче 8 символов.</small>}
            </label>
            {needPriv && (
              <label className="field">
                <span>Ключ шифрования (priv)</span>
                <input
                  className="input"
                  type="password"
                  value={passphrase}
                  onChange={(e) => setPassphrase(e.target.value)}
                  autoComplete="new-password"
                  placeholder={keepSecret ? KEEP_HINT : undefined}
                />
                <small>Не короче 8 символов.</small>
              </label>
            )}
          </>
        ) : (
          <>
            <label className="field">
              <span>Закрытый ключ (OpenSSH или PEM)</span>
              <textarea
                className="textarea mono"
                value={key}
                onChange={(e) => setKey(e.target.value)}
                placeholder={keepSecret ? `${KEEP_HINT}${initial?.key_fingerprint ? ` (${initial.key_fingerprint})` : ""}` : "-----BEGIN OPENSSH PRIVATE KEY-----"}
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
              <input
                className="input"
                type="password"
                value={passphrase}
                onChange={(e) => setPassphrase(e.target.value)}
                autoComplete="new-password"
                placeholder={keepSecret ? KEEP_HINT : undefined}
              />
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
          {isNetssh || isSnmp
            ? "На устройстве выполняются только команды просмотра версии и конфигурации (show / display / export): без enable, конфигурационного режима и сохранения. Учётке достаточно уровня «только чтение». Секреты из конфигурации в отчёт не попадают — маскируются."
            : "Поиску уязвимостей по учётной записи хватает обычных прав: команды только на чтение, без sudo. Аудиту конфигураций нужны права root — через sudo."}{" "}
          Вход и его результат пишутся в журнал аудита — без пароля, ключа и community.
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
