import { useState, type FormEvent } from "react";
import { Pencil, UserPlus } from "lucide-react";
import { api } from "../api/client";
import type { UserOut } from "../api/types";
import { useAuth } from "../auth/AuthContext";
import { Empty, ErrorAlert, Loading, Modal } from "../components/ui";
import { ROLE_LABEL, ROLES } from "../lib/labels";
import { useAsync } from "../lib/useAsync";

const MIN_PASSWORD = 12;

function RolePicker({ value, onChange }: { value: string[]; onChange: (v: string[]) => void }) {
  const credWithoutOperator = value.includes("cred_audit") && !value.includes("operator");
  const hostCredsWithoutRole = value.includes("host_credentials") && !value.includes("operator") && !value.includes("admin");
  return (
    <fieldset className="field" style={{ border: 0, padding: 0, margin: 0 }}>
      <span>Роли</span>
      <div className="grid-2">
        {ROLES.map((r) => (
          <label key={r.id} className="option-card">
            <input
              type="checkbox"
              checked={value.includes(r.id)}
              onChange={() => onChange(value.includes(r.id) ? value.filter((x) => x !== r.id) : [...value, r.id])}
            />
            <span>
              <b style={{ fontWeight: 500 }}>{r.label}</b>
              <small>{r.description}</small>
            </span>
          </label>
        ))}
      </div>
      {credWithoutOperator && <small style={{ color: "var(--warn)" }}>Право cred_audit действует только вместе с ролью оператора.</small>}
      {hostCredsWithoutRole && (
        <small style={{ color: "var(--warn)" }}>
          Право host_credentials добавляется к роли: оператору — для запуска по учётке, администратору — чтобы заводить учётки.
        </small>
      )}
      {value.includes("admin") && value.includes("operator") && (
        <small style={{ color: "var(--warn)" }}>Совмещение администратора и оператора нарушает разделение обязанностей.</small>
      )}
    </fieldset>
  );
}

function CreateUser({ onClose, onDone }: { onClose: () => void; onDone: () => void }) {
  const [username, setUsername] = useState("");
  const [displayName, setDisplayName] = useState("");
  const [password, setPassword] = useState("");
  const [roles, setRoles] = useState<string[]>(["operator"]);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const valid = /^[A-Za-z0-9_.@-]+$/.test(username) && password.length >= MIN_PASSWORD;

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      await api.createUser({ username, password, display_name: displayName.trim() || null, roles });
      onDone();
    } catch (err) {
      setError((err as Error).message);
      setBusy(false);
    }
  };

  return (
    <Modal
      title="Новый пользователь"
      onClose={onClose}
      footer={
        <>
          <button type="button" className="btn" onClick={onClose}>
            Отмена
          </button>
          <button type="submit" form="create-user" className="btn btn-primary" disabled={!valid || busy}>
            Создать
          </button>
        </>
      }
    >
      <form id="create-user" className="stack" style={{ gap: 14 }} onSubmit={submit}>
        <div className="grid-2">
          <label className="field">
            <span>Логин</span>
            <input className="input" value={username} onChange={(e) => setUsername(e.target.value)} autoComplete="off" required />
            <small>Латиница, цифры и символы . _ @ -</small>
          </label>
          <label className="field">
            <span>Имя</span>
            <input className="input" value={displayName} onChange={(e) => setDisplayName(e.target.value)} />
          </label>
        </div>
        <label className="field">
          <span>Временный пароль</span>
          <input className="input" type="password" value={password} onChange={(e) => setPassword(e.target.value)} autoComplete="new-password" required />
          <small>Не короче {MIN_PASSWORD} символов. Передайте пользователю по защищённому каналу.</small>
        </label>
        <RolePicker value={roles} onChange={setRoles} />
        {error && <ErrorAlert error={error} />}
      </form>
    </Modal>
  );
}

function EditUser({ user, onClose, onDone, self }: { user: UserOut; onClose: () => void; onDone: () => void; self: boolean }) {
  const [displayName, setDisplayName] = useState(user.display_name ?? "");
  const [active, setActive] = useState(user.is_active);
  const [password, setPassword] = useState("");
  const [roles, setRoles] = useState<string[]>(user.roles);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [mfaOn, setMfaOn] = useState(!!user.mfa_enabled);
  const [confirmReset, setConfirmReset] = useState(false);
  const [sessionsNote, setSessionsNote] = useState<string | null>(null);
  const ldap = user.auth_source === "ldap";

  const endSessions = async () => {
    setBusy(true);
    setError(null);
    try {
      const { revoked } = await api.endUserSessions(user.id);
      setSessionsNote(revoked ? `Завершено сеансов: ${revoked}` : "Открытых сеансов не было");
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setBusy(false);
    }
  };

  const resetMfa = async () => {
    setBusy(true);
    setError(null);
    try {
      await api.resetUserMfa(user.id);
      setMfaOn(false);
      setConfirmReset(false);
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setBusy(false);
    }
  };

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      const patch: { display_name?: string | null; is_active?: boolean; password?: string } = {};
      if (displayName !== (user.display_name ?? "")) patch.display_name = displayName.trim() || null;
      if (active !== user.is_active) patch.is_active = active;
      if (password) patch.password = password;
      if (Object.keys(patch).length) await api.updateUser(user.id, patch);
      const sorted = (a: string[]) => [...a].sort().join(",");
      if (!ldap && sorted(roles) !== sorted(user.roles)) await api.setRoles(user.id, roles);
      onDone();
    } catch (err) {
      const msg = (err as Error).message;
      setError(msg.includes("last active admin") ? "Нельзя отключить или лишить роли последнего активного администратора." : msg);
      setBusy(false);
    }
  };

  return (
    <Modal
      title={`Пользователь ${user.username}`}
      onClose={onClose}
      footer={
        <>
          <button type="button" className="btn" onClick={onClose}>
            Отмена
          </button>
          <button type="submit" form="edit-user" className="btn btn-primary" disabled={busy || (!!password && password.length < MIN_PASSWORD)}>
            Сохранить
          </button>
        </>
      }
    >
      <form id="edit-user" className="stack" style={{ gap: 14 }} onSubmit={submit}>
        <label className="field">
          <span>Имя</span>
          <input className="input" value={displayName} onChange={(e) => setDisplayName(e.target.value)} />
        </label>
        {ldap ? (
          <div className="alert alert-info" role="note">
            Учётная запись домена (AD). Пароль меняется в домене, роли назначаются по группам AD при каждом входе. Здесь можно только отключить вход в «Сканер».
          </div>
        ) : (
          <label className="field">
            <span>Новый пароль</span>
            <input className="input" type="password" value={password} onChange={(e) => setPassword(e.target.value)} autoComplete="new-password" placeholder="Оставьте пустым, чтобы не менять" />
            {password && password.length < MIN_PASSWORD && <small style={{ color: "var(--danger)" }}>Не короче {MIN_PASSWORD} символов</small>}
          </label>
        )}
        <label className="check">
          <input type="checkbox" checked={active} onChange={(e) => setActive(e.target.checked)} disabled={self} />
          <span>
            <b>Учётная запись активна</b>
            <small>{self ? "Свою учётную запись отключить нельзя" : "Отключённый пользователь не сможет войти"}</small>
          </span>
        </label>
        {ldap ? (
          <div className="field">
            <span>Роли (из групп AD)</span>
            <RoleList roles={user.roles} />
          </div>
        ) : (
          <RolePicker value={roles} onChange={setRoles} />
        )}
        {!self && (
          <div className="field">
            <span>Сеансы входа</span>
            <div className="inline" style={{ gap: 8, flexWrap: "wrap" }}>
              <button type="button" className="btn btn-sm" onClick={() => void endSessions()} disabled={busy}>
                Завершить все сеансы
              </button>
              {sessionsNote && <span className="muted" style={{ fontSize: 13 }}>{sessionsNote}</span>}
            </div>
            <small className="faint">Пользователь выйдет на всех устройствах. Отключение учётной записи, новый пароль и сброс 2FA закрывают сеансы сами.</small>
          </div>
        )}
        {mfaOn && (
          <div className="field">
            <span>Двухфакторный вход</span>
            <div className="inline" style={{ gap: 8, flexWrap: "wrap" }}>
              <span className="pill pill-ok">Включён</span>
              {confirmReset ? (
                <>
                  <button type="button" className="btn btn-sm btn-danger" onClick={() => void resetMfa()} disabled={busy}>
                    Да, сбросить
                  </button>
                  <button type="button" className="btn btn-sm" onClick={() => setConfirmReset(false)}>
                    Отмена
                  </button>
                </>
              ) : (
                <button type="button" className="btn btn-sm" onClick={() => setConfirmReset(true)}>
                  Сбросить 2FA
                </button>
              )}
            </div>
            <small>Если пользователь потерял телефон и коды восстановления. При следующем входе он настроит 2FA заново (или войдёт без неё, если 2FA необязательна).</small>
          </div>
        )}
        {error && <ErrorAlert error={error} />}
      </form>
    </Modal>
  );
}

function RoleList({ roles }: { roles: string[] }) {
  return (
    <span className="inline" style={{ gap: 6, flexWrap: "wrap" }}>
      {roles.length ? (
        roles.map((r) => (
          <span key={r} className={`pill ${r === "admin" ? "pill-warn" : r === "cred_audit" || r === "host_credentials" ? "pill-danger" : "pill-info"}`}>
            {ROLE_LABEL[r] ?? r}
          </span>
        ))
      ) : (
        <span className="faint">нет</span>
      )}
    </span>
  );
}

export function UsersPage() {
  const { me } = useAuth();
  const users = useAsync(() => api.users(), []);
  const [creating, setCreating] = useState(false);
  const [editing, setEditing] = useState<UserOut | null>(null);

  return (
    <>
      <div className="page-head">
        <div>
          <span className="crumbs">Администрирование</span>
          <h1>Пользователи и роли</h1>
        </div>
        <div className="actions">
          <button type="button" className="btn btn-primary" onClick={() => setCreating(true)}>
            <UserPlus size={16} /> Новый пользователь
          </button>
        </div>
      </div>
      {users.error && <ErrorAlert error={users.error} onRetry={users.reload} />}
      <section className="card" style={{ overflow: "hidden" }}>
        {users.loading && !users.data ? (
          <Loading />
        ) : !users.data?.length ? (
          <Empty title="Пользователей нет" />
        ) : (
          <div className="table-wrap">
            <table className="table" style={{ minWidth: 760 }}>
              <thead>
                <tr>
                  <th>Логин</th>
                  <th>Имя</th>
                  <th>Роли</th>
                  <th>Вход</th>
                  <th>Статус</th>
                  <th />
                </tr>
              </thead>
              <tbody>
                {users.data.map((u) => (
                  <tr key={u.id}>
                    <td className="mono">{u.username}</td>
                    <td>{u.display_name ?? "—"}</td>
                    <td>
                      <RoleList roles={u.roles} />
                    </td>
                    <td>
                      <span className="inline" style={{ gap: 6 }}>
                        <span className={`pill ${u.auth_source === "ldap" ? "pill-info" : "pill-muted"}`}>{u.auth_source === "ldap" ? "Домен" : "Локальный"}</span>
                        {u.mfa_enabled && <span className="pill pill-ok" title="Двухфакторный вход включён">2FA</span>}
                      </span>
                    </td>
                    <td>{u.is_active ? <span className="pill pill-ok">Активен</span> : <span className="pill pill-muted">Отключён</span>}</td>
                    <td className="right">
                      <button type="button" className="btn btn-sm" onClick={() => setEditing(u)} aria-label={`Изменить ${u.username}`}>
                        <Pencil size={14} /> Изменить
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>
      {creating && (
        <CreateUser
          onClose={() => setCreating(false)}
          onDone={() => {
            setCreating(false);
            void users.reload();
          }}
        />
      )}
      {editing && (
        <EditUser
          user={editing}
          self={editing.id === me?.id}
          onClose={() => setEditing(null)}
          onDone={() => {
            setEditing(null);
            void users.reload();
          }}
        />
      )}
    </>
  );
}
