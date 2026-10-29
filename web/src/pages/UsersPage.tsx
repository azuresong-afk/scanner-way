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
      if (sorted(roles) !== sorted(user.roles)) await api.setRoles(user.id, roles);
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
        <label className="field">
          <span>Новый пароль</span>
          <input className="input" type="password" value={password} onChange={(e) => setPassword(e.target.value)} autoComplete="new-password" placeholder="Оставьте пустым, чтобы не менять" />
          {password && password.length < MIN_PASSWORD && <small style={{ color: "var(--danger)" }}>Не короче {MIN_PASSWORD} символов</small>}
        </label>
        <label className="check">
          <input type="checkbox" checked={active} onChange={(e) => setActive(e.target.checked)} disabled={self} />
          <span>
            <b>Учётная запись активна</b>
            <small>{self ? "Свою учётную запись отключить нельзя" : "Отключённый пользователь не сможет войти"}</small>
          </span>
        </label>
        <RolePicker value={roles} onChange={setRoles} />
        {error && <ErrorAlert error={error} />}
      </form>
    </Modal>
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
            <table className="table" style={{ minWidth: 640 }}>
              <thead>
                <tr>
                  <th>Логин</th>
                  <th>Имя</th>
                  <th>Роли</th>
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
                      <span className="inline" style={{ gap: 6 }}>
                        {u.roles.length ? (
                          u.roles.map((r) => (
                            <span key={r} className={`pill ${r === "admin" ? "pill-warn" : r === "cred_audit" || r === "host_credentials" ? "pill-danger" : "pill-info"}`}>
                              {ROLE_LABEL[r] ?? r}
                            </span>
                          ))
                        ) : (
                          <span className="faint">нет</span>
                        )}
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
