import { useState, type ChangeEvent, type FormEvent } from "react";
import { ListChecks, Plus, Trash2 } from "lucide-react";
import { api } from "../api/client";
import type { CredSetEntry, CredSetOut } from "../api/types";
import { fmtDate } from "../lib/format";
import { useAsync } from "../lib/useAsync";
import { Empty, ErrorAlert, Loading, Modal } from "./ui";

/** Разбор файла/текста набора: по строке «логин:секрет» (пустой пароль — «логин:»). */
function parseCredSet(text: string): { entries: CredSetEntry[]; invalid: number[] } {
  const entries: CredSetEntry[] = [];
  const invalid: number[] = [];
  text.split(/\r?\n/).forEach((raw, i) => {
    const line = raw.trimEnd();
    if (!line.trim() || line.trimStart().startsWith("#")) return;
    const idx = line.indexOf(":");
    if (idx < 0) {
      invalid.push(i + 1);
      return;
    }
    const username = line.slice(0, idx).trim();
    if (!username) {
      invalid.push(i + 1);
      return;
    }
    entries.push({ username, secret: line.slice(idx + 1) });
  });
  return { entries, invalid };
}

/** Наборы проверки учёток договора (аудит паролей по согласованию). Видно только с правом cred_audit. */
export function CredSetsCard({ engagementId }: { engagementId: number }) {
  const list = useAsync(() => api.credSets(engagementId), [engagementId]);
  const [adding, setAdding] = useState(false);
  const [removing, setRemoving] = useState<CredSetOut | null>(null);

  return (
    <section className="card" style={{ overflow: "hidden" }}>
      <div className="card-head">
        <h2>Наборы проверки учёток</h2>
        <button type="button" className="btn btn-sm" onClick={() => setAdding(true)}>
          <Plus size={15} /> Добавить
        </button>
      </div>
      <p className="muted" style={{ margin: "0 20px 14px", fontSize: 13 }}>
        Для модуля «Аудит учётных данных»: сканер проверяет указанные оператором пары логин/пароль на согласованных хостах — с лимитом
        попыток, паузами и остановкой при блокировке. Встроенных словарей нет. Пароли хранятся зашифрованными и никогда не показываются.
      </p>
      {list.loading && !list.data ? (
        <Loading />
      ) : list.error ? (
        <div style={{ padding: "0 20px 16px" }}>
          <ErrorAlert error={list.error} onRetry={list.reload} />
        </div>
      ) : list.data!.length === 0 ? (
        <Empty title="Наборов нет" icon={<ListChecks size={20} />}>
          Добавьте набор проверяемых учёток, чтобы запускать аудит паролей по согласованию с заказчиком.
        </Empty>
      ) : (
        <div className="table-wrap">
          <table className="table">
            <thead>
              <tr>
                <th>Название</th>
                <th>Записей</th>
                <th>Сервисы</th>
                <th>Логины (маскированы)</th>
                <th>Добавлен</th>
                <th />
              </tr>
            </thead>
            <tbody>
              {list.data!.map((s) => (
                <tr key={s.id}>
                  <td>{s.name}</td>
                  <td className="num">{s.entry_count}</td>
                  <td className="muted">{s.services.length ? s.services.join(", ") : "все поддерживаемые"}</td>
                  <td className="mono faint" style={{ fontSize: 12 }}>
                    {s.masked_usernames.join(", ")}
                    {s.masked_usernames.length < s.entry_count ? " …" : ""}
                  </td>
                  <td className="muted nowrap">{fmtDate(s.created_at)}</td>
                  <td className="right">
                    <button type="button" className="btn btn-sm btn-ghost" aria-label={`Удалить ${s.name}`} onClick={() => setRemoving(s)}>
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
        <CredSetForm
          engagementId={engagementId}
          onClose={() => setAdding(false)}
          onDone={async () => {
            setAdding(false);
            await list.reload();
          }}
        />
      )}
      {removing && (
        <RemoveCredSet
          engagementId={engagementId}
          credSet={removing}
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

const MAX_ENTRIES = 200;

function CredSetForm({ engagementId, onClose, onDone }: { engagementId: number; onClose: () => void; onDone: () => void }) {
  const [name, setName] = useState("");
  const [services, setServices] = useState("");
  const [text, setText] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const parsed = parseCredSet(text);
  const tooMany = parsed.entries.length > MAX_ENTRIES;
  const canSubmit = name.trim() && parsed.entries.length > 0 && parsed.invalid.length === 0 && !tooMany && !busy;
  const serviceList = services
    .split(/[\s,]+/)
    .map((s) => s.trim().toLowerCase())
    .filter(Boolean);

  const readFile = async (ev: ChangeEvent<HTMLInputElement>) => {
    const file = ev.target.files?.[0];
    if (file) setText(await file.text());
    ev.target.value = "";
  };

  const submit = async (ev: FormEvent) => {
    ev.preventDefault();
    if (!canSubmit) return;
    setBusy(true);
    setError(null);
    try {
      await api.createCredSet(engagementId, { name: name.trim(), services: serviceList, entries: parsed.entries });
      onDone();
    } catch (err) {
      setError((err as Error).message);
      setBusy(false);
    }
  };

  return (
    <Modal
      title="Новый набор проверки учёток"
      onClose={onClose}
      footer={
        <>
          <button type="button" className="btn" onClick={onClose}>
            Отмена
          </button>
          <button type="submit" form="cred-set-form" className="btn btn-primary" disabled={!canSubmit}>
            {busy ? "Сохранение…" : "Сохранить"}
          </button>
        </>
      }
    >
      <form id="cred-set-form" className="stack" style={{ gap: 16 }} onSubmit={submit} autoComplete="off">
        <label className="field">
          <span>Название</span>
          <input className="input" value={name} onChange={(e) => setName(e.target.value)} placeholder="Дефолтные и сервисные учётки" maxLength={128} />
        </label>
        <label className="field">
          <span>Сервисы (необязательно)</span>
          <input className="input mono" value={services} onChange={(e) => setServices(e.target.value)} placeholder="ssh, rdp" />
          <small>К каким сервисам применять набор. Пусто — все поддерживаемые. Бэкенд есть только для SSH; для прочих сервисов попыток не будет.</small>
        </label>
        <label className="field">
          <span>Учётки — по одной в строке, «логин:пароль»</span>
          <textarea
            className="textarea mono"
            value={text}
            onChange={(e) => setText(e.target.value)}
            placeholder={"root:toor\nadmin:\nservice:P@ssw0rd"}
            spellCheck={false}
            style={{ fontSize: 12, minHeight: 140 }}
          />
          <small>
            Первое двоеточие делит логин и пароль; «логин:» — пустой пароль. Строки с # — комментарии.{" "}
            <label className="btn btn-sm btn-ghost" style={{ height: "auto", padding: 0, color: "var(--accent-text)", cursor: "pointer" }}>
              Загрузить из файла
              <input type="file" hidden onChange={readFile} />
            </label>
          </small>
          {parsed.entries.length > 0 && !tooMany && parsed.invalid.length === 0 && (
            <small className="muted">Записей распознано: {parsed.entries.length}. Пароли не отображаются и не сохраняются в журнал.</small>
          )}
          {tooMany && <small style={{ color: "var(--danger)" }}>Слишком много записей ({parsed.entries.length}); лимит — {MAX_ENTRIES}.</small>}
          {parsed.invalid.length > 0 && (
            <small style={{ color: "var(--danger)" }}>Нет двоеточия в строках: {parsed.invalid.slice(0, 5).join(", ")}</small>
          )}
        </label>
        <small className="muted">
          Проверка выполняется только по согласованию с заказчиком и только по целям из allowlist. Каждая попытка пишется в журнал аудита —
          без пароля (только логин и необратимый отпечаток).
        </small>
        {error && <ErrorAlert error={error} />}
      </form>
    </Modal>
  );
}

function RemoveCredSet({
  engagementId,
  credSet,
  onClose,
  onDone,
}: {
  engagementId: number;
  credSet: CredSetOut;
  onClose: () => void;
  onDone: () => void;
}) {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const confirm = async () => {
    setBusy(true);
    try {
      await api.deleteCredSet(engagementId, credSet.id);
      onDone();
    } catch (err) {
      setError((err as Error).message);
      setBusy(false);
    }
  };
  return (
    <Modal
      title="Удалить набор проверки учёток?"
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
        Набор «{credSet.name}» ({credSet.entry_count} записей) будет удалён вместе с зашифрованными паролями. Прошедшие прогоны и их
        результаты сохранятся.
      </p>
      {error && <ErrorAlert error={error} />}
    </Modal>
  );
}
