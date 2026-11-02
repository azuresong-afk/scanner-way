// Учётные атрибуты хоста (бывшая вкладка «Активы», R7): критичность, владелец,
// теги, группы. Используются на вкладке «Хосты» и на странице хоста.
import { useMemo, useState, type FormEvent } from "react";
import { Plus, Tag } from "lucide-react";
import type { AssetGroupOut, AssetIn, AssetOut, Criticality } from "../api/types";
import { ErrorAlert, Modal } from "./ui";
import { CRITICALITIES, CRITICALITY_LABEL } from "../lib/labels";

/** Мягкая метка критичности — те же цвета, что у опасности находок. */
export function CriticalityBadge({ value, implicit }: { value: Criticality; implicit?: boolean }) {
  return (
    <span className={`sev sev-${value}${implicit ? " sev-implicit" : ""}`} title={implicit ? "По умолчанию: хосту критичность не назначена" : undefined}>
      <i aria-hidden="true" />
      {CRITICALITY_LABEL[value]}
    </span>
  );
}

const splitTags = (s: string) => s.split(/[,;\n]/).map((t) => t.trim()).filter(Boolean);

export type BulkPatch = { add_tags?: string[]; remove_tags?: string[]; add_group_ids?: number[]; remove_group_ids?: number[]; criticality?: Criticality; owner?: string };

export function GroupsBar({
  groups,
  active,
  onPick,
  canWrite,
  onCreate,
  onRename,
  onDelete,
}: {
  groups: AssetGroupOut[];
  active: number | null;
  onPick: (id: number) => void;
  canWrite: boolean;
  onCreate: (name: string) => Promise<unknown>;
  onRename: (g: AssetGroupOut, name: string) => Promise<unknown>;
  onDelete: (g: AssetGroupOut) => Promise<unknown>;
}) {
  const [name, setName] = useState("");
  const activeGroup = groups.find((g) => g.id === active) ?? null;
  const [renaming, setRenaming] = useState("");
  return (
    <div className="inline os-filter" role="group" aria-label="Группы хостов">
      <span className="faint chip-row-label">Группы</span>
      {groups.map((g) => (
        <button key={g.id} type="button" className="chip" aria-pressed={g.id === active} onClick={() => { onPick(g.id); setRenaming(g.name); }}>
          {g.name} <span className="faint">{g.asset_count}</span>
        </button>
      ))}
      {canWrite && (
        <form
          className="inline"
          style={{ gap: 6 }}
          onSubmit={(e: FormEvent) => {
            e.preventDefault();
            if (name.trim()) void onCreate(name.trim()).then(() => setName(""));
          }}
        >
          <input className="input" style={{ width: 170, height: 30 }} placeholder="Новая группа" aria-label="Название новой группы" value={name} onChange={(e) => setName(e.target.value)} maxLength={128} />
          <button type="submit" className="btn btn-sm" disabled={!name.trim()}>
            <Plus size={14} /> Создать
          </button>
        </form>
      )}
      {canWrite && activeGroup && (
        <span className="inline" style={{ gap: 6 }}>
          <input className="input" style={{ width: 150, height: 30 }} aria-label="Новое имя группы" value={renaming} onChange={(e) => setRenaming(e.target.value)} maxLength={128} />
          <button type="button" className="btn btn-sm" disabled={!renaming.trim() || renaming.trim() === activeGroup.name} onClick={() => onRename(activeGroup, renaming.trim())}>
            Переименовать
          </button>
          <button type="button" className="btn btn-sm btn-danger" onClick={() => onDelete(activeGroup)}>
            Удалить группу
          </button>
        </span>
      )}
    </div>
  );
}

export function BulkBar({
  count,
  groups,
  busy,
  onApply,
  onClear,
}: {
  count: number;
  groups: AssetGroupOut[];
  busy: boolean;
  onApply: (patch: BulkPatch) => void;
  onClear: () => void;
}) {
  const [addTags, setAddTags] = useState("");
  const [removeTags, setRemoveTags] = useState("");
  const [addGroup, setAddGroup] = useState("");
  const [removeGroup, setRemoveGroup] = useState("");
  const [crit, setCrit] = useState<Criticality | "">("");
  const [owner, setOwner] = useState("");
  const patch = useMemo(() => {
    const p: Parameters<typeof onApply>[0] = {};
    if (splitTags(addTags).length) p.add_tags = splitTags(addTags);
    if (splitTags(removeTags).length) p.remove_tags = splitTags(removeTags);
    if (addGroup) p.add_group_ids = [Number(addGroup)];
    if (removeGroup) p.remove_group_ids = [Number(removeGroup)];
    if (crit) p.criticality = crit;
    if (owner.trim()) p.owner = owner.trim();
    return p;
  }, [addTags, removeTags, addGroup, removeGroup, crit, owner]);
  const groupOptions = groups.map((g) => (
    <option key={g.id} value={g.id}>
      {g.name}
    </option>
  ));
  return (
    <div className="inline" role="group" aria-label="Массовые действия" style={{ gap: 8, flexWrap: "wrap", padding: "10px 20px", borderBottom: "1px solid var(--border)" }}>
      <b>Выбрано: {count}</b>
      <input className="input" style={{ width: 150 }} placeholder="+ теги через запятую" aria-label="Добавить теги" value={addTags} onChange={(e) => setAddTags(e.target.value)} />
      <input className="input" style={{ width: 150 }} placeholder="− теги" aria-label="Снять теги" value={removeTags} onChange={(e) => setRemoveTags(e.target.value)} />
      <select className="select" aria-label="Добавить в группу" value={addGroup} onChange={(e) => setAddGroup(e.target.value)}>
        <option value="">+ в группу…</option>
        {groupOptions}
      </select>
      <select className="select" aria-label="Убрать из группы" value={removeGroup} onChange={(e) => setRemoveGroup(e.target.value)}>
        <option value="">− из группы…</option>
        {groupOptions}
      </select>
      <select className="select" aria-label="Задать критичность" value={crit} onChange={(e) => setCrit(e.target.value as Criticality | "")}>
        <option value="">Критичность…</option>
        {CRITICALITIES.map((c) => (
          <option key={c} value={c}>
            {CRITICALITY_LABEL[c]}
          </option>
        ))}
      </select>
      <input className="input" style={{ width: 150 }} placeholder="Владелец" aria-label="Задать владельца" value={owner} onChange={(e) => setOwner(e.target.value)} />
      <button type="button" className="btn btn-primary btn-sm" disabled={busy || Object.keys(patch).length === 0} onClick={() => onApply(patch)}>
        <Tag size={14} /> Применить
      </button>
      <button type="button" className="btn btn-sm btn-ghost" onClick={onClear}>
        Снять выбор
      </button>
    </div>
  );
}

export function AssetModal({
  asset,
  presetAddress,
  groups,
  onClose,
  onSave,
}: {
  asset: AssetOut | null;
  /** Адрес найденного прогонами хоста, у которого ещё нет учётной записи. */
  presetAddress?: string;
  groups: AssetGroupOut[];
  onClose: () => void;
  onSave: (data: AssetIn) => Promise<void>;
}) {
  const [address, setAddress] = useState(asset?.address ?? presetAddress ?? "");
  const [hostname, setHostname] = useState(asset?.hostname ?? "");
  const [owner, setOwner] = useState(asset?.owner ?? "");
  const [crit, setCrit] = useState<Criticality>(asset?.criticality ?? "medium");
  const [tags, setTags] = useState((asset?.tags ?? []).join(", "));
  const [notes, setNotes] = useState(asset?.notes ?? "");
  const [groupIds, setGroupIds] = useState<number[]>(asset?.groups.map((g) => g.id) ?? []);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<Error | null>(null);

  async function submit(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      await onSave({ address: address.trim(), hostname, owner, criticality: crit, notes, tags: splitTags(tags), group_ids: groupIds });
    } catch (err) {
      setError(err as Error);
      setBusy(false);
    }
  }

  return (
    <Modal
      title={asset || presetAddress ? `Хост ${asset?.address ?? presetAddress}` : "Новый хост"}
      onClose={onClose}
      footer={
        <>
          <button type="button" className="btn" onClick={onClose}>
            Отмена
          </button>
          <button type="submit" form="asset-form" className="btn btn-primary" disabled={busy || !address.trim()}>
            {busy ? "Сохранение…" : "Сохранить"}
          </button>
        </>
      }
    >
      <form id="asset-form" className="stack" style={{ gap: 16 }} onSubmit={submit}>
        <div className="inline" style={{ alignItems: "flex-end" }}>
          <label className="field" style={{ flex: "1 1 160px" }}>
            <span>Адрес</span>
            <input className="input mono" value={address} onChange={(e) => setAddress(e.target.value)} placeholder="10.0.0.5" maxLength={64} readOnly={!!presetAddress} />
          </label>
          <label className="field" style={{ flex: "1 1 160px" }}>
            <span>Имя хоста</span>
            <input className="input" value={hostname} onChange={(e) => setHostname(e.target.value)} maxLength={253} />
          </label>
        </div>
        <div className="inline" style={{ alignItems: "flex-end" }}>
          <label className="field" style={{ flex: "1 1 160px" }}>
            <span>Владелец</span>
            <input className="input" value={owner} onChange={(e) => setOwner(e.target.value)} placeholder="Отдел ИТ" maxLength={256} />
          </label>
          <label className="field" style={{ flex: "1 1 160px" }}>
            <span>Критичность</span>
            <select className="select" value={crit} onChange={(e) => setCrit(e.target.value as Criticality)}>
              {CRITICALITIES.map((c) => (
                <option key={c} value={c}>
                  {CRITICALITY_LABEL[c]}
                </option>
              ))}
            </select>
          </label>
        </div>
        <label className="field">
          <span>Теги</span>
          <input className="input" value={tags} onChange={(e) => setTags(e.target.value)} placeholder="prod, dmz, бд" />
          <small>Через запятую; регистр не важен.</small>
        </label>
        {groups.length > 0 && (
          <fieldset className="field" style={{ border: 0, padding: 0, margin: 0 }}>
            <span>Группы</span>
            <div className="inline" style={{ gap: 13, flexWrap: "wrap" }}>
              {groups.map((g) => (
                <label key={g.id} className="check">
                  <input
                    type="checkbox"
                    checked={groupIds.includes(g.id)}
                    onChange={(e) => setGroupIds((cur) => (e.target.checked ? [...cur, g.id] : cur.filter((i) => i !== g.id)))}
                  />
                  {g.name}
                </label>
              ))}
            </div>
          </fieldset>
        )}
        <label className="field">
          <span>Заметки</span>
          <textarea className="textarea" style={{ minHeight: 70 }} value={notes} onChange={(e) => setNotes(e.target.value)} maxLength={4000} />
        </label>
        {error && <ErrorAlert error={error} />}
      </form>
    </Modal>
  );
}
