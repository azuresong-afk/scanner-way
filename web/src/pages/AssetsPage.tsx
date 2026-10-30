import { useMemo, useState, type FormEvent } from "react";
import { Boxes, Download, Pencil, Plus, Search, Tag, Trash2 } from "lucide-react";
import { api } from "../api/client";
import type { AssetGroupOut, AssetIn, AssetOut, Criticality } from "../api/types";
import { useAuth } from "../auth/AuthContext";
import { useEngagement } from "../auth/EngagementContext";
import { SeverityStack } from "../components/charts/SeverityBars";
import { Empty, ErrorAlert, Loading, Modal } from "../components/ui";
import { CRITICALITIES, CRITICALITY_LABEL } from "../lib/labels";
import { useAsync } from "../lib/useAsync";

/** Мягкая метка критичности — те же цвета, что у опасности находок. */
export function CriticalityBadge({ value }: { value: Criticality }) {
  return (
    <span className={`sev sev-${value}`}>
      <i aria-hidden="true" />
      {CRITICALITY_LABEL[value]}
    </span>
  );
}

const splitTags = (s: string) => s.split(/[,;\n]/).map((t) => t.trim()).filter(Boolean);

export function AssetsPage() {
  const { current: engagement } = useEngagement();
  const { has } = useAuth();
  const canWrite = has("manage_engagements");
  const eid = engagement?.id;
  const [query, setQuery] = useState("");
  const [criticality, setCriticality] = useState<Criticality | "">("");
  const [tag, setTag] = useState("");
  const [groupId, setGroupId] = useState<number | null>(null);
  const [selected, setSelected] = useState<Set<number>>(new Set());
  const [editing, setEditing] = useState<AssetOut | "new" | null>(null);
  const [removing, setRemoving] = useState<AssetOut | null>(null);
  const [busy, setBusy] = useState(false);
  const [actionError, setActionError] = useState<Error | null>(null);

  const filters = { q: query.trim() || undefined, criticality: criticality || undefined, tag: tag || undefined, group_id: groupId ?? undefined };
  const assets = useAsync(
    () => api.assets(eid!, filters),
    [eid, filters.q, filters.criticality, filters.tag, filters.group_id],
    !!eid,
  );
  const groups = useAsync(() => api.assetGroups(eid!), [eid], !!eid);
  const tags = useAsync(() => api.assetTags(eid!), [eid], !!eid);

  const rows = assets.data ?? [];
  const allSelected = rows.length > 0 && rows.every((r) => selected.has(r.id));
  const reloadAll = async () => {
    await Promise.all([assets.reload(), groups.reload(), tags.reload()]);
  };

  async function run(fn: () => Promise<unknown>) {
    setBusy(true);
    setActionError(null);
    try {
      await fn();
      await reloadAll();
    } catch (e) {
      setActionError(e as Error);
    } finally {
      setBusy(false);
    }
  }

  if (!engagement) return <div className="card"><Empty title="Выберите или создайте договор" /></div>;

  return (
    <>
      <div className="page-head">
        <div>
          <span className="crumbs">{engagement.client ? `${engagement.client} · ${engagement.name}` : engagement.name}</span>
          <h1>Активы</h1>
        </div>
        {canWrite && (
          <div className="actions">
            <button type="button" className="btn" disabled={busy} onClick={() => run(() => api.importAssets(eid!))} title="Завести активы для хостов, найденных прогонами">
              <Download size={16} /> Из найденных хостов
            </button>
            <button type="button" className="btn btn-primary" onClick={() => setEditing("new")}>
              <Plus size={16} /> Добавить актив
            </button>
          </div>
        )}
      </div>
      {assets.error && <ErrorAlert error={assets.error} onRetry={assets.reload} />}
      {actionError && <ErrorAlert error={actionError} />}

      <GroupsBar
        groups={groups.data ?? []}
        active={groupId}
        onPick={(id) => setGroupId((cur) => (cur === id ? null : id))}
        canWrite={canWrite}
        onCreate={(name) => run(() => api.createAssetGroup(eid!, name))}
        onRename={(g, name) => run(() => api.renameAssetGroup(eid!, g.id, name))}
        onDelete={(g) => {
          if (groupId === g.id) setGroupId(null);
          return run(() => api.deleteAssetGroup(eid!, g.id));
        }}
      />

      <section className="card" style={{ overflow: "hidden" }}>
        <div className="card-head">
          <h2>
            {rows.length} {rows.length === 1 ? "актив" : "активов"}
          </h2>
          <div className="inline" style={{ gap: 13 }}>
            <select className="select" aria-label="Критичность" value={criticality} onChange={(e) => setCriticality(e.target.value as Criticality | "")}>
              <option value="">Любая критичность</option>
              {CRITICALITIES.map((c) => (
                <option key={c} value={c}>
                  {CRITICALITY_LABEL[c]}
                </option>
              ))}
            </select>
            <select className="select" aria-label="Тег" value={tag} onChange={(e) => setTag(e.target.value)}>
              <option value="">Любой тег</option>
              {(tags.data ?? []).map((t) => (
                <option key={t.tag} value={t.tag}>
                  {t.tag} ({t.count})
                </option>
              ))}
            </select>
            <div className="search" style={{ width: 240, maxWidth: "100%" }}>
              <Search size={15} aria-hidden="true" />
              <input className="input" type="search" placeholder="Адрес, имя, владелец" aria-label="Поиск актива" value={query} onChange={(e) => setQuery(e.target.value)} />
            </div>
          </div>
        </div>

        {canWrite && selected.size > 0 && (
          <BulkBar
            count={selected.size}
            groups={groups.data ?? []}
            busy={busy}
            onApply={(patch) => run(async () => {
              await api.bulkAssets(eid!, { asset_ids: [...selected], ...patch });
              setSelected(new Set());
            })}
            onClear={() => setSelected(new Set())}
          />
        )}

        {assets.loading && !assets.data ? (
          <Loading />
        ) : rows.length === 0 ? (
          <Empty title="Активов нет" icon={<Boxes size={28} />}>
            {canWrite ? "Добавьте актив вручную или заведите их из хостов, найденных прогонами." : "Активы пока не заведены."}
          </Empty>
        ) : (
          <div className="table-wrap">
            <table className="table" style={{ minWidth: 1040 }}>
              <thead>
                <tr>
                  {canWrite && (
                    <th style={{ width: 36 }}>
                      <input type="checkbox" aria-label="Выбрать все" checked={allSelected} onChange={(e) => setSelected(e.target.checked ? new Set(rows.map((r) => r.id)) : new Set())} />
                    </th>
                  )}
                  <th>Актив</th>
                  <th>Владелец</th>
                  <th>Критичность</th>
                  <th>Теги</th>
                  <th>Группы</th>
                  <th>Находки</th>
                  {canWrite && <th style={{ width: 80 }} />}
                </tr>
              </thead>
              <tbody>
                {rows.map((a) => (
                  <tr key={a.id}>
                    {canWrite && (
                      <td>
                        <input
                          type="checkbox"
                          aria-label={`Выбрать ${a.address}`}
                          checked={selected.has(a.id)}
                          onChange={(e) =>
                            setSelected((cur) => {
                              const next = new Set(cur);
                              if (e.target.checked) next.add(a.id);
                              else next.delete(a.id);
                              return next;
                            })
                          }
                        />
                      </td>
                    )}
                    <td>
                      <span className="mono">{a.address}</span>
                      {(a.hostname || a.os_family_label) && (
                        <small className="faint os-name">{[a.hostname, a.os_family_label].filter(Boolean).join(" · ")}</small>
                      )}
                    </td>
                    <td>{a.owner ?? <span className="faint">—</span>}</td>
                    <td>
                      <CriticalityBadge value={a.criticality} />
                    </td>
                    <td>
                      <div className="inline" style={{ gap: 4, flexWrap: "wrap" }}>
                        {a.tags.length ? a.tags.map((t) => <span key={t} className="chip">{t}</span>) : <span className="faint">—</span>}
                      </div>
                    </td>
                    <td>{a.groups.length ? a.groups.map((g) => g.name).join(", ") : <span className="faint">—</span>}</td>
                    <td style={{ width: 190 }}>
                      {a.last_run_id === null ? (
                        <span className="faint" title="Хост не сканировался">не сканировался</span>
                      ) : a.findings_total ? (
                        <div className="inline" style={{ gap: 8 }}>
                          <SeverityStack counts={{ critical: 0, high: 0, medium: 0, low: 0, info: 0, ...a.finding_counts }} />
                          <b className="num">{a.findings_total}</b>
                        </div>
                      ) : (
                        <span className="faint">нет</span>
                      )}
                    </td>
                    {canWrite && (
                      <td className="right nowrap">
                        <button type="button" className="btn btn-ghost icon-btn" aria-label={`Изменить ${a.address}`} onClick={() => setEditing(a)}>
                          <Pencil size={15} />
                        </button>
                        <button type="button" className="btn btn-ghost icon-btn" aria-label={`Удалить ${a.address}`} onClick={() => setRemoving(a)}>
                          <Trash2 size={15} />
                        </button>
                      </td>
                    )}
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>

      {editing && (
        <AssetModal
          asset={editing === "new" ? null : editing}
          groups={groups.data ?? []}
          onClose={() => setEditing(null)}
          onSave={async (data) => {
            if (editing === "new") await api.createAsset(eid!, data);
            else await api.updateAsset(eid!, editing.id, data);
            setEditing(null);
            await reloadAll();
          }}
        />
      )}
      {removing && (
        <Modal
          title="Удалить актив?"
          onClose={() => setRemoving(null)}
          footer={
            <>
              <button type="button" className="btn" onClick={() => setRemoving(null)}>
                Отмена
              </button>
              <button
                type="button"
                className="btn btn-danger"
                disabled={busy}
                onClick={() => {
                  const a = removing;
                  setRemoving(null);
                  setSelected((cur) => new Set([...cur].filter((i) => i !== a.id)));
                  void run(() => api.deleteAsset(eid!, a.id));
                }}
              >
                Удалить
              </button>
            </>
          }
        >
          <p style={{ margin: 0 }}>Актив {removing.address} будет убран из реестра. Результаты прогонов не затрагиваются.</p>
        </Modal>
      )}
    </>
  );
}

function GroupsBar({
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
    <div className="inline os-filter" role="group" aria-label="Группы активов" style={{ marginBottom: 13 }}>
      <span className="faint" style={{ fontSize: 12 }}>
        Группы
      </span>
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

function BulkBar({
  count,
  groups,
  busy,
  onApply,
  onClear,
}: {
  count: number;
  groups: AssetGroupOut[];
  busy: boolean;
  onApply: (patch: { add_tags?: string[]; remove_tags?: string[]; add_group_ids?: number[]; remove_group_ids?: number[]; criticality?: Criticality; owner?: string }) => void;
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

function AssetModal({
  asset,
  groups,
  onClose,
  onSave,
}: {
  asset: AssetOut | null;
  groups: AssetGroupOut[];
  onClose: () => void;
  onSave: (data: AssetIn) => Promise<void>;
}) {
  const [address, setAddress] = useState(asset?.address ?? "");
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
      title={asset ? `Актив ${asset.address}` : "Новый актив"}
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
            <input className="input mono" value={address} onChange={(e) => setAddress(e.target.value)} placeholder="10.0.0.5" maxLength={64} />
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
