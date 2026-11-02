import { useEffect, useMemo, useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { Pencil, Plus, Search, Server, Trash2 } from "lucide-react";
import { api } from "../api/client";
import type { AssetOut, Criticality } from "../api/types";
import { useAuth } from "../auth/AuthContext";
import { AssetModal, BulkBar, CriticalityBadge, GroupsBar, type BulkPatch } from "../components/AssetEditing";
import { SeverityStack } from "../components/charts/SeverityBars";
import { RunPicker } from "../components/RunPicker";
import { Empty, ErrorAlert, Loading, Modal, SeverityBadge } from "../components/ui";
import { CRITICALITIES, CRITICALITY_LABEL, osSourceHint } from "../lib/labels";
import { groupByOs, hostListRows, type HostListRow } from "../lib/stats";
import { useAsync } from "../lib/useAsync";
import { useRunSelection } from "../lib/useRunSelection";

const GROUP_KEY = "scanner.hosts.byOs";
/** Критичность хоста без учётной записи — как в R6 (scanner/core/assets.py DEFAULT_CRITICALITY). */
const DEFAULT_CRITICALITY: Criticality = "medium";

function readGrouped(): boolean {
  try {
    return localStorage.getItem(GROUP_KEY) === "1";
  } catch {
    return false;
  }
}

const critOf = (h: HostListRow): Criticality => h.asset?.criticality ?? DEFAULT_CRITICALITY;

/**
 * Единая вкладка «Хосты»: инвентарь договора по всем прогонам (ОС, сервисы,
 * уязвимости выбранного прогона) вместе с учётными атрибутами хоста —
 * критичностью, владельцем, тегами и группами (бывшая вкладка «Активы», R7).
 */
export function HostsPage() {
  const { engagement, runs, run, setRun, loading, error } = useRunSelection();
  const { has } = useAuth();
  const navigate = useNavigate();
  const eid = engagement?.id;
  // Учётные атрибуты читаются с правом view_engagements, меняются — с manage_engagements.
  const showAssets = has("view_engagements");
  const canWrite = showAssets && has("manage_engagements");

  // Список хостов — инвентарь договора по всем прогонам, от выбора прогона не зависит.
  const inventory = useAsync(() => api.hosts(eid!), [eid], !!eid);
  // От прогона зависят только счётчики уязвимостей.
  const findings = useAsync(() => api.findings(run!.id), [run?.id], !!run);
  const assets = useAsync(() => api.assets(eid!), [eid], !!eid && showAssets);
  const groups = useAsync(() => api.assetGroups(eid!), [eid], !!eid && showAssets);
  const tags = useAsync(() => api.assetTags(eid!), [eid], !!eid && showAssets);

  const [query, setQuery] = useState("");
  const [osFilter, setOsFilter] = useState<string[]>([]);
  const [groupId, setGroupId] = useState<number | null>(null);
  const [criticality, setCriticality] = useState<Criticality | "">("");
  const [tag, setTag] = useState("");
  const [grouped, setGrouped] = useState(readGrouped);
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [editing, setEditing] = useState<HostListRow | "new" | null>(null);
  const [removing, setRemoving] = useState<HostListRow | null>(null);
  const [busy, setBusy] = useState(false);
  const [actionError, setActionError] = useState<Error | null>(null);

  useEffect(() => {
    try {
      localStorage.setItem(GROUP_KEY, grouped ? "1" : "0");
    } catch {
      /* без хранилища выбор живёт до перезагрузки */
    }
  }, [grouped]);

  const hosts = useMemo(
    () => (inventory.data ? hostListRows(inventory.data, assets.data ?? [], findings.data ?? [], run?.id ?? null) : []),
    [inventory.data, assets.data, findings.data, run?.id],
  );
  const inRun = hosts.filter((h) => h.inRun).length;
  // Семейства ОС, встречающиеся в договоре, в порядке групп — для чипов фильтра.
  const osFamilies = useMemo(() => groupByOs(hosts).map((g) => ({ family: g.family, label: g.label, count: g.rows.length })), [hosts]);
  const q = query.trim().toLowerCase();
  const shown = hosts.filter((h) => {
    if (osFilter.length && !osFilter.includes(h.osFamily)) return false;
    if (groupId !== null && !h.asset?.groups.some((g) => g.id === groupId)) return false;
    if (criticality && critOf(h) !== criticality) return false;
    if (tag && !h.asset?.tags.includes(tag)) return false;
    if (!q) return true;
    const a = h.asset;
    const hay = [h.host, h.summary, h.osLabel, h.osName, a?.hostname, a?.owner, ...(a?.tags ?? []), ...(a?.groups.map((g) => g.name) ?? [])];
    return hay.filter(Boolean).join(" ").toLowerCase().includes(q);
  });
  const osGroups = grouped ? groupByOs(shown) : [];
  const toggleOs = (f: string) => setOsFilter((cur) => (cur.includes(f) ? cur.filter((x) => x !== f) : [...cur, f]));
  const allSelected = shown.length > 0 && shown.every((h) => selected.has(h.host));

  async function reloadAssets() {
    await Promise.all([assets.reload(), groups.reload(), tags.reload()]);
  }

  async function act(fn: () => Promise<unknown>) {
    setBusy(true);
    setActionError(null);
    try {
      await fn();
      await reloadAssets();
    } catch (e) {
      setActionError(e as Error);
    } finally {
      setBusy(false);
    }
  }

  /** id учётных записей для адресов; недостающие заводятся (критичность по умолчанию). */
  async function ensureAssets(addresses: string[]): Promise<number[]> {
    const known = new Map((assets.data ?? []).map((a) => [a.address, a.id]));
    const ids: number[] = [];
    for (const addr of addresses) {
      let id = known.get(addr);
      if (id === undefined) id = (await api.createAsset(eid!, { address: addr })).id;
      ids.push(id);
    }
    return ids;
  }

  function hostLink(h: HostListRow): string | null {
    if (!run || !h.scanned) return null;
    return `/hosts/${encodeURIComponent(h.host)}?run=${h.inRun ? run.id : (h.lastRunId ?? run.id)}`;
  }

  // Колонки до «Макс. опасность» — для строки-заголовка группы ОС.
  const leadCols = (canWrite ? 1 : 0) + 4 + (showAssets ? 2 : 0);

  function renderRow(h: HostListRow) {
    const to = hostLink(h);
    const a = h.asset;
    return (
      <tr key={h.host} className={to ? "clickable" : undefined} onClick={to ? () => navigate(to) : undefined}>
        {canWrite && (
          <td onClick={(e) => e.stopPropagation()}>
            <input
              type="checkbox"
              aria-label={`Выбрать ${h.host}`}
              checked={selected.has(h.host)}
              onChange={(e) =>
                setSelected((cur) => {
                  const next = new Set(cur);
                  if (e.target.checked) next.add(h.host);
                  else next.delete(h.host);
                  return next;
                })
              }
            />
          </td>
        )}
        <td>
          {to ? (
            <Link className="mono" to={to} onClick={(e) => e.stopPropagation()}>
              {h.host}
            </Link>
          ) : (
            <span className="mono">{h.host}</span>
          )}
          {a?.hostname && <small className="faint os-name">{a.hostname}</small>}
        </td>
        <td style={{ maxWidth: 240 }} title={osSourceHint(h.osSource, h.osAccuracy)}>
          {h.osFamily === "unknown" ? (
            <span className="faint">не определена</span>
          ) : (
            <>
              <span>{h.osLabel}</span>
              {h.osName && h.osName !== h.osLabel && <small className="faint os-name">{h.osName}</small>}
            </>
          )}
        </td>
        <td className="muted" style={{ maxWidth: 280 }}>
          {h.summary || "—"}
        </td>
        <td className="right num">{h.scanned ? h.services.length : "—"}</td>
        {showAssets && (
          <>
            <td>
              <CriticalityBadge value={critOf(h)} implicit={!a} />
            </td>
            <td style={{ maxWidth: 260 }}>
              {a?.owner ?? <span className="faint">—</span>}
              {a && (a.groups.length > 0 || a.tags.length > 0) && (
                <div className="inline" style={{ gap: 4, flexWrap: "wrap", marginTop: 4 }}>
                  {a.groups.map((g) => (
                    <span key={`g${g.id}`} className="chip chip-static" title="Группа">
                      {g.name}
                    </span>
                  ))}
                  {a.tags.map((t) => (
                    <span key={`t${t}`} className="chip chip-static faint" title="Тег">
                      #{t}
                    </span>
                  ))}
                </div>
              )}
            </td>
          </>
        )}
        {!h.scanned ? (
          <>
            <td colSpan={2} className="faint" title="Хост заведён вручную и ещё не сканировался">
              не сканировался
            </td>
            <td className="right num faint">—</td>
          </>
        ) : h.inRun ? (
          <>
            <td>{h.total ? <SeverityBadge severity={h.maxSeverity} /> : <span className="faint">нет</span>}</td>
            <td style={{ width: 180 }}>
              <SeverityStack counts={h.counts} />
            </td>
            <td className="right num" style={{ fontWeight: 600 }}>
              {h.total}
            </td>
          </>
        ) : (
          <>
            <td colSpan={2} className="faint" title="Хост не сканировался в выбранном прогоне">
              не в прогоне №{run?.id}
            </td>
            <td className="right num faint">—</td>
          </>
        )}
        {canWrite && (
          <td className="nowrap" onClick={(e) => e.stopPropagation()}>
            <button type="button" className="btn btn-ghost icon-btn" aria-label={`Изменить ${h.host}`} onClick={() => setEditing(h)}>
              <Pencil size={15} />
            </button>
            {a && (
              <button
                type="button"
                className="btn btn-ghost icon-btn"
                aria-label={h.scanned ? `Сбросить учёт ${h.host}` : `Удалить ${h.host}`}
                onClick={() => setRemoving(h)}
              >
                <Trash2 size={15} />
              </button>
            )}
          </td>
        )}
      </tr>
    );
  }

  if (!engagement) return <div className="card"><Empty title="Выберите или создайте договор" /></div>;

  // Пока нет данных — загрузка (у находок флаг loading включается не сразу после выбора прогона).
  const pending = (enabled: boolean, s: { data?: unknown; error: Error | null }) => enabled && s.data === undefined && !s.error;
  const firstLoad = pending(true, inventory) || pending(!!run, findings) || pending(showAssets, assets);

  return (
    <>
      <div className="page-head">
        <div>
          <span className="crumbs">{engagement.client ? `${engagement.client} · ${engagement.name}` : engagement.name}</span>
          <h1>Активы</h1>
        </div>
        <div className="actions">
          {canWrite && (
            <button type="button" className="btn" onClick={() => setEditing("new")} title="Завести актив вручную, например ещё не сканированный хост">
              <Plus size={16} /> Добавить актив
            </button>
          )}
          {runs.length > 0 && <RunPicker runs={runs} value={run?.id ?? null} onChange={setRun} />}
        </div>
      </div>
      {error && <ErrorAlert error={error} />}
      {inventory.error && <ErrorAlert error={inventory.error} onRetry={inventory.reload} />}
      {findings.error && <ErrorAlert error={findings.error} onRetry={findings.reload} />}
      {assets.error && <ErrorAlert error={assets.error} onRetry={assets.reload} />}
      {actionError && <ErrorAlert error={actionError} />}


      {loading && !runs.length ? (
        <Loading />
      ) : (
        <section className="card" style={{ overflow: "hidden" }}>
          <div className="card-head">
            <h2>
              {shown.length} {shown.length === hosts.length ? "" : `из ${hosts.length}`} {plural(hosts.length)}
              {run && (
                <span className="faint" style={{ fontWeight: 400, fontSize: 13, marginLeft: 8 }}>
                  в прогоне №{run.id}: {inRun}
                </span>
              )}
            </h2>
            <div className="inline" style={{ gap: 13, flexWrap: "wrap" }}>
              <label className="check" style={{ alignItems: "center" }}>
                <input type="checkbox" checked={grouped} onChange={(e) => setGrouped(e.target.checked)} />
                По ОС
              </label>
              {showAssets && (
                <>
                  <select className="select" style={{ width: "auto" }} aria-label="Критичность" value={criticality} onChange={(e) => setCriticality(e.target.value as Criticality | "")}>
                    <option value="">Любая критичность</option>
                    {CRITICALITIES.map((c) => (
                      <option key={c} value={c}>
                        {CRITICALITY_LABEL[c]}
                      </option>
                    ))}
                  </select>
                  {(tags.data?.length ?? 0) > 0 && (
                    <select className="select" style={{ width: "auto" }} aria-label="Тег" value={tag} onChange={(e) => setTag(e.target.value)}>
                      <option value="">Любой тег</option>
                      {(tags.data ?? []).map((t) => (
                        <option key={t.tag} value={t.tag}>
                          {t.tag} ({t.count})
                        </option>
                      ))}
                    </select>
                  )}
                </>
              )}
              <div className="search" style={{ width: 260, maxWidth: "100%" }}>
                <Search size={15} aria-hidden="true" />
                <input
                  className="input"
                  type="search"
                  placeholder={showAssets ? "IP, имя, ОС, владелец, тег" : "IP, сервис или ОС"}
                  aria-label="Поиск актива"
                  value={query}
                  onChange={(e) => setQuery(e.target.value)}
                />
              </div>
            </div>
          </div>
          {osFamilies.length > 0 && (
            <div className="inline os-filter" role="group" aria-label="Фильтр по ОС">
              <span className="faint chip-row-label">ОС</span>
              {osFamilies.map((f) => (
                <button key={f.family} type="button" className="chip" aria-pressed={osFilter.includes(f.family)} onClick={() => toggleOs(f.family)}>
                  {f.label} <span className="faint">{f.count}</span>
                </button>
              ))}
              {osFilter.length > 0 && (
                <button type="button" className="btn btn-sm btn-ghost" onClick={() => setOsFilter([])}>
                  Все ОС
                </button>
              )}
            </div>
          )}

          {showAssets && (groups.data?.length || canWrite) ? (
            <GroupsBar
              groups={groups.data ?? []}
              active={groupId}
              onPick={(id) => setGroupId((cur) => (cur === id ? null : id))}
              canWrite={canWrite}
              onCreate={(name) => act(() => api.createAssetGroup(eid!, name))}
              onRename={(g, name) => act(() => api.renameAssetGroup(eid!, g.id, name))}
              onDelete={(g) => {
                if (groupId === g.id) setGroupId(null);
                return act(() => api.deleteAssetGroup(eid!, g.id));
              }}
            />
          ) : null}

          {canWrite && selected.size > 0 && (
            <BulkBar
              count={selected.size}
              groups={groups.data ?? []}
              busy={busy}
              onApply={(patch: BulkPatch) =>
                act(async () => {
                  const ids = await ensureAssets([...selected]);
                  await api.bulkAssets(eid!, { asset_ids: ids, ...patch });
                  setSelected(new Set());
                })
              }
              onClear={() => setSelected(new Set())}
            />
          )}

          {firstLoad ? (
            <Loading />
          ) : hosts.length === 0 ? (
            <Empty title="Активов пока нет" icon={<Server size={28} />}>
              {canWrite ? "Активы появятся после первого прогона; можно и завести актив вручную." : "Активы появятся после первого прогона."}
            </Empty>
          ) : shown.length === 0 ? (
            <Empty title="Активы не найдены" />
          ) : (
            <div className="table-wrap">
              <table className="table" style={{ minWidth: showAssets ? 1240 : 980 }}>
                <thead>
                  <tr>
                    {canWrite && (
                      <th style={{ width: 36 }}>
                        <input
                          type="checkbox"
                          aria-label="Выбрать все"
                          checked={allSelected}
                          onChange={(e) => setSelected(e.target.checked ? new Set(shown.map((h) => h.host)) : new Set())}
                        />
                      </th>
                    )}
                    <th>Хост</th>
                    <th>ОС</th>
                    <th>Сервисы</th>
                    <th className="right">Портов</th>
                    {showAssets && (
                      <>
                        <th>Критичность</th>
                        <th>Владелец, группы, теги</th>
                      </>
                    )}
                    <th>Макс. опасность</th>
                    <th>Распределение</th>
                    <th className="right">Уязвимостей</th>
                    {canWrite && <th style={{ width: 80 }} />}
                  </tr>
                </thead>
                {grouped ? (
                  osGroups.map((g) => (
                    <tbody key={g.family} aria-label={g.label}>
                      <tr className="os-group">
                        <td colSpan={leadCols}>
                          <b>{g.label}</b>{" "}
                          <span className="faint">
                            {g.rows.length} {plural(g.rows.length)}
                          </span>
                        </td>
                        <td />
                        <td style={{ width: 180 }}>{g.total > 0 && <SeverityStack counts={g.counts} />}</td>
                        <td className="right num">{g.total}</td>
                        {canWrite && <td />}
                      </tr>
                      {g.rows.map(renderRow)}
                    </tbody>
                  ))
                ) : (
                  <tbody>{shown.map(renderRow)}</tbody>
                )}
              </table>
            </div>
          )}
        </section>
      )}

      {editing && (
        <AssetModal
          asset={editing === "new" ? null : editing.asset}
          presetAddress={editing !== "new" && !editing.asset ? editing.host : undefined}
          groups={groups.data ?? []}
          onClose={() => setEditing(null)}
          onSave={async (data) => {
            const existing: AssetOut | null = editing === "new" ? null : editing.asset;
            if (existing) await api.updateAsset(eid!, existing.id, data);
            else await api.createAsset(eid!, data);
            setEditing(null);
            await reloadAssets();
          }}
        />
      )}
      {removing?.asset && (
        <Modal
          title={removing.scanned ? "Сбросить учётные данные актива?" : "Удалить актив?"}
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
                  const a = removing.asset!;
                  setRemoving(null);
                  void act(() => api.deleteAsset(eid!, a.id));
                }}
              >
                {removing.scanned ? "Сбросить" : "Удалить"}
              </button>
            </>
          }
        >
          <p style={{ margin: 0 }}>
            {removing.scanned
              ? `У актива ${removing.host} будут убраны владелец, теги, группы, заметки, а критичность вернётся к «Средней». Сам актив и результаты прогонов остаются.`
              : `Актив ${removing.host} заведён вручную и ещё не сканировался — он пропадёт из списка.`}
          </p>
        </Modal>
      )}
    </>
  );
}

function plural(n: number): string {
  const d = n % 10;
  const dd = n % 100;
  if (d === 1 && dd !== 11) return "актив";
  if (d >= 2 && d <= 4 && (dd < 12 || dd > 14)) return "актива";
  return "активов";
}
