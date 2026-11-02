import { useMemo, useState } from "react";
import { Search } from "lucide-react";
import { api } from "../api/client";
import type { Criticality } from "../api/types";
import { CRITICALITIES, CRITICALITY_LABEL } from "../lib/labels";
import { groupByOs, hostListRows, type HostListRow } from "../lib/stats";
import { inAllowlist } from "../lib/targets";
import { useAsync } from "../lib/useAsync";
import { CriticalityBadge } from "./AssetEditing";
import { Empty, ErrorAlert, Loading, Modal } from "./ui";

/** Критичность хоста без учётной записи — как в R6 (DEFAULT_CRITICALITY). */
const DEFAULT_CRITICALITY: Criticality = "medium";
const critOf = (h: HostListRow): Criticality => h.asset?.criticality ?? DEFAULT_CRITICALITY;

export type HostPickerMode = "run" | "allowlist";

/**
 * Выбор хостов из «Активов» договора: поиск, фильтры по группе, ОС, тегу и
 * критичности, отметка по одному или всех найденных (например, всей группы).
 *
 * mode="run" — цели прогона: хосты вне allowlist показываются, но выбрать их
 * нельзя (сканер не выходит за объём работ). mode="allowlist" — расширение
 * allowlist: уже разрешённые хосты отмечены и не выбираются повторно.
 */
export function HostPicker({
  engagementId,
  allowlist,
  mode,
  onClose,
  onPick,
  busy,
  error,
}: {
  engagementId: number;
  /** Подсети allowlist договора (CIDR). */
  allowlist: string[];
  mode: HostPickerMode;
  onClose: () => void;
  onPick: (addresses: string[]) => void;
  busy?: boolean;
  error?: string | null;
}) {
  const inventory = useAsync(() => api.hosts(engagementId), [engagementId]);
  const assets = useAsync(() => api.assets(engagementId), [engagementId]);
  const groups = useAsync(() => api.assetGroups(engagementId), [engagementId]);
  const tags = useAsync(() => api.assetTags(engagementId), [engagementId]);

  const [query, setQuery] = useState("");
  const [groupId, setGroupId] = useState<number | null>(null);
  const [osFilter, setOsFilter] = useState<string[]>([]);
  const [tag, setTag] = useState("");
  const [criticality, setCriticality] = useState<Criticality | "">("");
  const [selected, setSelected] = useState<Set<string>>(new Set());

  const hosts = useMemo(
    () => (inventory.data || assets.data ? hostListRows(inventory.data ?? [], assets.data ?? [], [], null) : []),
    [inventory.data, assets.data],
  );
  const inScope = useMemo(() => new Set(hosts.filter((h) => inAllowlist(h.host, allowlist)).map((h) => h.host)), [hosts, allowlist]);
  // run: выбирать можно только разрешённые; allowlist: только ещё не разрешённые.
  const selectable = (h: HostListRow) => (mode === "run" ? inScope.has(h.host) : !inScope.has(h.host));
  const osFamilies = useMemo(() => groupByOs(hosts).map((g) => ({ family: g.family, label: g.label, count: g.rows.length })), [hosts]);

  const q = query.trim().toLowerCase();
  const shown = hosts.filter((h) => {
    if (groupId !== null && !h.asset?.groups.some((g) => g.id === groupId)) return false;
    if (osFilter.length && !osFilter.includes(h.osFamily)) return false;
    if (criticality && critOf(h) !== criticality) return false;
    if (tag && !h.asset?.tags.includes(tag)) return false;
    if (!q) return true;
    const a = h.asset;
    const hay = [h.host, h.osLabel, h.osName, a?.hostname, a?.owner, a?.notes, ...(a?.tags ?? []), ...(a?.groups.map((g) => g.name) ?? [])];
    return hay.filter(Boolean).join(" ").toLowerCase().includes(q);
  });
  const shownSelectable = shown.filter(selectable);
  const allShownSelected = shownSelectable.length > 0 && shownSelectable.every((h) => selected.has(h.host));
  const blockedShown = shown.length - shownSelectable.length;
  const filtered = !!(q || groupId !== null || osFilter.length || tag || criticality);

  const setMany = (addrs: string[], on: boolean) =>
    setSelected((cur) => {
      const next = new Set(cur);
      for (const a of addrs) {
        if (on) next.add(a);
        else next.delete(a);
      }
      return next;
    });
  const toggleOs = (f: string) => setOsFilter((cur) => (cur.includes(f) ? cur.filter((x) => x !== f) : [...cur, f]));
  const resetFilters = () => {
    setQuery("");
    setGroupId(null);
    setOsFilter([]);
    setTag("");
    setCriticality("");
  };

  const loading = (inventory.loading && !inventory.data) || (assets.loading && !assets.data);
  const loadError = inventory.error && assets.error ? inventory.error : null;
  const picked = [...selected];
  const title = mode === "run" ? "Цели прогона из активов" : "Добавить активы в allowlist";
  const action = mode === "run" ? "Добавить в цели" : "Добавить в allowlist";

  return (
    <Modal
      title={title}
      wide
      onClose={onClose}
      footer={
        <>
          <span className="muted" style={{ marginRight: "auto", fontSize: 13 }} aria-live="polite">
            Выбрано: <b style={{ color: "var(--text)" }}>{picked.length}</b>
            {picked.length > 0 && (
              <>
                {" · "}
                <button type="button" className="btn btn-sm btn-ghost" style={{ height: "auto", padding: 0 }} onClick={() => setSelected(new Set())}>
                  снять выбор
                </button>
              </>
            )}
          </span>
          <button type="button" className="btn" onClick={onClose}>
            Отмена
          </button>
          <button type="button" className="btn btn-primary" disabled={picked.length === 0 || busy} onClick={() => onPick(picked)}>
            {busy ? "Сохранение…" : `${action}${picked.length ? ` (${picked.length})` : ""}`}
          </button>
        </>
      }
    >
      <div className="stack" style={{ gap: 13 }}>
        {mode === "run" ? (
          <small className="muted">
            Выбирать можно только хосты из allowlist договора — хосты вне его показаны серым. Подряд идущие адреса сворачиваются в диапазон.
          </small>
        ) : (
          <small style={{ color: "var(--warn)" }}>
            Добавляйте в allowlist только хосты, входящие в объём работ по договору. Заносятся ровно выбранные адреса (подряд идущие — одним
            диапазоном), действие пишется в журнал аудита.
          </small>
        )}

        <div className="inline" style={{ gap: 8, flexWrap: "wrap" }}>
          <div className="search" style={{ flex: "1 1 240px" }}>
            <Search size={15} aria-hidden="true" />
            <input
              className="input"
              type="search"
              aria-label="Поиск хостов"
              placeholder="Адрес, имя, владелец, тег, ОС…"
              value={query}
              onChange={(e) => setQuery(e.target.value)}
            />
          </div>
          <select className="select" aria-label="Тег" value={tag} onChange={(e) => setTag(e.target.value)} style={{ width: "auto" }}>
            <option value="">Все теги</option>
            {(tags.data ?? []).map((t) => (
              <option key={t.tag} value={t.tag}>
                #{t.tag} ({t.count})
              </option>
            ))}
          </select>
          <select
            className="select"
            aria-label="Критичность"
            value={criticality}
            onChange={(e) => setCriticality(e.target.value as Criticality | "")}
            style={{ width: "auto" }}
          >
            <option value="">Любая критичность</option>
            {CRITICALITIES.map((c) => (
              <option key={c} value={c}>
                {CRITICALITY_LABEL[c]}
              </option>
            ))}
          </select>
          {filtered && (
            <button type="button" className="btn btn-ghost" onClick={resetFilters}>
              Сбросить фильтры
            </button>
          )}
        </div>

        {(groups.data ?? []).length > 0 && (
          <div className="inline" role="group" aria-label="Группы активов" style={{ gap: 6, flexWrap: "wrap" }}>
            <span className="faint" style={{ fontSize: 12, marginRight: 4 }}>
              Группа:
            </span>
            {groups.data!.map((g) => (
              <button key={g.id} type="button" className="chip" aria-pressed={groupId === g.id} onClick={() => setGroupId(groupId === g.id ? null : g.id)}>
                {g.name} <span className="faint">{g.asset_count}</span>
              </button>
            ))}
          </div>
        )}
        {osFamilies.length > 1 && (
          <div className="inline" role="group" aria-label="Семейства ОС" style={{ gap: 6, flexWrap: "wrap" }}>
            <span className="faint" style={{ fontSize: 12, marginRight: 4 }}>
              ОС:
            </span>
            {osFamilies.map((f) => (
              <button key={f.family} type="button" className="chip" aria-pressed={osFilter.includes(f.family)} onClick={() => toggleOs(f.family)}>
                {f.label} <span className="faint">{f.count}</span>
              </button>
            ))}
          </div>
        )}

        {error && <ErrorAlert error={error} />}
        {loading ? (
          <Loading />
        ) : loadError ? (
          <ErrorAlert error={loadError} onRetry={() => (inventory.reload(), assets.reload())} />
        ) : hosts.length === 0 ? (
          <Empty title="В «Активах» пока нет хостов">Добавьте активы на вкладке «Активы» или запустите обнаружение хостов.</Empty>
        ) : (
          <>
            <div className="inline" style={{ gap: 8, flexWrap: "wrap" }}>
              <button
                type="button"
                className="btn btn-sm"
                disabled={shownSelectable.length === 0}
                onClick={() => setMany(shownSelectable.map((h) => h.host), !allShownSelected)}
              >
                {allShownSelected ? "Снять найденные" : `Выбрать ${filtered ? "найденные" : "все"} (${shownSelectable.length})`}
              </button>
              <small className="muted">
                Показано {shown.length} из {hosts.length}
                {blockedShown > 0 && ` · ${mode === "run" ? "вне allowlist" : "уже в allowlist"}: ${blockedShown}`}
              </small>
            </div>
            <div className="table-wrap card" style={{ maxHeight: "50vh", overflowY: "auto" }}>
              <table className="table">
                <thead>
                  <tr>
                    <th style={{ width: 34 }}>
                      <input
                        type="checkbox"
                        aria-label="Выбрать все найденные"
                        checked={allShownSelected}
                        disabled={shownSelectable.length === 0}
                        onChange={(e) => setMany(shownSelectable.map((h) => h.host), e.target.checked)}
                      />
                    </th>
                    <th>Хост</th>
                    <th>ОС</th>
                    <th>Критичность</th>
                    <th>Группы и теги</th>
                    <th>Allowlist</th>
                  </tr>
                </thead>
                <tbody>
                  {shown.map((h) => {
                    const can = selectable(h);
                    const a = h.asset;
                    return (
                      <tr key={h.host} className={can ? "clickable" : undefined} style={can ? undefined : { opacity: 0.55 }} onClick={can ? () => setMany([h.host], !selected.has(h.host)) : undefined}>
                        <td onClick={(e) => e.stopPropagation()}>
                          <input
                            type="checkbox"
                            aria-label={`Выбрать ${h.host}`}
                            checked={selected.has(h.host)}
                            disabled={!can}
                            onChange={(e) => setMany([h.host], e.target.checked)}
                          />
                        </td>
                        <td>
                          <span className="mono">{h.host}</span>
                          {a?.hostname && <small className="faint os-name">{a.hostname}</small>}
                        </td>
                        <td>{h.osFamily === "unknown" ? <span className="faint">не определена</span> : h.osLabel}</td>
                        <td>
                          <CriticalityBadge value={critOf(h)} implicit={!a} />
                        </td>
                        <td style={{ maxWidth: 280 }}>
                          {a && (a.groups.length > 0 || a.tags.length > 0) ? (
                            <div className="inline" style={{ gap: 4, flexWrap: "wrap" }}>
                              {a.groups.map((g) => (
                                <span key={`g${g.id}`} className="chip chip-static">
                                  {g.name}
                                </span>
                              ))}
                              {a.tags.map((t) => (
                                <span key={`t${t}`} className="chip chip-static faint">
                                  #{t}
                                </span>
                              ))}
                            </div>
                          ) : (
                            <span className="faint">—</span>
                          )}
                        </td>
                        <td className="nowrap">
                          {inScope.has(h.host) ? <span className="muted">в allowlist</span> : <span style={{ color: "var(--warn)" }}>вне allowlist</span>}
                        </td>
                      </tr>
                    );
                  })}
                  {shown.length === 0 && (
                    <tr>
                      <td colSpan={6} className="muted" style={{ textAlign: "center", padding: 21 }}>
                        Под фильтр не попал ни один хост
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
          </>
        )}
      </div>
    </Modal>
  );
}
