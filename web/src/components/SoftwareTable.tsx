import { Fragment, useEffect, useMemo, useState } from "react";
import { ArrowDown, ArrowUp, ChevronDown, ChevronRight, EyeOff, Undo2 } from "lucide-react";
import { api } from "../api/client";
import type { FindingOut, ServiceOut, SoftwareFalsePositiveOut } from "../api/types";
import { bySoftware, sortSoftware, type SoftwareRow, type SoftwareSortKey } from "../lib/stats";
import { SeverityStack } from "./charts/SeverityBars";
import { FindingsTable } from "./FindingsTable";
import { Empty, Modal, SeverityBadge } from "./ui";

interface SoftwareSort {
  key: SoftwareSortKey;
  dir: 1 | -1;
}
const SORT_KEY = "scanner.host.swSort";
const SORT_KEYS: SoftwareSortKey[] = ["risk", "count", "cvss", "name"];

function loadSort(): SoftwareSort {
  try {
    const v = JSON.parse(localStorage.getItem(SORT_KEY) ?? "null") as SoftwareSort | null;
    if (v && SORT_KEYS.includes(v.key) && (v.dir === 1 || v.dir === -1)) return v;
  } catch {
    // нет localStorage или мусор в нём — сортировка по умолчанию
  }
  return { key: "risk", dir: 1 };
}

function saveSort(v: SoftwareSort) {
  try {
    localStorage.setItem(SORT_KEY, JSON.stringify(v));
  } catch {
    // без localStorage — просто не запоминаем
  }
}

/** Что делаем с ПО: отметить все его уязвимости как ложные или снять отметку. */
interface FpAction {
  row: SoftwareRow;
  mark: boolean;
}

/** Уязвимости хоста, сгруппированные по ПО; по клику на ПО раскрывается его список. */
export function SoftwareTable({
  findings,
  services,
  onOpen,
  selected,
  runId,
  host,
  triage,
  onChanged,
}: {
  findings: FindingOut[];
  services: ServiceOut[];
  onOpen: (f: FindingOut) => void;
  selected?: FindingOut | null;
  /** Прогон, хост и право triage_findings — для отметки «ложное срабатывание» всего ПО; без них кнопки нет. */
  runId?: number;
  host?: string;
  triage?: boolean;
  onChanged?: () => void;
}) {
  const canTriage = !!triage && runId != null && !!host;
  const [sort, setSortState] = useState<SoftwareSort>(loadSort);
  const rows = useMemo(() => sortSoftware(bySoftware(findings, services), sort.key, sort.dir), [findings, services, sort]);
  const [expanded, setExpanded] = useState<Set<string>>(() => new Set());
  const [action, setAction] = useState<FpAction | null>(null);
  if (!rows.length) return <Empty title="Уязвимостей не найдено" />;

  const setSort = (key: SoftwareSortKey) => {
    const next: SoftwareSort = { key, dir: sort.key === key ? ((-sort.dir) as 1 | -1) : 1 };
    setSortState(next);
    saveSort(next);
  };
  const head = (key: SoftwareSortKey, label: string, right?: boolean) => (
    <th scope="col" className={right ? "right" : undefined} aria-sort={sort.key === key ? (sort.dir === 1 ? "descending" : "ascending") : "none"}>
      <button type="button" title={`Сортировать: ${label.toLowerCase()}`} onClick={() => setSort(key)}>
        {label}
        {sort.key === key && (sort.dir === 1 ? <ArrowDown size={12} /> : <ArrowUp size={12} />)}
      </button>
    </th>
  );

  const toggle = (key: string) =>
    setExpanded((prev) => {
      const next = new Set(prev);
      if (next.has(key)) next.delete(key);
      else next.add(key);
      return next;
    });
  const allOpen = rows.every((r) => expanded.has(r.key));

  return (
    <div className="table-wrap">
      <table className="table sw-table" style={{ minWidth: 760 }}>
        <thead>
          <tr>
            <th scope="col" style={{ width: 34 }}>
              <button
                type="button"
                className="sw-toggle"
                aria-label={allOpen ? "Свернуть все" : "Раскрыть все"}
                title={allOpen ? "Свернуть все" : "Раскрыть все"}
                onClick={() => setExpanded(allOpen ? new Set() : new Set(rows.map((r) => r.key)))}
              >
                {allOpen ? <ChevronDown size={15} /> : <ChevronRight size={15} />}
              </button>
            </th>
            {head("name", "ПО")}
            <th scope="col">Версия</th>
            <th scope="col">Где найдено</th>
            {head("risk", "Макс. опасность")}
            <th scope="col">Распределение</th>
            {head("cvss", "Макс. CVSS", true)}
            {head("count", "Уязвимостей", true)}
            {canTriage && (
              <th scope="col" style={{ width: 34 }}>
                <span className="sr-only">Ложные срабатывания</span>
              </th>
            )}
          </tr>
        </thead>
        <tbody>
          {rows.map((r) => {
            const open = expanded.has(r.key);
            return (
              <Fragment key={r.key}>
                <tr className={`clickable${open ? " selected" : ""}`} onClick={() => toggle(r.key)}>
                  <td>
                    <button
                      type="button"
                      className="sw-toggle"
                      aria-expanded={open}
                      aria-label={`${open ? "Свернуть" : "Раскрыть"} уязвимости ${r.name}`}
                      onClick={(e) => {
                        e.stopPropagation();
                        toggle(r.key);
                      }}
                    >
                      {open ? <ChevronDown size={15} /> : <ChevronRight size={15} />}
                    </button>
                  </td>
                  <td style={{ fontWeight: 600 }}>
                    {r.name}
                    {!r.known && <span className="faint" style={{ fontWeight: 400 }}> · ПО не определено</span>}
                  </td>
                  <td className="mono muted">{r.version ?? "—"}</td>
                  <td className="muted">
                    {r.ports.length > 0 && <span className="mono">{r.ports.join(", ")}</span>}
                    {r.ports.length > 0 && r.fromPackage && ", "}
                    {r.fromPackage && "пакет (по учётной записи)"}
                    {!r.ports.length && !r.fromPackage && "—"}
                  </td>
                  <td>{r.total ? <SeverityBadge severity={r.maxSeverity} /> : <span className="faint">нет</span>}</td>
                  <td style={{ width: 180 }}>
                    <SeverityStack counts={r.counts} />
                  </td>
                  <td className="right num">{r.maxCvss != null ? r.maxCvss.toFixed(1) : "—"}</td>
                  <td className="right num" style={{ fontWeight: 600 }}>
                    {r.total}
                    {r.falsePositives > 0 && (
                      <small className="faint" style={{ fontWeight: 400 }} title="Отмечено как ложные срабатывания">
                        {" "}
                        +{r.falsePositives} ложн.
                      </small>
                    )}
                  </td>
                  {canTriage && (
                    <td onClick={(e) => e.stopPropagation()}>
                      {r.known && r.total > 0 ? (
                        <button
                          type="button"
                          className="sw-toggle"
                          title="Все уязвимости этого ПО — в ложные срабатывания"
                          aria-label={`Отметить все уязвимости ${r.name} как ложные срабатывания`}
                          onClick={() => setAction({ row: r, mark: true })}
                        >
                          <EyeOff size={15} />
                        </button>
                      ) : r.known && r.falsePositives > 0 ? (
                        <button
                          type="button"
                          className="sw-toggle"
                          title="Снять отметку «ложное срабатывание» со всех уязвимостей этого ПО"
                          aria-label={`Снять отметку ложного срабатывания с ${r.name}`}
                          onClick={() => setAction({ row: r, mark: false })}
                        >
                          <Undo2 size={15} />
                        </button>
                      ) : null}
                    </td>
                  )}
                </tr>
                {open && (
                  <tr className="sw-detail">
                    <td colSpan={canTriage ? 9 : 8}>
                      <FindingsTable findings={r.findings} onOpen={onOpen} selected={selected} hideHost />
                    </td>
                  </tr>
                )}
              </Fragment>
            );
          })}
        </tbody>
      </table>
      {action && runId != null && host && (
        <SoftwareFalsePositiveModal
          action={action}
          runId={runId}
          host={host}
          onClose={() => setAction(null)}
          onDone={() => {
            setAction(null);
            onChanged?.();
          }}
        />
      )}
    </div>
  );
}

const plural = (n: number, one: string, few: string, many: string) => {
  const m10 = n % 10;
  const m100 = n % 100;
  if (m10 === 1 && m100 !== 11) return one;
  if (m10 >= 2 && m10 <= 4 && (m100 < 12 || m100 > 14)) return few;
  return many;
};
const vulns = (n: number) => `${n} ${plural(n, "уязвимость", "уязвимости", "уязвимостей")}`;

/**
 * Подтверждение: все уязвимости ПО — в ложные срабатывания (или снять отметку).
 * Охват — этот хост или все хосты прогона с тем же ПО той же версии; число
 * для «всех хостов» сервер считает заранее (dry_run). Действие — в журнал аудита.
 */
function SoftwareFalsePositiveModal({
  action,
  runId,
  host,
  onClose,
  onDone,
}: {
  action: FpAction;
  runId: number;
  host: string;
  onClose: () => void;
  onDone: () => void;
}) {
  const { row, mark } = action;
  const [allHosts, setAllHosts] = useState(false);
  const [reason, setReason] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [preview, setPreview] = useState<SoftwareFalsePositiveOut | null>(null);
  const base = { software: row.name, version: row.version };
  const call = mark ? api.markSoftwareFalsePositive : api.unmarkSoftwareFalsePositive;
  const label = `${row.name}${row.version ? ` ${row.version}` : ""}`;
  const here = mark ? row.total : row.falsePositives;

  useEffect(() => {
    let alive = true;
    call(runId, { ...base, all_hosts: true, dry_run: true })
      .then((r) => alive && setPreview(r))
      .catch(() => alive && setPreview(null));
    return () => {
      alive = false;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [runId, row.key, mark]);

  const submit = async () => {
    setBusy(true);
    setError(null);
    try {
      await call(runId, { ...base, ...(allHosts ? { all_hosts: true } : { host }), reason: mark ? reason.trim() || null : null });
      onDone();
    } catch (e) {
      setError((e as Error).message);
      setBusy(false);
    }
  };

  return (
    <Modal
      title={mark ? "Отметить ПО как ложное срабатывание" : "Снять отметку с ПО"}
      onClose={onClose}
      footer={
        <>
          <button type="button" className="btn btn-ghost" disabled={busy} onClick={onClose}>
            Отмена
          </button>
          <button type="button" className="btn btn-primary" disabled={busy} onClick={() => void submit()}>
            {mark ? <EyeOff size={14} /> : <Undo2 size={14} />} {mark ? "Отметить" : "Снять отметку"}
          </button>
        </>
      }
    >
      <div className="stack" style={{ gap: 13 }}>
        <p style={{ margin: 0 }}>
          {mark ? "Все уязвимости " : "Отметка «ложное срабатывание» будет снята со всех уязвимостей "}
          <strong>{label}</strong>
          {mark ? " будут отмечены как ложные срабатывания." : "."}
        </p>
        <div className="stack" role="radiogroup" aria-label="Где применить" style={{ gap: 8 }}>
          <label className="check">
            <input type="radio" name="fp-scope" checked={!allHosts} onChange={() => setAllHosts(false)} />
            <span>
              <b>Только на этом хосте</b>
              <small>
                <span className="mono">{host}</span> — {vulns(here)}
              </small>
            </span>
          </label>
          <label className="check">
            <input type="radio" name="fp-scope" checked={allHosts} onChange={() => setAllHosts(true)} />
            <span>
              <b>На всех хостах прогона с этим ПО</b>
              <small>
                {preview
                  ? `${preview.hosts} ${plural(preview.hosts, "хост", "хоста", "хостов")}, ${vulns(preview.changed)}`
                  : "считаю…"}
              </small>
            </span>
          </label>
        </div>
        {mark && (
          <label className="field">
            <span>Обоснование</span>
            <textarea
              className="textarea"
              style={{ fontFamily: "inherit", minHeight: 72 }}
              value={reason}
              onChange={(e) => setReason(e.target.value)}
              maxLength={2000}
              placeholder="Например: ПО не используется, порт закрыт межсетевым экраном"
            />
          </label>
        )}
        <small className="faint">
          {mark
            ? "Отмеченные уязвимости не учитываются в сводке, отчётах и сравнении прогонов и останутся ложными в следующих прогонах договора. Уже отмеченные ранее не меняются. "
            : ""}
          Действие записывается в журнал аудита; отметку можно снять так же, одной кнопкой.
        </small>
        {error && (
          <div className="alert alert-danger" role="alert">
            {error}
          </div>
        )}
      </div>
    </Modal>
  );
}
