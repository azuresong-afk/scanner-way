import { Fragment, useMemo, useState } from "react";
import { ChevronDown, ChevronRight } from "lucide-react";
import type { FindingOut, ServiceOut } from "../api/types";
import { bySoftware } from "../lib/stats";
import { SeverityStack } from "./charts/SeverityBars";
import { FindingsTable } from "./FindingsTable";
import { Empty, SeverityBadge } from "./ui";

/** Уязвимости хоста, сгруппированные по ПО; по клику на ПО раскрывается его список. */
export function SoftwareTable({
  findings,
  services,
  onOpen,
  selected,
}: {
  findings: FindingOut[];
  services: ServiceOut[];
  onOpen: (f: FindingOut) => void;
  selected?: FindingOut | null;
}) {
  const rows = useMemo(() => bySoftware(findings, services), [findings, services]);
  const [expanded, setExpanded] = useState<Set<string>>(() => new Set());
  if (!rows.length) return <Empty title="Уязвимостей не найдено" />;

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
            <th scope="col">ПО</th>
            <th scope="col">Версия</th>
            <th scope="col">Где найдено</th>
            <th scope="col">Макс. опасность</th>
            <th scope="col">Распределение</th>
            <th scope="col" className="right">
              Макс. CVSS
            </th>
            <th scope="col" className="right">
              Уязвимостей
            </th>
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
                  </td>
                </tr>
                {open && (
                  <tr className="sw-detail">
                    <td colSpan={8}>
                      <FindingsTable findings={r.findings} onOpen={onOpen} selected={selected} hideHost />
                    </td>
                  </tr>
                )}
              </Fragment>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}
