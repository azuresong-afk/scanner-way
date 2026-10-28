import { useMemo, useState } from "react";
import { ArrowDown, ArrowUp } from "lucide-react";
import type { FindingOut } from "../api/types";
import { MODULE_LABEL } from "../lib/labels";
import { compareFindings, compareIp, SEVERITY_RANK } from "../lib/stats";
import { FindingStatusPill, RefTags, SeverityBadge } from "./ui";

type SortKey = "severity" | "title" | "host" | "cvss" | "module";

const PAGE = 100;

export function FindingsTable({
  findings,
  onOpen,
  selected,
  hideHost,
}: {
  findings: FindingOut[];
  onOpen: (f: FindingOut) => void;
  selected?: FindingOut | null;
  hideHost?: boolean;
}) {
  const [sort, setSort] = useState<{ key: SortKey; dir: 1 | -1 }>({ key: "severity", dir: 1 });
  const [limit, setLimit] = useState(PAGE);

  const rows = useMemo(() => {
    const cmp: Record<SortKey, (a: FindingOut, b: FindingOut) => number> = {
      severity: compareFindings,
      title: (a, b) => a.title.localeCompare(b.title, "ru"),
      host: (a, b) => compareIp(a.host, b.host) || (a.port ?? 0) - (b.port ?? 0),
      cvss: (a, b) => (b.cvss ?? -1) - (a.cvss ?? -1) || SEVERITY_RANK[b.severity] - SEVERITY_RANK[a.severity],
      module: (a, b) => a.module.localeCompare(b.module),
    };
    return [...findings].sort((a, b) => cmp[sort.key](a, b) * sort.dir);
  }, [findings, sort]);

  const head = (key: SortKey, label: string, right?: boolean) => (
    <th scope="col" className={right ? "right" : undefined} aria-sort={sort.key === key ? (sort.dir === 1 ? "ascending" : "descending") : "none"}>
      <button type="button" onClick={() => setSort((s) => ({ key, dir: s.key === key ? ((-s.dir) as 1 | -1) : 1 }))}>
        {label}
        {sort.key === key && (sort.dir === 1 ? <ArrowDown size={12} /> : <ArrowUp size={12} />)}
      </button>
    </th>
  );

  return (
    <>
      <div className="table-wrap">
        <table className="table" style={{ minWidth: 860 }}>
          <thead>
            <tr>
              {head("severity", "Опасность")}
              {head("title", "Уязвимость")}
              {!hideHost && head("host", "Хост:порт")}
              <th scope="col">БДУ ФСТЭК / CVE</th>
              {head("cvss", "CVSS", true)}
              {head("module", "Модуль")}
              <th scope="col">Статус</th>
            </tr>
          </thead>
          <tbody>
            {rows.slice(0, limit).map((f, i) => (
              <tr
                key={`${f.host}|${f.port}|${f.vuln_id}|${f.module}|${i}`}
                className={`clickable ${selected === f ? "selected" : ""}`}
                onClick={() => onOpen(f)}
              >
                <td>
                  <SeverityBadge severity={f.severity} />
                </td>
                <td style={{ fontWeight: 500, minWidth: 240 }}>
                  <button
                    type="button"
                    onClick={(e) => {
                      e.stopPropagation();
                      onOpen(f);
                    }}
                    style={{ all: "unset", cursor: "pointer" }}
                  >
                    {f.title}
                  </button>
                </td>
                {!hideHost && (
                  <td className="mono nowrap">
                    {f.host}
                    {f.port ? `:${f.port}` : ""}
                  </td>
                )}
                <td>
                  <RefTags cve={f.cve_ids} bdu={f.bdu_ids} limit={3} />
                </td>
                <td className="right num">{f.cvss !== null ? f.cvss.toFixed(1) : "—"}</td>
                <td className="muted nowrap">{MODULE_LABEL[f.module] ?? f.module}</td>
                <td>
                  <FindingStatusPill status={f.status} />
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      {rows.length > limit && (
        <div style={{ padding: 12, textAlign: "center" }}>
          <button type="button" className="btn btn-sm" onClick={() => setLimit((l) => l + PAGE)}>
            Показать ещё ({rows.length - limit})
          </button>
        </div>
      )}
    </>
  );
}
