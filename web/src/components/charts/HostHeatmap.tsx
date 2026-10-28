import type { Severity } from "../../api/types";
import { SEVERITY_SHORT } from "../../lib/labels";
import { heatLevel, type HostRow } from "../../lib/stats";

const COLS: Severity[] = ["critical", "high", "medium", "low"];

/** Тепловая карта «хост × уровень опасности» (одна синяя шкала, светлее = меньше). */
export function HostHeatmap({ rows, onPick, limit = 12 }: { rows: HostRow[]; onPick?: (host: string) => void; limit?: number }) {
  const shown = rows.slice(0, limit);
  return (
    <div className="table-wrap">
      <table className="heat">
        <thead>
          <tr>
            <th scope="col">Хост</th>
            <th scope="col" style={{ textAlign: "left" }}>
              Сервисы
            </th>
            {COLS.map((s) => (
              <th key={s} scope="col">
                {SEVERITY_SHORT[s]}
              </th>
            ))}
            <th scope="col" style={{ textAlign: "right" }}>
              Всего
            </th>
          </tr>
        </thead>
        <tbody>
          {shown.map((r) => (
            <tr
              key={r.host}
              onClick={onPick ? () => onPick(r.host) : undefined}
              style={onPick ? { cursor: "pointer" } : undefined}
            >
              <td className="mono">
                {onPick ? (
                  <button
                    type="button"
                    onClick={(e) => {
                      e.stopPropagation();
                      onPick(r.host);
                    }}
                    style={{ all: "unset", cursor: "pointer" }}>
                    {r.host}
                  </button>
                ) : (
                  r.host
                )}
              </td>
              <td className="muted" style={{ maxWidth: 260, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                {r.summary || "—"}
              </td>
              {COLS.map((s) => (
                <td key={s} className={`cell h${heatLevel(r.counts[s])}`} title={`${r.host}: ${SEVERITY_SHORT[s]} ${r.counts[s]}`}>
                  {r.counts[s]}
                </td>
              ))}
              <td className="num" style={{ textAlign: "right", fontWeight: 600 }}>
                {r.total}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

export function HeatLegend() {
  return (
    <span className="heat-legend" aria-hidden="true">
      меньше
      <i style={{ background: "var(--heat-1)" }} />
      <i style={{ background: "var(--heat-2)" }} />
      <i style={{ background: "var(--heat-3)" }} />
      <i style={{ background: "var(--heat-4)" }} />
      больше
    </span>
  );
}
