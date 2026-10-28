import type { Severity } from "../../api/types";
import { SEVERITY_LABEL } from "../../lib/labels";
import type { SeverityCounts } from "../../lib/stats";

const ORDER: Severity[] = ["critical", "high", "medium", "low"];

/** Горизонтальные столбцы по уровням опасности; подпись значения справа. */
export function SeverityBars({ counts, onPick }: { counts: SeverityCounts; onPick?: (s: Severity) => void }) {
  const max = Math.max(1, ...ORDER.map((s) => counts[s]));
  return (
    <div className="sevbars">
      {ORDER.map((s) => {
        const content = (
          <>
            <span className={`sev sev-${s}`}>
              <i aria-hidden="true" />
              {SEVERITY_LABEL[s]}
            </span>
            <span className="sevbar-track">
              <span
                className={`sevbar-fill ${s}`}
                style={{ display: "block", width: counts[s] ? `${(counts[s] / max) * 100}%` : 0 }}
              />
            </span>
            <span className="num" style={{ textAlign: "right", fontWeight: 600 }}>
              {counts[s]}
            </span>
          </>
        );
        return onPick ? (
          <button
            key={s}
            type="button"
            className="sevbar"
            title={`${SEVERITY_LABEL[s]}: ${counts[s]} — показать находки`}
            onClick={() => onPick(s)}
            style={{ all: "unset", display: "grid", gridTemplateColumns: "118px minmax(0,1fr) 40px", gap: 10, alignItems: "center", cursor: "pointer" }}
          >
            {content}
          </button>
        ) : (
          <div key={s} className="sevbar" title={`${SEVERITY_LABEL[s]}: ${counts[s]}`}>
            {content}
          </div>
        );
      })}
    </div>
  );
}

/** Узкая полоса-распределение (без информационных). */
export function SeverityStack({ counts }: { counts: SeverityCounts }) {
  const parts = ORDER.filter((s) => counts[s] > 0);
  if (!parts.length) return <span className="faint">—</span>;
  return (
    <div
      className="stackbar"
      role="img"
      aria-label={parts.map((s) => `${SEVERITY_LABEL[s]}: ${counts[s]}`).join(", ")}
      style={{ minWidth: 80 }}
    >
      {parts.map((s) => (
        <span
          key={s}
          title={`${SEVERITY_LABEL[s]}: ${counts[s]}`}
          className={`sevbar-fill ${s}`}
          style={{ flex: `${counts[s]} 1 0`, height: 10 }}
        />
      ))}
    </div>
  );
}
