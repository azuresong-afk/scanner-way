import type { RunOut } from "../api/types";
import { fmtDate } from "../lib/format";
import { RUN_STATUS_LABEL } from "../lib/labels";

export function RunPicker({ runs, value, onChange, label = "Прогон" }: { runs: RunOut[]; value: number | null; onChange: (id: number) => void; label?: string }) {
  return (
    <label className="inline" style={{ gap: 8 }}>
      <span className="faint" style={{ fontSize: 13 }}>
        {label}
      </span>
      <select className="select" style={{ width: "auto", height: 34 }} value={value ?? ""} onChange={(e) => onChange(Number(e.target.value))}>
        {value === null && <option value="">—</option>}
        {runs.map((r) => (
          <option key={r.id} value={r.id}>
            №{r.id} · {fmtDate(r.started_at ?? r.created_at)} · {RUN_STATUS_LABEL[r.status]}
          </option>
        ))}
      </select>
    </label>
  );
}
