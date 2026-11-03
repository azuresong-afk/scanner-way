import type { RunOut } from "../api/types";
import { fmtDate } from "../lib/format";
import { RUN_STATUS_LABEL, runName } from "../lib/labels";

const short = (s: string, n = 48) => (s.length > n ? `${s.slice(0, n - 1)}…` : s);

/**
 * Выбор прогона. С `latestLabel` первым пунктом идёт «без прогона» (value = null)
 * — например, «Последние данные» на вкладке «Активы».
 */
export function RunPicker({
  runs,
  value,
  onChange,
  label = "Прогон",
  latestLabel,
}: {
  runs: RunOut[];
  value: number | null;
  /** null — выбран пункт `latestLabel` (бывает только с ним). */
  onChange(id: number | null): void;
  label?: string;
  latestLabel?: string;
}) {
  return (
    <label className="inline" style={{ gap: 8 }}>
      <span className="faint" style={{ fontSize: 13 }}>
        {label}
      </span>
      <select
        className="select"
        style={{ width: "auto", height: 34 }}
        value={value ?? ""}
        onChange={(e) => onChange(e.target.value === "" ? null : Number(e.target.value))}
      >
        {latestLabel ? <option value="">{latestLabel}</option> : value === null && <option value="">—</option>}
        {runs.map((r) => (
          <option key={r.id} value={r.id}>
            №{r.id} · {short(runName(r))} · {fmtDate(r.started_at ?? r.created_at)} · {RUN_STATUS_LABEL[r.status]}
          </option>
        ))}
      </select>
    </label>
  );
}
