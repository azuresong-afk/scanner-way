import type { Severity } from "../../api/types";
import { fmtDelta, fmtNumber } from "../../lib/format";
import { SEVERITY_LABEL } from "../../lib/labels";
import { columnTotal, type RunColumn } from "../../lib/summary";
import { niceMax } from "./scale";

type Level = Exclude<Severity, "info">;

/** Порядок в столбце снизу вверх: критические у основания. */
const STACK: Level[] = ["critical", "high", "medium", "low"];
/** Подписей под осью не больше — иначе они наезжают друг на друга. */
const MAX_X_LABELS = 12;

/** Заголовок подсказки и начало подписи для чтения с экрана. */
const caption = (p: RunColumn, sep: string) => (p.period ? `${p.period}${sep}прогон ${p.sub}` : `Прогон ${p.label}${sep}${p.sub}`);

/**
 * Открытые уязвимости по прогонам: столбец на прогон, внутри — уровни опасности.
 * Растягивается на всю высоту карточки. Подписаны первый и последний итог и самое
 * большое снижение; остальное — в подсказке при наведении или фокусе.
 */
export function RunColumns({ points }: { points: RunColumn[] }) {
  const totals = points.map(columnTotal);
  // запас сверху под подпись итога
  const max = niceMax(Math.max(1, ...totals) * 1.08);
  const ticks = [0, 1, 2, 3, 4, 5].map((k) => (max / 5) * k);
  const pct = (v: number) => `${(v / max) * 100}%`;
  let drop = { i: -1, d: 0 };
  for (let i = 1; i < totals.length; i++) {
    const d = totals[i] - totals[i - 1];
    if (d < drop.d) drop = { i, d };
  }
  const last = points.length - 1;
  // при многих столбцах подписан каждый step-й, считая от последнего
  const step = Math.max(1, Math.ceil(points.length / MAX_X_LABELS));

  return (
    <div className="runcols">
      <div className="runcols-plot">
        {ticks.map((t) => (
          <span key={t} className={`runcols-grid ${t === 0 ? "base" : ""}`} style={{ bottom: pct(t) }} aria-hidden="true">
            <span className="runcols-tick num">{fmtNumber(t)}</span>
          </span>
        ))}
        <div className="runcols-cols" role="list" aria-label="Открытые уязвимости по уровням в каждом прогоне">
          {points.map((p, i) => {
            const total = totals[i];
            const aria = `${caption(p, ", ")}: всего ${total}; ${STACK.map((s) => `${SEVERITY_LABEL[s].toLowerCase()} ${p.counts[s]}`).join(", ")}`;
            return (
              <div key={`${p.label}-${i}`} className="runcols-col" role="listitem" tabIndex={0} aria-label={aria}>
                {(i === 0 || i === last) && (
                  <span className={`runcols-total num ${i === last ? "last" : ""}`} style={{ bottom: `calc(${pct(total)} + 6px)` }} aria-hidden="true">
                    {fmtNumber(total)}
                  </span>
                )}
                {i === drop.i && i !== last && (
                  <span className="runcols-total runcols-drop num" style={{ bottom: `calc(${pct(total)} + 6px)` }} aria-hidden="true">
                    {fmtDelta(drop.d)}
                  </span>
                )}
                <span className="runcols-bar" style={{ height: pct(total) }} aria-hidden="true">
                  {[...STACK].reverse().map((s) =>
                    p.counts[s] > 0 ? <span key={s} className={`sevbar-fill ${s}`} style={{ flex: `${p.counts[s]} 1 0` }} /> : null,
                  )}
                </span>
                <span className={`runcols-tip ${i < points.length / 2 ? "to-right" : "to-left"}`} aria-hidden="true">
                  <b>{caption(p, " · ")}</b>
                  <span>
                    Всего <b className="num">{fmtNumber(total)}</b>
                  </span>
                  {STACK.map((s) => (
                    <span key={s} className={`sev sev-${s}`}>
                      <i />
                      {SEVERITY_LABEL[s]} <span className="num">{p.counts[s]}</span>
                    </span>
                  ))}
                </span>
              </div>
            );
          })}
        </div>
      </div>
      <div className="runcols-x" aria-hidden="true">
        {points.map((p, i) => (
          <span key={`${p.label}-${i}`} className={i === last ? "last" : ""}>
            {(last - i) % step === 0 && (
              <>
                <span>{p.label}</span>
                <span className="faint">{p.sub}</span>
              </>
            )}
          </span>
        ))}
      </div>
    </div>
  );
}

/** Те же данные таблицей (для чтения с экрана и печати). */
export function RunColumnsTable({ points }: { points: RunColumn[] }) {
  const periods = points.some((p) => p.period);
  return (
    <div className="table-wrap">
      <table className="table">
        <thead>
          <tr>
            <th>{periods ? "Период" : "Прогон"}</th>
            <th>{periods ? "Последний прогон" : "Дата"}</th>
            {STACK.map((s) => (
              <th key={s} className="right">
                {SEVERITY_LABEL[s]}
              </th>
            ))}
            <th className="right">Всего</th>
          </tr>
        </thead>
        <tbody>
          {points.map((p, i) => (
            <tr key={`${p.label}-${i}`}>
              <td className={periods ? undefined : "mono"}>{p.period ?? p.label}</td>
              <td className="muted nowrap">{p.sub}</td>
              {STACK.map((s) => (
                <td key={s} className="right num">
                  {p.counts[s]}
                </td>
              ))}
              <td className="right num" style={{ fontWeight: 600 }}>
                {columnTotal(p)}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
