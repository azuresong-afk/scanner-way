import { useState } from "react";
import type { TrendPoint } from "./TrendChart";
import { niceMax } from "./scale";

const W = 640;
const H = 220;
const PAD = { l: 40, r: 12, t: 18, b: 30 };
const BAR = 24;

/** Тренд в виде составных столбцов: снизу крит.+высокие, сверху остальные. */
export function TrendColumns({ points }: { points: TrendPoint[] }) {
  const [hover, setHover] = useState<number | null>(null);
  const max = niceMax(Math.max(1, ...points.map((p) => p.all)));
  const iw = W - PAD.l - PAD.r;
  const ih = H - PAD.t - PAD.b;
  const band = iw / Math.max(points.length, 1);
  const cx = (i: number) => PAD.l + band * (i + 0.5);
  const h = (v: number) => (v / max) * ih;
  const base = PAD.t + ih;
  const ticks = [0, 1, 2, 3, 4, 5].map((k) => (max / 5) * k);
  const last = points.length - 1;
  const labelEvery = Math.max(1, Math.ceil(points.length / 10));

  // Верхний сегмент: скругление 4px только сверху.
  const topPath = (x: number, y: number, bottom: number) => {
    if (bottom - y < 1) return "";
    const r = Math.min(4, (bottom - y) / 2);
    return `M${x},${bottom} V${y + r} Q${x},${y} ${x + r},${y} H${x + BAR - r} Q${x + BAR},${y} ${x + BAR},${y + r} V${bottom} Z`;
  };

  return (
    <div className="chart" onMouseLeave={() => setHover(null)}>
      <svg viewBox={`0 0 ${W} ${H}`} role="img" aria-label={`Открытые уязвимости по ${points.length} прогонам: с ${points[0]?.all ?? 0} до ${points[last]?.all ?? 0}`}>
        {ticks.map((t) => (
          <g key={t}>
            <line x1={PAD.l} x2={W - PAD.r} y1={base - h(t)} y2={base - h(t)} stroke="var(--grid)" strokeWidth={1} />
            <text x={PAD.l - 8} y={base - h(t) + 4} textAnchor="end" fontSize={11} fill="var(--text-3)" className="num">
              {t}
            </text>
          </g>
        ))}
        {points.map((p, i) => {
          const x = cx(i) - BAR / 2;
          const severeH = h(p.severe);
          const restTop = base - h(p.all);
          const restBottom = base - severeH - (p.severe > 0 ? 2 : 0);
          const onlySevere = p.all === p.severe;
          return (
            <g key={i} opacity={hover === null || hover === i ? 1 : 0.55}>
              {p.severe > 0 &&
                (onlySevere ? (
                  <path d={topPath(x, base - severeH, base)} fill="var(--series-2)" />
                ) : (
                  <rect x={x} y={base - severeH} width={BAR} height={severeH} fill="var(--series-2)" />
                ))}
              {!onlySevere && <path d={topPath(x, restTop, restBottom)} fill="var(--series-1)" />}
              {(i === 0 || i === last || i === hover) && (
                <text x={cx(i)} y={restTop - 6} textAnchor="middle" fontSize={11} fontWeight={600} fill="var(--text)">
                  {p.all}
                </text>
              )}
              {(i % labelEvery === 0 || i === last) && (
                <text x={cx(i)} y={H - 8} textAnchor="middle" fontSize={11} fill="var(--text-3)">
                  {p.label}
                </text>
              )}
              <rect x={cx(i) - band / 2} y={PAD.t} width={band} height={ih} fill="transparent" onMouseEnter={() => setHover(i)} />
            </g>
          );
        })}
        <line x1={PAD.l} x2={W - PAD.r} y1={base} y2={base} stroke="var(--axis)" strokeWidth={1} />
      </svg>
      {hover !== null && points[hover] && (
        <div className="tooltip" style={{ left: `${(cx(hover) / W) * 100}%`, top: `${((base - h(points[hover].all)) / H) * 100}%` }}>
          <b>
            {points[hover].label}
            {points[hover].sub ? <span className="faint"> · {points[hover].sub}</span> : null}
          </b>
          <div>
            <span>Все открытые</span>
            <span className="num">{points[hover].all}</span>
          </div>
          <div>
            <span>Крит. и высокие</span>
            <span className="num">{points[hover].severe}</span>
          </div>
        </div>
      )}
    </div>
  );
}
