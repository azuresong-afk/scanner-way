import { useState } from "react";
import { niceMax } from "./scale";

export interface TrendPoint {
  label: string;
  sub?: string;
  all: number;
  severe: number;
}

const W = 640;
const H = 280;
const PAD = { l: 40, r: 16, t: 16, b: 30 };

/**
 * Тренд открытых уязвимостей по прогонам: две линии в одной шкале
 * (все / критические+высокие), перекрестие и подсказка при наведении.
 */
export function TrendChart({ points }: { points: TrendPoint[] }) {
  const [hover, setHover] = useState<number | null>(null);
  const max = niceMax(Math.max(1, ...points.map((p) => p.all)));
  const iw = W - PAD.l - PAD.r;
  const ih = H - PAD.t - PAD.b;
  const step = points.length > 1 ? iw / (points.length - 1) : 0;
  const x = (i: number) => (points.length > 1 ? PAD.l + i * step : PAD.l + iw / 2);
  const y = (v: number) => PAD.t + ih - (v / max) * ih;
  const path = (key: "all" | "severe") =>
    points.map((p, i) => `${i ? "L" : "M"}${x(i).toFixed(1)},${y(p[key]).toFixed(1)}`).join(" ");
  const ticks = [0, 1, 2, 3, 4, 5].map((k) => (max / 5) * k);
  const labelEvery = Math.max(1, Math.ceil(points.length / 10));
  const last = points.length - 1;
  const band = points.length > 1 ? step : iw;

  return (
    <div className="chart" onMouseLeave={() => setHover(null)}>
      <svg
        viewBox={`0 0 ${W} ${H}`}
        role="img"
        aria-label={`Открытые уязвимости по ${points.length} прогонам: с ${points[0]?.all ?? 0} до ${points[last]?.all ?? 0}`}
      >
        {ticks.map((t) => (
          <g key={t}>
            <line x1={PAD.l} x2={W - PAD.r} y1={y(t)} y2={y(t)} stroke="var(--grid)" strokeWidth={1} />
            <text x={PAD.l - 8} y={y(t) + 4} textAnchor="end" fontSize={11} fill="var(--text-3)" className="num">
              {t}
            </text>
          </g>
        ))}
        <line x1={PAD.l} x2={W - PAD.r} y1={y(0)} y2={y(0)} stroke="var(--axis)" strokeWidth={1} />
        {points.length > 1 && (
          <path d={`${path("all")} L${x(last)},${y(0)} L${x(0)},${y(0)} Z`} fill="var(--series-1)" fillOpacity={0.1} />
        )}
        <path d={path("all")} fill="none" stroke="var(--series-1)" strokeWidth={2} strokeLinejoin="round" strokeLinecap="round" />
        <path d={path("severe")} fill="none" stroke="var(--series-2)" strokeWidth={2} strokeLinejoin="round" strokeLinecap="round" />
        {hover !== null && (
          <line x1={x(hover)} x2={x(hover)} y1={PAD.t} y2={y(0)} stroke="var(--border-strong)" strokeWidth={1} />
        )}
        {points.map((p, i) =>
          i === last || i === hover || points.length === 1 ? (
            <g key={i}>
              <circle cx={x(i)} cy={y(p.all)} r={4.5} fill="var(--series-1)" stroke="var(--surface)" strokeWidth={2} />
              <circle cx={x(i)} cy={y(p.severe)} r={4.5} fill="var(--series-2)" stroke="var(--surface)" strokeWidth={2} />
            </g>
          ) : null,
        )}
        {hover === null && points.length > 0 && (
          <>
            <text x={x(last) - 8} y={y(points[last].all) - 10} textAnchor="end" fontSize={12} fontWeight={600} fill="var(--text)">
              {points[last].all}
            </text>
            <text x={x(last) - 8} y={y(points[last].severe) - 10} textAnchor="end" fontSize={12} fontWeight={600} fill="var(--text)">
              {points[last].severe}
            </text>
          </>
        )}
        {points.map((p, i) =>
          i % labelEvery === 0 || i === last ? (
            <text key={i} x={x(i)} y={H - 8} textAnchor="middle" fontSize={11} fill="var(--text-3)">
              {p.label}
            </text>
          ) : null,
        )}
        {points.map((_, i) => (
          <rect
            key={i}
            x={x(i) - band / 2}
            y={PAD.t}
            width={band}
            height={ih}
            fill="transparent"
            onMouseEnter={() => setHover(i)}
          />
        ))}
      </svg>
      {hover !== null && points[hover] && (
        <div
          className="tooltip"
          style={{ left: `${(x(hover) / W) * 100}%`, top: `${(y(points[hover].all) / H) * 100}%` }}
        >
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
