/** «Красивый» верх шкалы (1, 2, 2.5, 5 × 10^n), делится на 5 целых делений. */
export function niceMax(v: number): number {
  if (v <= 5) return 5;
  const p = 10 ** Math.floor(Math.log10(v));
  for (const m of [1, 2, 2.5, 5, 10]) if (m * p >= v) return m * p;
  return 10 * p;
}
