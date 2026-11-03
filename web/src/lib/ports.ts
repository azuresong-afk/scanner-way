// Запись портов «22, 80, 8000-8100» — как в API (scanner/core/portspec.py):
// запятая, точка с запятой или пробел между записями, диапазон — через дефис.

export type PortRange = [number, number];

/** Разобрать запись портов; строка — текст ошибки для пользователя. */
export function parsePortSpec(text: string): PortRange[] | string {
  const raw = text.trim().replace(/\s*[-‐-―]\s*/g, "-");
  if (!raw) return [];
  const out: PortRange[] = [];
  for (const item of raw.split(/[,;\s]+/).filter(Boolean)) {
    const m = /^(\d{1,5})(?:-(\d{1,5}))?$/.exec(item);
    if (!m) return `не порт и не диапазон: «${item}»`;
    const lo = Number(m[1]);
    const hi = m[2] ? Number(m[2]) : lo;
    for (const p of [lo, hi]) if (p < 1 || p > 65535) return `порт вне диапазона 1–65535: ${p}`;
    if (hi < lo) return `конец диапазона меньше начала: «${item}»`;
    out.push([lo, hi]);
  }
  return mergeRanges(out);
}

export function mergeRanges(ranges: PortRange[]): PortRange[] {
  const out: PortRange[] = [];
  for (const [lo, hi] of [...ranges].sort((a, b) => a[0] - b[0] || a[1] - b[1])) {
    const last = out[out.length - 1];
    if (last && lo <= last[1] + 1) last[1] = Math.max(last[1], hi);
    else out.push([lo, hi]);
  }
  return out;
}

export function subtractRanges(ranges: PortRange[], excluded: PortRange[]): PortRange[] {
  const out: PortRange[] = [];
  const ex = mergeRanges(excluded);
  for (const [lo, hi] of mergeRanges(ranges)) {
    let cur = lo;
    for (const [xlo, xhi] of ex) {
      if (xhi < cur || xlo > hi) continue;
      if (xlo > cur) out.push([cur, xlo - 1]);
      cur = Math.max(cur, xhi + 1);
      if (cur > hi) break;
    }
    if (cur <= hi) out.push([cur, hi]);
  }
  return out;
}

export const countPorts = (ranges: PortRange[]) => ranges.reduce((n, [lo, hi]) => n + hi - lo + 1, 0);

export const portsText = (ranges: PortRange[]) => ranges.map(([lo, hi]) => (lo === hi ? `${lo}` : `${lo}-${hi}`)).join(", ");

/** Готовые наборы для поля «Порты». */
export const PORT_PRESETS: { label: string; ports: string }[] = [
  {
    label: "Типовые",
    ports: "21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 3389, 5985, 5986",
  },
  { label: "Веб", ports: "80, 443, 8000-8100, 8443, 8888" },
  { label: "СУБД", ports: "1433, 1521, 3306, 5432, 6379, 27017" },
  { label: "Все 65 535", ports: "1-65535" },
];
