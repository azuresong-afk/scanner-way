const dtf = new Intl.DateTimeFormat("ru-RU", {
  day: "2-digit",
  month: "short",
  hour: "2-digit",
  minute: "2-digit",
});
const dtfFull = new Intl.DateTimeFormat("ru-RU", {
  day: "2-digit",
  month: "2-digit",
  year: "numeric",
  hour: "2-digit",
  minute: "2-digit",
  second: "2-digit",
});

/** API отдаёт naive UTC без зоны — считаем такие строки UTC. */
export function parseDate(s: string | null | undefined): Date | null {
  if (!s) return null;
  const iso = /[zZ]|[+-]\d\d:?\d\d$/.test(s) ? s : `${s}Z`;
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? null : d;
}

export function fmtDate(s: string | null | undefined): string {
  const d = parseDate(s);
  return d ? dtf.format(d) : "—";
}

export function fmtDateFull(s: string | null | undefined): string {
  const d = parseDate(s);
  return d ? dtfFull.format(d) : "—";
}

export function fmtDuration(from: string | null, to: string | null, now = Date.now()): string {
  const a = parseDate(from);
  if (!a) return "—";
  const b = parseDate(to)?.getTime() ?? now;
  let sec = Math.max(0, Math.round((b - a.getTime()) / 1000));
  const h = Math.floor(sec / 3600);
  sec -= h * 3600;
  const m = Math.floor(sec / 60);
  const s = sec - m * 60;
  if (h) return `${h} ч ${m} мин`;
  if (m) return `${m} мин ${s} с`;
  return `${s} с`;
}

export function fmtNumber(n: number): string {
  return n.toLocaleString("ru-RU");
}

export function fmtDelta(n: number): string {
  if (n === 0) return "без изменений";
  return n > 0 ? `+${fmtNumber(n)}` : `−${fmtNumber(Math.abs(n))}`;
}

/** Склонение: plural(5, ["хост", "хоста", "хостов"]). */
export function plural(n: number, forms: [string, string, string]): string {
  const a = Math.abs(n) % 100;
  const b = a % 10;
  if (a > 10 && a < 20) return forms[2];
  if (b > 1 && b < 5) return forms[1];
  if (b === 1) return forms[0];
  return forms[2];
}
