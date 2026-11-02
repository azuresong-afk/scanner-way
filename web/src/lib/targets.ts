// Разбор списка целей из формы запуска: адреса, подсети CIDR, диапазоны
// «начало-конец». Окончательную проверку по allowlist делает API (цели вне allowlist отклоняются, подсети урезаются).

const IPV4 = /^(25[0-5]|2[0-4]\d|1?\d?\d)(\.(25[0-5]|2[0-4]\d|1?\d?\d)){3}$/;

export function isIpOrCidr(s: string): boolean {
  const [addr, mask, ...rest] = s.split("/");
  if (rest.length) return false;
  if (IPV4.test(addr)) return mask === undefined || (/^\d{1,2}$/.test(mask) && Number(mask) <= 32);
  if (addr.includes(":") && /^[0-9a-fA-F:.]+$/.test(addr)) {
    return mask === undefined || (/^\d{1,3}$/.test(mask) && Number(mask) <= 128);
  }
  return false;
}

// ---- адреса как числа (IPv4 и IPv6) ----
export interface Ip {
  v: 4 | 6;
  n: bigint;
}

export function parseIp(s: string): Ip | null {
  if (IPV4.test(s)) {
    return { v: 4, n: s.split(".").reduce((acc, o) => (acc << 8n) | BigInt(Number(o)), 0n) };
  }
  if (!s.includes(":") || !/^[0-9a-fA-F:]+$/.test(s)) return null;
  const parts = s.split("::");
  if (parts.length > 2) return null;
  const head = parts[0] ? parts[0].split(":") : [];
  const tail = parts.length === 2 && parts[1] ? parts[1].split(":") : [];
  const missing = 8 - head.length - tail.length;
  if (parts.length === 1 ? head.length !== 8 : missing < 1) return null;
  const groups = [...head, ...Array(parts.length === 2 ? missing : 0).fill("0"), ...tail];
  if (groups.some((g) => !/^[0-9a-fA-F]{1,4}$/.test(g))) return null;
  return { v: 6, n: groups.reduce((acc, g) => (acc << 16n) | BigInt(parseInt(g, 16)), 0n) };
}

function ipv4ToString(n: bigint): string {
  return [24n, 16n, 8n, 0n].map((sh) => String((n >> sh) & 255n)).join(".");
}

const RANGE = /^([0-9A-Fa-f:.]+)-([0-9A-Fa-f:.]+)$/;

/** Диапазон «10.0.0.1-10.0.0.50» или краткий «10.0.0.1-50» → первый и последний адрес. */
export function parseRange(s: string): { first: Ip; last: Ip } | null {
  const m = RANGE.exec(s.replace(/\s+/g, ""));
  if (!m) return null;
  const first = parseIp(m[1]);
  if (!first) return null;
  let last: Ip | null;
  if (first.v === 4 && /^\d{1,3}$/.test(m[2])) {
    const octet = Number(m[2]);
    last = octet <= 255 ? { v: 4, n: (first.n & ~255n) | BigInt(octet) } : null;
  } else {
    last = parseIp(m[2]);
  }
  if (!last || last.v !== first.v || last.n < first.n) return null;
  return { first, last };
}

/** Адрес, подсеть CIDR или диапазон «начало-конец». */
export function isTargetSpec(s: string): boolean {
  return isIpOrCidr(s) || parseRange(s) !== null;
}

/** Первый и последний адрес записи цели; null — не цель. */
export function specBounds(s: string): { v: 4 | 6; first: bigint; last: bigint } | null {
  const r = parseRange(s);
  if (r) return { v: r.first.v, first: r.first.n, last: r.last.n };
  if (!isIpOrCidr(s)) return null;
  const [addr, mask] = s.split("/");
  const ip = parseIp(addr);
  if (!ip) return null;
  const bits = ip.v === 4 ? 32n : 128n;
  const prefix = mask === undefined ? bits : BigInt(Number(mask));
  const size = 1n << (bits - prefix);
  const first = (ip.n / size) * size;
  return { v: ip.v, first, last: first + size - 1n };
}

/** Сколько адресов в записи цели (для подсказки в форме). */
export function specSize(s: string): number {
  const b = specBounds(s);
  return b ? Number(b.last - b.first + 1n) : 0;
}

/** Адрес входит в одну из подсетей allowlist. */
export function inAllowlist(addr: string, cidrs: string[]): boolean {
  const ip = parseIp(addr);
  if (!ip) return false;
  return cidrs.some((c) => {
    const b = specBounds(c);
    return !!b && b.v === ip.v && ip.n >= b.first && ip.n <= b.last;
  });
}

/** Подряд идущие адреса (от трёх) сворачиваются в диапазон «начало-конец». */
export function compactAddresses(addrs: string[]): string[] {
  const ips = [...new Set(addrs)].map((a) => ({ a, ip: parseIp(a) }));
  const other = ips.filter((x) => !x.ip || x.ip.v === 6).map((x) => x.a);
  const v4 = ips
    .filter((x) => x.ip?.v === 4)
    .map((x) => x.ip!)
    .sort((x, y) => (x.n < y.n ? -1 : x.n > y.n ? 1 : 0));
  const out: string[] = [];
  let i = 0;
  while (i < v4.length) {
    let j = i;
    while (j + 1 < v4.length && v4[j + 1].n === v4[j].n + 1n) j++;
    if (j - i >= 2) out.push(`${ipv4ToString(v4[i].n)}-${ipv4ToString(v4[j].n)}`);
    else for (let k = i; k <= j; k++) out.push(ipv4ToString(v4[k].n));
    i = j + 1;
  }
  return [...out, ...other];
}

/** Разбивает текст на записи целей. Пробелы вокруг «-» в диапазоне допустимы. */
export function splitTargets(text: string): string[] {
  const items = text
    .replace(/\s*-\s*/g, "-")
    .split(/[\s,;]+/)
    .map((t) => t.trim())
    .filter(Boolean);
  return [...new Set(items)];
}

export function parseTargets(text: string): { targets: string[]; invalid: string[] } {
  const uniq = splitTargets(text);
  return { targets: uniq.filter(isTargetSpec), invalid: uniq.filter((t) => !isTargetSpec(t)) };
}

/** Добавляет записи к тексту целей без повторов (порядок прежних строк сохраняется). */
export function mergeTargets(text: string, extra: string[]): string {
  const cur = splitTargets(text);
  const add = extra.filter((t) => !cur.includes(t));
  return [...cur, ...add].join("\n");
}

/** Один адрес (без маски) — для проверки доступности хоста. */
export function isSingleIp(s: string): boolean {
  return !s.includes("/") && isIpOrCidr(s);
}

/** Порты из строки «22, 80 443»: null — если есть мусор или выход за 1..65535. */
export function parsePorts(text: string): number[] | null {
  const items = text.split(/[\s,;]+/).filter(Boolean);
  const ports = items.map(Number);
  if (ports.some((p) => !Number.isInteger(p) || p < 1 || p > 65535)) return null;
  return [...new Set(ports)].sort((a, b) => a - b);
}
