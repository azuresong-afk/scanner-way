// Разбор списка целей из формы запуска. Окончательную проверку по allowlist
// делает API (цели вне allowlist отклоняются, подсети урезаются).

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

export function parseTargets(text: string): { targets: string[]; invalid: string[] } {
  const items = text
    .split(/[\s,;]+/)
    .map((t) => t.trim())
    .filter(Boolean);
  const uniq = [...new Set(items)];
  return { targets: uniq.filter(isIpOrCidr), invalid: uniq.filter((t) => !isIpOrCidr(t)) };
}
