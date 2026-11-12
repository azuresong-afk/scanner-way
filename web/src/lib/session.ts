// Продление входа: пока пользователь что-то делает, токен продлевается
// (POST /auth/refresh); отошёл — токен доживает свой срок, и нужен новый вход.
// Фоновые запросы (опрос прогресса прогона) активностью не считаются.

/** Предупреждать о выходе по бездействию за столько до конца токена. */
export const WARN_MS = 5 * 60_000;

export interface TokenClock {
  /** Локальное время выдачи токена, мс. */
  issuedAt: number;
  /** Локальное время окончания токена, мс. */
  expiresAt: number;
  /** Предельный срок сеанса (дальше не продлить), мс; null — без предела. */
  sessionEndsAt: number | null;
}

export type SessionStep =
  | { kind: "ok" }
  | { kind: "refresh" }
  /** Скоро выход: по бездействию (можно продлить) или по пределу сеанса (нельзя). */
  | { kind: "warn"; leftMs: number; final: boolean }
  | { kind: "expired" };

/** Можно ли ещё продлить токен: его срок не упёрся в предел сеанса. */
export function canExtend(c: TokenClock): boolean {
  return c.sessionEndsAt === null || c.expiresAt < c.sessionEndsAt - 1000;
}

export function sessionStep(c: TokenClock, now: number, lastActivity: number): SessionStep {
  const left = c.expiresAt - now;
  if (left <= 0) return { kind: "expired" };
  const ttl = Math.max(1, c.expiresAt - c.issuedAt);
  const extend = canExtend(c);
  // работал после выдачи токена и прошла половина срока — продлеваем
  if (extend && lastActivity > c.issuedAt && left <= ttl / 2) return { kind: "refresh" };
  const warnAt = Math.min(WARN_MS, ttl / 4);
  if (left <= warnAt) return { kind: "warn", leftMs: left, final: !extend };
  return { kind: "ok" };
}

/** Короткое имя браузера и ОС из User-Agent — чтобы узнать свой вход. */
export function deviceLabel(ua: string | null): string {
  if (!ua) return "Неизвестное устройство";
  const browser = /Edg\//.test(ua)
    ? "Edge"
    : /YaBrowser\//.test(ua)
      ? "Яндекс Браузер"
      : /Firefox\//.test(ua)
        ? "Firefox"
        : /Chrome\//.test(ua)
          ? "Chrome"
          : /Safari\//.test(ua)
            ? "Safari"
            : null;
  const os = /Windows/.test(ua)
    ? "Windows"
    : /Android/.test(ua)
      ? "Android"
      : /iPhone|iPad/.test(ua)
        ? "iOS"
        : /Mac OS X/.test(ua)
          ? "macOS"
          : /Linux/.test(ua)
            ? "Linux"
            : null;
  if (!browser && !os) return ua.slice(0, 60);
  return [browser, os].filter(Boolean).join(", ");
}
