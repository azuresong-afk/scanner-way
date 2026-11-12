import { createContext, useCallback, useContext, useEffect, useMemo, useRef, useState, type ReactNode } from "react";
import { api, getToken, setToken, setUnauthorizedHandler, tokenTimes } from "../api/client";
import type { MeOut, TokenOut } from "../api/types";
import { sessionStep, type SessionStep, type TokenClock } from "../lib/session";

export type Perm =
  | "manage_users"
  | "manage_engagements"
  | "manage_allowlist"
  | "view_engagements"
  | "run_scan"
  | "view_report"
  | "view_audit"
  | "cred_audit"
  | "host_credentials"
  | "triage_findings"
  | "manage_nodes";

interface AuthValue {
  me: MeOut | null;
  ready: boolean;
  /** Пароль. Если нужна 2FA — возвращает второй шаг (mfa_token), иначе входит сразу. */
  login: (username: string, password: string) => Promise<TokenOut>;
  /** Завершить вход готовым токеном доступа (после кода 2FA). */
  acceptToken: (accessToken: string, info?: TokenOut) => Promise<void>;
  /** Выход: сеанс закрывается на сервере, токен больше не действует. */
  logout: () => void;
  has: (perm: Perm) => boolean;
  /** Состояние сеанса для предупреждения о скором выходе. */
  session: SessionStep;
  /** «Продолжить работу» — продлить вход сейчас. */
  extend: () => Promise<void>;
}

const AuthContext = createContext<AuthValue | null>(null);

const TICK_MS = 15_000;
const ACTIVITY_EVENTS = ["pointerdown", "keydown", "wheel", "touchstart"] as const;

function clockOf(t: TokenOut | undefined, token: string): TokenClock | null {
  const now = Date.now();
  let ttl = t?.expires_in;
  if (ttl === undefined) {
    // токен из хранилища вкладки: срок — из него же (часы сервера ≈ наши)
    const times = tokenTimes(token);
    if (!times) return null;
    ttl = times.exp - Math.floor(now / 1000);
  }
  const ends = t?.session_expires_at ? Date.parse(t.session_expires_at) : null;
  return { issuedAt: now, expiresAt: now + ttl * 1000, sessionEndsAt: Number.isFinite(ends) ? ends : null };
}

export function AuthProvider({ children }: { children: ReactNode }) {
  const [me, setMe] = useState<MeOut | null>(null);
  const [ready, setReady] = useState(false);
  const [session, setSession] = useState<SessionStep>({ kind: "ok" });
  const clock = useRef<TokenClock | null>(null);
  const activity = useRef(0);
  const refreshing = useRef(false);

  const clear = useCallback(() => {
    clock.current = null;
    setToken(null);
    setMe(null);
    setSession({ kind: "ok" });
  }, []);

  const logout = useCallback(() => {
    // сервер отзывает сеанс; сбой сети не мешает выйти в этой вкладке
    if (getToken()) void api.logout().catch(() => undefined);
    clear();
  }, [clear]);

  const refresh = useCallback(async () => {
    if (refreshing.current || !getToken()) return;
    refreshing.current = true;
    try {
      const t = await api.refresh();
      if (t.access_token) {
        setToken(t.access_token);
        clock.current = clockOf(t, t.access_token);
        setSession({ kind: "ok" });
      }
    } catch {
      /* 401 уже вывел на страницу входа; сеть — попробуем на следующем такте */
    } finally {
      refreshing.current = false;
    }
  }, []);

  const tick = useCallback(() => {
    const c = clock.current;
    if (!c || !getToken()) return;
    const step = sessionStep(c, Date.now(), activity.current);
    if (step.kind === "expired") clear();
    else if (step.kind === "refresh") void refresh();
    else setSession(step);
  }, [clear, refresh]);

  useEffect(() => {
    const mark = () => {
      activity.current = Date.now();
    };
    for (const ev of ACTIVITY_EVENTS) window.addEventListener(ev, mark, { passive: true });
    const id = window.setInterval(tick, TICK_MS);
    const onVisible = () => document.visibilityState === "visible" && tick();
    document.addEventListener("visibilitychange", onVisible);
    return () => {
      for (const ev of ACTIVITY_EVENTS) window.removeEventListener(ev, mark);
      window.clearInterval(id);
      document.removeEventListener("visibilitychange", onVisible);
    };
  }, [tick]);

  useEffect(() => {
    setUnauthorizedHandler(() => {
      clock.current = null;
      setMe(null);
      setSession({ kind: "ok" });
    });
    const stored = getToken();
    if (!stored) {
      setReady(true);
      return () => setUnauthorizedHandler(null);
    }
    clock.current = clockOf(undefined, stored);
    api
      .me()
      .then((m) => {
        setMe(m);
        // перезагрузка вкладки — тоже работа: сразу продлеваем и узнаём предел сеанса
        if (clock.current) {
          activity.current = Date.now();
          void refresh();
        }
      })
      .catch(() => {
        clock.current = null;
        setToken(null);
      })
      .finally(() => setReady(true));
    return () => setUnauthorizedHandler(null);
  }, [refresh]);

  const acceptToken = useCallback(async (accessToken: string, info?: TokenOut) => {
    setToken(accessToken);
    try {
      setMe(await api.me());
      clock.current = clockOf(info, accessToken);
      setSession({ kind: "ok" });
    } catch (e) {
      clock.current = null;
      setToken(null);
      throw e;
    }
  }, []);

  const login = useCallback(
    async (username: string, password: string) => {
      const t = await api.login(username, password);
      if (t.access_token) await acceptToken(t.access_token, t);
      return t;
    },
    [acceptToken],
  );

  const extend = useCallback(async () => {
    activity.current = Date.now();
    await refresh();
  }, [refresh]);

  const value = useMemo<AuthValue>(
    () => ({
      me,
      ready,
      login,
      acceptToken,
      logout,
      has: (perm) => !!me?.permissions.includes(perm),
      session,
      extend,
    }),
    [me, ready, login, acceptToken, logout, session, extend],
  );

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth(): AuthValue {
  const v = useContext(AuthContext);
  if (!v) throw new Error("useAuth outside AuthProvider");
  return v;
}
