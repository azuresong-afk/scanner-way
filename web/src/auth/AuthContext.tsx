import { createContext, useCallback, useContext, useEffect, useMemo, useState, type ReactNode } from "react";
import { api, getToken, setToken, setUnauthorizedHandler } from "../api/client";
import type { AuthConfigOut, MeOut, TokenOut } from "../api/types";

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
  | "triage_findings";

interface AuthValue {
  me: MeOut | null;
  ready: boolean;
  /** Способы входа на сервере: вход через домен (LDAP/AD) и режим 2FA. */
  config: AuthConfigOut;
  /** Пароль. Если нужна 2FA — возвращает второй шаг (mfa_token), иначе входит сразу. */
  login: (username: string, password: string) => Promise<TokenOut>;
  /** Завершить вход готовым токеном доступа (после кода 2FA). */
  acceptToken: (accessToken: string) => Promise<void>;
  logout: () => void;
  has: (perm: Perm) => boolean;
}

const AuthContext = createContext<AuthValue | null>(null);

export function AuthProvider({ children }: { children: ReactNode }) {
  const [me, setMe] = useState<MeOut | null>(null);
  const [ready, setReady] = useState(false);
  const [config, setConfig] = useState<AuthConfigOut>({ ldap: false, mfa: "off" });

  useEffect(() => {
    // старый сервер без /auth/config — просто локальный вход без 2FA
    api.authConfig().then(setConfig).catch(() => undefined);
  }, []);

  const logout = useCallback(() => {
    setToken(null);
    setMe(null);
  }, []);

  useEffect(() => {
    setUnauthorizedHandler(() => setMe(null));
    if (!getToken()) {
      setReady(true);
      return () => setUnauthorizedHandler(null);
    }
    api
      .me()
      .then(setMe)
      .catch(() => setToken(null))
      .finally(() => setReady(true));
    return () => setUnauthorizedHandler(null);
  }, []);

  const acceptToken = useCallback(async (accessToken: string) => {
    setToken(accessToken);
    try {
      setMe(await api.me());
    } catch (e) {
      setToken(null);
      throw e;
    }
  }, []);

  const login = useCallback(
    async (username: string, password: string) => {
      const t = await api.login(username, password);
      if (t.access_token) await acceptToken(t.access_token);
      return t;
    },
    [acceptToken],
  );

  const value = useMemo<AuthValue>(
    () => ({
      me,
      ready,
      config,
      login,
      acceptToken,
      logout,
      has: (perm) => !!me?.permissions.includes(perm),
    }),
    [me, ready, config, login, acceptToken, logout],
  );

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth(): AuthValue {
  const v = useContext(AuthContext);
  if (!v) throw new Error("useAuth outside AuthProvider");
  return v;
}
