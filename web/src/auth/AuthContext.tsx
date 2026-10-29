import { createContext, useCallback, useContext, useEffect, useMemo, useState, type ReactNode } from "react";
import { api, getToken, setToken, setUnauthorizedHandler } from "../api/client";
import type { MeOut } from "../api/types";

export type Perm =
  | "manage_users"
  | "manage_engagements"
  | "manage_allowlist"
  | "view_engagements"
  | "run_scan"
  | "view_report"
  | "view_audit"
  | "cred_audit"
  | "host_credentials";

interface AuthValue {
  me: MeOut | null;
  ready: boolean;
  login: (username: string, password: string) => Promise<void>;
  logout: () => void;
  has: (perm: Perm) => boolean;
}

const AuthContext = createContext<AuthValue | null>(null);

export function AuthProvider({ children }: { children: ReactNode }) {
  const [me, setMe] = useState<MeOut | null>(null);
  const [ready, setReady] = useState(false);

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

  const login = useCallback(async (username: string, password: string) => {
    const t = await api.login(username, password);
    setToken(t.access_token);
    try {
      setMe(await api.me());
    } catch (e) {
      setToken(null);
      throw e;
    }
  }, []);

  const value = useMemo<AuthValue>(
    () => ({
      me,
      ready,
      login,
      logout,
      has: (perm) => !!me?.permissions.includes(perm),
    }),
    [me, ready, login, logout],
  );

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth(): AuthValue {
  const v = useContext(AuthContext);
  if (!v) throw new Error("useAuth outside AuthProvider");
  return v;
}
