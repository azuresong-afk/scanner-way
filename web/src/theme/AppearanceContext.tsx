import { createContext, useCallback, useContext, useEffect, useMemo, useState, type ReactNode } from "react";

export type Theme = "dark" | "light";
/** sidebar — вариант «A+C» (боковое меню, плотный дашборд); topnav — «B+C» (верхнее меню, просторные блоки). */
export type LayoutKind = "sidebar" | "topnav";

const LAYOUT_KEY = "scanner.layout";
const themeKey = (l: LayoutKind) => `scanner.theme.${l}`;
const DEFAULT_THEME: Record<LayoutKind, Theme> = { sidebar: "dark", topnav: "light" };

function read(key: string): string | null {
  try {
    return localStorage.getItem(key);
  } catch {
    return null;
  }
}

function write(key: string, value: string) {
  try {
    localStorage.setItem(key, value);
  } catch {
    /* хранилище недоступно — настройка живёт до перезагрузки */
  }
}

function savedTheme(layout: LayoutKind): Theme {
  const v = read(themeKey(layout));
  return v === "dark" || v === "light" ? v : DEFAULT_THEME[layout];
}

interface AppearanceValue {
  layout: LayoutKind;
  theme: Theme;
  setLayout: (l: LayoutKind) => void;
  toggleTheme: () => void;
}

const Ctx = createContext<AppearanceValue>({ layout: "sidebar", theme: "dark", setLayout: () => {}, toggleTheme: () => {} });

/** Вид интерфейса и тема; тема запоминается отдельно для каждого вида. */
export function AppearanceProvider({ children }: { children: ReactNode }) {
  const [layout, setLayoutState] = useState<LayoutKind>(() => (read(LAYOUT_KEY) === "topnav" ? "topnav" : "sidebar"));
  const [theme, setTheme] = useState<Theme>(() => savedTheme(layout));

  useEffect(() => {
    document.documentElement.dataset.theme = theme;
    document.documentElement.dataset.layout = layout;
  }, [theme, layout]);

  const setLayout = useCallback((l: LayoutKind) => {
    write(LAYOUT_KEY, l);
    setLayoutState(l);
    setTheme(savedTheme(l));
  }, []);

  const toggleTheme = useCallback(() => {
    setTheme((t) => {
      const next = t === "dark" ? "light" : "dark";
      write(themeKey(layout), next);
      return next;
    });
  }, [layout]);

  const value = useMemo(() => ({ layout, theme, setLayout, toggleTheme }), [layout, theme, setLayout, toggleTheme]);
  return <Ctx.Provider value={value}>{children}</Ctx.Provider>;
}

export const useAppearance = () => useContext(Ctx);
