import { useEffect, useState } from "react";
import { Link, Outlet, useLocation } from "react-router-dom";
import { LogOut, Menu, Moon, Radar, ShieldCheck, Sun } from "lucide-react";
import { useAuth } from "../auth/AuthContext";
import { useEngagement } from "../auth/EngagementContext";
import { useTheme } from "../theme/ThemeContext";
import { ROLE_LABEL } from "../lib/labels";
import { HealthChip } from "./HealthChip";
import { QuickSearch } from "./QuickSearch";
import { RunProgressChip } from "./RunProgressChip";
import { SideNav } from "./SideNav";
import { SessionNotice } from "./SessionNotice";
import { SystemHealthProvider } from "../health/SystemHealthContext";

function initials(name: string): string {
  const parts = name.split(/[\s._@-]+/).filter(Boolean);
  return (parts[0]?.[0] ?? "?").toUpperCase() + (parts[1]?.[0] ?? "").toUpperCase();
}

function EngagementPicker() {
  const { engagements, current, select } = useEngagement();
  if (!engagements.length) return null;
  return (
    <label className="inline engagement-picker" style={{ gap: 8 }}>
      {/* подпись «Проект» убрана (выбор Антона): шапка в одну линию; имя поля — для экранных дикторов */}
      <select className="select" aria-label="Проект" value={current?.id ?? ""} onChange={(e) => select(Number(e.target.value))}>
        {engagements.map((e) => (
          <option key={e.id} value={e.id}>
            {e.client ? `${e.client} · ${e.name}` : e.name}
          </option>
        ))}
      </select>
    </label>
  );
}

/** Переключатель светлой и тёмной темы. */
function ThemeToggle() {
  const { theme, toggleTheme } = useTheme();
  return (
    <button
      type="button"
      className="btn btn-sm"
      style={{ width: "100%" }}
      onClick={toggleTheme}
      aria-label={theme === "dark" ? "Включить светлую тему" : "Включить тёмную тему"}
    >
      {theme === "dark" ? <Sun size={15} /> : <Moon size={15} />}
      {theme === "dark" ? "Светлая тема" : "Тёмная тема"}
    </button>
  );
}

function Brand() {
  return (
    <div className="brand">
      <div className="brand-mark" aria-hidden="true">
        <Radar size={18} />
      </div>
      <div style={{ display: "flex", flexDirection: "column" }}>
        <span className="brand-name">Scanner</span>
        <span className="brand-sub">авторизованный аудит</span>
      </div>
    </div>
  );
}

export function Layout() {
  const { has } = useAuth();
  // Лампочка «Состояние» в меню и плашка в шапке берут один общий опрос /system/health.
  return (
    <SystemHealthProvider enabled={has("view_engagements")}>
      <Shell />
    </SystemHealthProvider>
  );
}

function Shell() {
  const { me, has, logout } = useAuth();
  const [open, setOpen] = useState(false);
  const location = useLocation();
  useEffect(() => setOpen(false), [location.pathname]);
  const name = me?.display_name || me?.username || "";
  const roles = me?.roles.map((r) => ROLE_LABEL[r] ?? r).join(", ") || "нет ролей";

  return (
    <div className="shell">
      {open && <div className="scrim" onClick={() => setOpen(false)} />}
      <nav className={`sidebar ${open ? "open" : ""}`} aria-label="Основное меню">
        <Brand />
        <SideNav has={has} />
        <div className="sidebar-foot">
          <div className="user-card">
            <div className="avatar" aria-hidden="true">
              {initials(name)}
            </div>
            <div className="user-meta">
              <span title={name}>{name}</span>
              <span>{roles}</span>
            </div>
            <Link to="/security" className="btn btn-sm btn-ghost icon-btn" style={{ marginLeft: "auto", width: 30 }} aria-label="Безопасность входа" title="Безопасность входа (2FA)">
              <ShieldCheck size={15} />
            </Link>
            <button type="button" className="btn btn-sm btn-ghost icon-btn" style={{ width: 30 }} onClick={logout} aria-label="Выйти" title="Выйти">
              <LogOut size={15} />
            </button>
          </div>
          <ThemeToggle />
        </div>
      </nav>
      <div className="main">
        <header className="topbar">
          <button type="button" className="btn btn-ghost icon-btn menu-btn" aria-label="Меню" onClick={() => setOpen(true)}>
            <Menu size={20} />
          </button>
          <EngagementPicker />
          <QuickSearch />
          <RunProgressChip />
          <span className="spacer" />
          <HealthChip />
          <span className="faint hide-sm" style={{ fontSize: 12 }}>
            Только цели из allowlist проекта
          </span>
        </header>
        <main className="content">
          <SessionNotice />
          <Outlet />
        </main>
      </div>
    </div>
  );
}
