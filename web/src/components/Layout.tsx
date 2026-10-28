import { useEffect, useState, type ReactNode } from "react";
import { NavLink, Outlet, useLocation } from "react-router-dom";
import {
  BarChart3,
  FileText,
  LayoutDashboard,
  ListChecks,
  LogOut,
  Menu,
  Moon,
  PanelLeft,
  PanelTop,
  Radar,
  Server,
  ShieldAlert,
  Sun,
  Users,
} from "lucide-react";
import { useAuth, type Perm } from "../auth/AuthContext";
import { useEngagement } from "../auth/EngagementContext";
import { useAppearance } from "../theme/AppearanceContext";
import { ROLE_LABEL } from "../lib/labels";

interface NavItem {
  to: string;
  label: string;
  short: string;
  icon: ReactNode;
  perm: Perm;
  admin?: boolean;
}

const NAV: NavItem[] = [
  { to: "/", label: "Обзор", short: "Обзор", icon: <LayoutDashboard size={18} />, perm: "view_report" },
  { to: "/engagements", label: "Договоры и allowlist", short: "Договоры", icon: <FileText size={18} />, perm: "view_engagements" },
  { to: "/runs", label: "Прогоны", short: "Прогоны", icon: <Radar size={18} />, perm: "view_report" },
  { to: "/findings", label: "Находки", short: "Находки", icon: <ShieldAlert size={18} />, perm: "view_report" },
  { to: "/hosts", label: "Хосты", short: "Хосты", icon: <Server size={18} />, perm: "view_report" },
  { to: "/reports", label: "Отчёты", short: "Отчёты", icon: <BarChart3 size={18} />, perm: "view_report" },
  { to: "/audit", label: "Журнал аудита", short: "Аудит", icon: <ListChecks size={18} />, perm: "view_audit", admin: true },
  { to: "/users", label: "Пользователи и роли", short: "Пользователи", icon: <Users size={18} />, perm: "manage_users", admin: true },
];

function initials(name: string): string {
  const parts = name.split(/[\s._@-]+/).filter(Boolean);
  return (parts[0]?.[0] ?? "?").toUpperCase() + (parts[1]?.[0] ?? "").toUpperCase();
}

export function EngagementPicker() {
  const { engagements, current, select } = useEngagement();
  if (!engagements.length) return null;
  return (
    <label className="inline engagement-picker" style={{ gap: 8 }}>
      <span className="faint" style={{ fontSize: 13 }}>
        Договор
      </span>
      <select className="select" value={current?.id ?? ""} onChange={(e) => select(Number(e.target.value))}>
        {engagements.map((e) => (
          <option key={e.id} value={e.id}>
            {e.client ? `${e.client} · ${e.name}` : e.name}
          </option>
        ))}
      </select>
    </label>
  );
}

/** Переключатели вида интерфейса и темы. */
export function AppearanceControls({ compact }: { compact?: boolean }) {
  const { layout, setLayout, theme, toggleTheme } = useAppearance();
  return (
    <div className="inline" style={{ gap: 6, flexWrap: "nowrap" }}>
      <div className="segmented" role="group" aria-label="Вид интерфейса">
        <button type="button" aria-pressed={layout === "sidebar"} title="Боковое меню (A+C)" aria-label="Боковое меню" onClick={() => setLayout("sidebar")}>
          <PanelLeft size={15} />
        </button>
        <button type="button" aria-pressed={layout === "topnav"} title="Верхнее меню (B+C)" aria-label="Верхнее меню" onClick={() => setLayout("topnav")}>
          <PanelTop size={15} />
        </button>
      </div>
      <button
        type="button"
        className={`btn btn-sm ${compact ? "icon-btn" : ""}`}
        style={compact ? { width: 32 } : { flex: 1 }}
        onClick={toggleTheme}
        aria-label={theme === "dark" ? "Включить светлую тему" : "Включить тёмную тему"}
        title={theme === "dark" ? "Светлая тема" : "Тёмная тема"}
      >
        {theme === "dark" ? <Sun size={15} /> : <Moon size={15} />}
        {!compact && (theme === "dark" ? "Светлая тема" : "Тёмная тема")}
      </button>
    </div>
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

function useNavItems() {
  const { has } = useAuth();
  return NAV.filter((i) => has(i.perm));
}

function userInfo(me: ReturnType<typeof useAuth>["me"]) {
  const name = me?.display_name || me?.username || "";
  const roles = me?.roles.map((r) => ROLE_LABEL[r] ?? r).join(", ") || "нет ролей";
  return { name, roles };
}

function SidebarShell() {
  const { me, logout } = useAuth();
  const items = useNavItems();
  const [open, setOpen] = useState(false);
  const location = useLocation();
  useEffect(() => setOpen(false), [location.pathname]);
  const { name, roles } = userInfo(me);
  const main = items.filter((i) => !i.admin);
  const admin = items.filter((i) => i.admin);

  return (
    <div className="shell">
      {open && <div className="scrim" onClick={() => setOpen(false)} />}
      <nav className={`sidebar ${open ? "open" : ""}`} aria-label="Основное меню">
        <Brand />
        {main.map((i) => (
          <NavLink key={i.to} to={i.to} end={i.to === "/"} className={({ isActive }) => `nav-link ${isActive ? "active" : ""}`}>
            {i.icon}
            <span>{i.label}</span>
          </NavLink>
        ))}
        {admin.length > 0 && <div className="nav-section">Администрирование</div>}
        {admin.map((i) => (
          <NavLink key={i.to} to={i.to} className={({ isActive }) => `nav-link ${isActive ? "active" : ""}`}>
            {i.icon}
            <span>{i.label}</span>
          </NavLink>
        ))}
        <div className="sidebar-foot">
          <div className="user-card">
            <div className="avatar" aria-hidden="true">
              {initials(name)}
            </div>
            <div className="user-meta">
              <span title={name}>{name}</span>
              <span>{roles}</span>
            </div>
            <button type="button" className="btn btn-sm btn-ghost icon-btn" style={{ marginLeft: "auto", width: 30 }} onClick={logout} aria-label="Выйти" title="Выйти">
              <LogOut size={15} />
            </button>
          </div>
          <AppearanceControls />
        </div>
      </nav>
      <div className="main">
        <header className="topbar">
          <button type="button" className="btn btn-ghost icon-btn menu-btn" aria-label="Меню" onClick={() => setOpen(true)}>
            <Menu size={20} />
          </button>
          <EngagementPicker />
          <span className="spacer" />
          <span className="faint hide-sm" style={{ fontSize: 12 }}>
            Только цели из allowlist договора
          </span>
        </header>
        <main className="content">
          <Outlet />
        </main>
      </div>
    </div>
  );
}

function TopNavShell() {
  const { me, logout } = useAuth();
  const items = useNavItems();
  const { name, roles } = userInfo(me);
  return (
    <div className="topnav-shell">
      <header className="topnav">
        <div className="topnav-inner">
          <Brand />
          <nav className="topnav-links" aria-label="Основное меню">
            {items.map((i) => (
              <NavLink key={i.to} to={i.to} end={i.to === "/"} className={({ isActive }) => `topnav-link ${isActive ? "active" : ""}`}>
                {i.short}
              </NavLink>
            ))}
          </nav>
          <div className="inline" style={{ gap: 10, flexWrap: "nowrap", marginLeft: "auto" }}>
            <AppearanceControls compact />
            <div className="avatar" title={`${name} · ${roles}`} aria-label={`${name}, ${roles}`}>
              {initials(name)}
            </div>
            <button type="button" className="btn btn-sm btn-ghost icon-btn" style={{ width: 32 }} onClick={logout} aria-label="Выйти" title="Выйти">
              <LogOut size={15} />
            </button>
          </div>
        </div>
      </header>
      <div className="subbar">
        <div className="subbar-inner">
          <EngagementPicker />
          <span className="spacer" />
          <span className="faint hide-sm" style={{ fontSize: 12 }}>
            Только цели из allowlist договора
          </span>
        </div>
      </div>
      <main className="content content-centered">
        <Outlet />
      </main>
    </div>
  );
}

export function Layout() {
  const { layout } = useAppearance();
  return layout === "topnav" ? <TopNavShell /> : <SidebarShell />;
}
