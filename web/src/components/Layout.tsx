import { useEffect, useState, type ReactNode } from "react";
import { NavLink, Outlet, useLocation } from "react-router-dom";
import {
  BarChart3,
  Boxes,
  CalendarClock,
  ClipboardCheck,
  Database,
  FileText,
  LayoutDashboard,
  ListChecks,
  LogOut,
  Menu,
  Moon,
  Radar,
  Server,
  ShieldAlert,
  Sun,
  Users,
} from "lucide-react";
import { useAuth, type Perm } from "../auth/AuthContext";
import { useEngagement } from "../auth/EngagementContext";
import { useTheme } from "../theme/ThemeContext";
import { ROLE_LABEL } from "../lib/labels";

interface NavItem {
  to: string;
  label: string;
  icon: ReactNode;
  perm: Perm;
  admin?: boolean;
}

const NAV: NavItem[] = [
  { to: "/", label: "Сводка", icon: <LayoutDashboard size={18} />, perm: "view_report" },
  { to: "/engagements", label: "Договоры и allowlist", icon: <FileText size={18} />, perm: "view_engagements" },
  { to: "/assets", label: "Активы", icon: <Boxes size={18} />, perm: "view_engagements" },
  { to: "/runs", label: "Прогоны", icon: <Radar size={18} />, perm: "view_report" },
  { to: "/schedules", label: "Расписания", icon: <CalendarClock size={18} />, perm: "view_report" },
  { to: "/findings", label: "Находки", icon: <ShieldAlert size={18} />, perm: "view_report" },
  { to: "/hosts", label: "Хосты", icon: <Server size={18} />, perm: "view_report" },
  { to: "/compliance", label: "Соответствие", icon: <ClipboardCheck size={18} />, perm: "view_report" },
  { to: "/reports", label: "Отчёты", icon: <BarChart3 size={18} />, perm: "view_report" },
  { to: "/feeds", label: "Справочники", icon: <Database size={18} />, perm: "view_engagements", admin: true },
  { to: "/audit", label: "Журнал аудита", icon: <ListChecks size={18} />, perm: "view_audit", admin: true },
  { to: "/users", label: "Пользователи и роли", icon: <Users size={18} />, perm: "manage_users", admin: true },
];

function initials(name: string): string {
  const parts = name.split(/[\s._@-]+/).filter(Boolean);
  return (parts[0]?.[0] ?? "?").toUpperCase() + (parts[1]?.[0] ?? "").toUpperCase();
}

function EngagementPicker() {
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
  const { me, has, logout } = useAuth();
  const items = NAV.filter((i) => has(i.perm));
  const [open, setOpen] = useState(false);
  const location = useLocation();
  useEffect(() => setOpen(false), [location.pathname]);
  const name = me?.display_name || me?.username || "";
  const roles = me?.roles.map((r) => ROLE_LABEL[r] ?? r).join(", ") || "нет ролей";
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
          <ThemeToggle />
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
