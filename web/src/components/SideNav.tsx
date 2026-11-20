import type { ReactNode } from "react";
import { Link, NavLink, useLocation } from "react-router-dom";
import {
  Activity,
  BarChart3,
  Bell,
  CalendarClock,
  ChevronDown,
  ChevronRight,
  ClipboardCheck,
  Database,
  FileText,
  KeyRound,
  LayoutDashboard,
  ListChecks,
  Network,
  Radar,
  Server,
  Settings,
  ShieldAlert,
  Users,
  Wifi,
} from "lucide-react";
import type { Perm } from "../auth/AuthContext";
import { useSystemHealth, type ServiceState } from "../health/SystemHealthContext";

// Боковое меню «Короткий список» (выбор Антона, 20.11.2026): восемь рабочих пунктов по ходу
// работы, внизу «Настройка» и под ней «Состояние» с лампочкой сервиса. Пункт, который объединяет
// несколько страниц («Сканирование», «Настройка»), раскрывает подпункты прямо в меню, пока открыта
// одна из его страниц. URL прежние (/runs, /reachability, /schedules …), закладки не ломаются.

interface Page {
  to: string;
  label: string;
  icon: ReactNode;
  /** Страница видна, если есть хотя бы одно из прав. */
  perm: Perm | Perm[];
}

const page = (to: string, label: string, icon: ReactNode, perm: Perm | Perm[]): Page => ({ to, label, icon, perm });

const P = {
  summary: page("/", "Сводка", <LayoutDashboard size={18} />, "view_report"),
  projects: page("/engagements", "Проекты", <FileText size={18} />, "view_engagements"),
  assets: page("/hosts", "Активы", <Server size={18} />, "view_report"),
  creds: page("/credentials", "Учётные записи", <KeyRound size={18} />, ["host_credentials", "cred_audit"]),
  runs: page("/runs", "Прогоны", <Radar size={18} />, "view_report"),
  reach: page("/reachability", "Сетевой поиск", <Wifi size={18} />, "view_report"),
  sched: page("/schedules", "Расписание", <CalendarClock size={18} />, "view_report"),
  findings: page("/findings", "Находки", <ShieldAlert size={18} />, "view_report"),
  compl: page("/compliance", "Нормативы", <ClipboardCheck size={18} />, "view_report"),
  reports: page("/reports", "Отчёты", <BarChart3 size={18} />, "view_report"),
  feeds: page("/feeds", "Справочники", <Database size={18} />, "view_engagements"),
  nodes: page("/nodes", "Сканеры", <Network size={18} />, "view_engagements"),
  notify: page("/integrations", "Уведомления", <Bell size={18} />, "view_engagements"),
  audit: page("/audit", "Журнал аудита", <ListChecks size={18} />, "view_audit"),
  users: page("/users", "Пользователи и роли", <Users size={18} />, "manage_users"),
  health: page("/health", "Состояние", <Activity size={18} />, "view_engagements"),
};

/** Пункт меню: одна страница или группа страниц с подпунктами. */
interface Item {
  label: string;
  icon: ReactNode;
  pages: Page[];
  /** Вместо значка — лампочка состояния сервиса. */
  lamp?: boolean;
}

const one = (p: Page, over: Partial<Item> = {}): Item => ({ label: p.label, icon: p.icon, pages: [p], ...over });
const group = (label: string, icon: ReactNode, pages: Page[]): Item => ({ label, icon, pages });

const MAIN: Item[] = [
  one(P.summary),
  one(P.projects),
  one(P.assets),
  one(P.creds),
  group("Сканирование", <Radar size={18} />, [P.runs, P.reach, P.sched]),
  one(P.findings),
  one(P.compl),
  one(P.reports),
];

const BOTTOM: Item[] = [group("Настройка", <Settings size={18} />, [P.feeds, P.nodes, P.notify, P.audit, P.users]), one(P.health, { lamp: true })];

const SERVICE_LABEL: Record<ServiceState, string> = { on: "Активен", off: "Не активен", unknown: "Проверка…" };

type Has = (p: Perm) => boolean;

const allowed = (p: Page, has: Has) => (Array.isArray(p.perm) ? p.perm : [p.perm]).some(has);
const isOn = (path: string, to: string) => (to === "/" ? path === "/" : path === to || path.startsWith(`${to}/`));

/** Оставляет страницы, доступные по правам; пункт без доступных страниц скрывается. */
function visible(items: Item[], has: Has): Item[] {
  return items.flatMap((it) => {
    const pages = it.pages.filter((p) => allowed(p, has));
    if (!pages.length) return [];
    // из группы доступна одна страница — показываем её саму, а не группу из одного подпункта
    if (it.pages.length > 1 && pages.length === 1) return [one(pages[0])];
    return [{ ...it, pages }];
  });
}

function PageLink({ it, path, service }: { it: Item; path: string; service: ServiceState }) {
  const p = it.pages[0];
  const active = isOn(path, p.to);
  if (it.lamp) {
    const title = `${it.label}: сервис ${SERVICE_LABEL[service].toLowerCase()}`;
    return (
      <NavLink to={p.to} className={`nav-link ${active ? "active" : ""}`} title={title} aria-label={title}>
        <span className="nav-ic">
          <span className={`lamp ${service}`} aria-hidden="true" />
        </span>
        <span>{it.label}</span>
        <span className={`nav-state ${service}`} aria-hidden="true">
          {SERVICE_LABEL[service]}
        </span>
      </NavLink>
    );
  }
  return (
    <NavLink to={p.to} end={p.to === "/"} className={`nav-link ${active ? "active" : ""}`}>
      <span className="nav-ic">{it.icon}</span>
      <span>{it.label}</span>
    </NavLink>
  );
}

/** Пункт с несколькими страницами: ведёт на первую из них и раскрывает подпункты, пока открыта любая. */
function GroupLink({ it, path }: { it: Item; path: string }) {
  const open = it.pages.some((p) => isOn(path, p.to));
  return (
    <>
      <Link to={it.pages[0].to} className={`nav-link nav-parent ${open ? "open" : ""}`} aria-expanded={open}>
        <span className="nav-ic">{it.icon}</span>
        <span>{it.label}</span>
        <span className="nav-chev" aria-hidden="true">
          {open ? <ChevronDown size={13} /> : <ChevronRight size={13} />}
        </span>
      </Link>
      {open && (
        <div className="nav-sub" role="group" aria-label={it.label}>
          {it.pages.map((p) => (
            <NavLink key={p.to} to={p.to} className={`nav-link sub-link ${isOn(path, p.to) ? "active" : ""}`}>
              {p.label}
            </NavLink>
          ))}
        </div>
      )}
    </>
  );
}

export function SideNav({ has }: { has: Has }) {
  const { pathname } = useLocation();
  const { service } = useSystemHealth();
  const render = (it: Item) =>
    it.pages.length > 1 ? <GroupLink key={it.label} it={it} path={pathname} /> : <PageLink key={it.label} it={it} path={pathname} service={service} />;
  const main = visible(MAIN, has);
  const bottom = visible(BOTTOM, has);
  return (
    <div className="nav-body">
      <div className="nav-group">{main.map(render)}</div>
      {bottom.length > 0 && <div className="nav-group nav-bottom">{bottom.map(render)}</div>}
    </div>
  );
}
