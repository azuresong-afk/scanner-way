// Макеты меню для утверждения (предложение В4 разбора продукта). Вариант выбирается
// ключом localStorage «scanner.menu» (now | v1 | v2 | v3 | v4); по умолчанию — текущее меню.
// Страницы и URL не меняются: варианты только по-разному группируют пункты и
// показывают вкладки раздела над страницей, если раздел объединяет несколько страниц.
import { useState, type ReactNode } from "react";
import { NavLink, useLocation } from "react-router-dom";
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

export type MenuVariant = "now" | "v1" | "v2" | "v3" | "v4";

export function menuVariant(): MenuVariant {
  try {
    const v = localStorage.getItem("scanner.menu");
    if (v === "v1" || v === "v2" || v === "v3" || v === "v4") return v;
  } catch {
    /* хранилище недоступно */
  }
  return "now";
}

interface Page {
  to: string;
  label: string;
  icon: (size: number) => ReactNode;
  perm: Perm | Perm[];
}

const P: Record<string, Page> = {
  summary: { to: "/", label: "Сводка", icon: (s) => <LayoutDashboard size={s} />, perm: "view_report" },
  projects: { to: "/engagements", label: "Проекты", icon: (s) => <FileText size={s} />, perm: "view_engagements" },
  assets: { to: "/hosts", label: "Активы", icon: (s) => <Server size={s} />, perm: "view_report" },
  creds: { to: "/credentials", label: "Учётные записи", icon: (s) => <KeyRound size={s} />, perm: ["host_credentials", "cred_audit"] },
  findings: { to: "/findings", label: "Находки", icon: (s) => <ShieldAlert size={s} />, perm: "view_report" },
  reach: { to: "/reachability", label: "Сетевой поиск", icon: (s) => <Wifi size={s} />, perm: "view_report" },
  runs: { to: "/runs", label: "Сканирование", icon: (s) => <Radar size={s} />, perm: "view_report" },
  sched: { to: "/schedules", label: "Расписание", icon: (s) => <CalendarClock size={s} />, perm: "view_report" },
  compl: { to: "/compliance", label: "Соответствие нормативам", icon: (s) => <ClipboardCheck size={s} />, perm: "view_report" },
  reports: { to: "/reports", label: "Отчёты", icon: (s) => <BarChart3 size={s} />, perm: "view_report" },
  feeds: { to: "/feeds", label: "Справочники", icon: (s) => <Database size={s} />, perm: "view_engagements" },
  nodes: { to: "/nodes", label: "Сканеры", icon: (s) => <Network size={s} />, perm: "view_engagements" },
  notify: { to: "/integrations", label: "Уведомления", icon: (s) => <Bell size={s} />, perm: "view_engagements" },
  health: { to: "/health", label: "Состояние", icon: (s) => <Activity size={s} />, perm: "view_engagements" },
  audit: { to: "/audit", label: "Журнал аудита", icon: (s) => <ListChecks size={s} />, perm: "view_audit" },
  users: { to: "/users", label: "Пользователи и роли", icon: (s) => <Users size={s} />, perm: "manage_users" },
};

const ADMIN = [P.feeds, P.nodes, P.notify, P.health, P.audit, P.users];

/** Пункт меню, объединяющий несколько страниц: вкладки показываются над страницей. */
interface Item {
  label: string;
  icon: (size: number) => ReactNode;
  pages: Page[];
  /** Короткая подпись для узкой панели. */
  short?: string;
  /** Подписи вкладок, если они отличаются от названий страниц. */
  tabLabels?: Record<string, string>;
}

const one = (p: Page, short?: string): Item => ({ label: p.label, icon: p.icon, pages: [p], short });

const SCAN: Item = {
  label: "Сканирование",
  short: "Скан",
  icon: P.runs.icon,
  pages: [P.runs, P.reach, P.sched],
  tabLabels: { "/runs": "Прогоны" },
};
const ASSETS: Item = {
  label: "Активы",
  icon: P.assets.icon,
  pages: [P.assets, P.creds],
  tabLabels: { "/hosts": "Список активов" },
};
const SETTINGS: Item = { label: "Настройка", short: "Настройка", icon: (s) => <Settings size={s} />, pages: ADMIN };

type Has = (p: Perm) => boolean;
const allowed = (p: Page, has: Has) => (Array.isArray(p.perm) ? p.perm : [p.perm]).some(has);
const visible = (it: Item, has: Has): Item | null => {
  const pages = it.pages.filter((p) => allowed(p, has));
  return pages.length ? { ...it, pages } : null;
};
const isOn = (path: string, to: string) => (to === "/" ? path === "/" : path === to || path.startsWith(`${to}/`));
const itemActive = (it: Item, path: string) => it.pages.some((p) => isOn(path, p.to));

/** Структура меню для каждого варианта. */
interface Section {
  title?: string;
  /** Номер шага (вариант «Шаги работы»). */
  step?: number;
  items: Item[];
  collapsible?: boolean;
}

function structure(v: MenuVariant): { top: Section[]; bottom?: Item } {
  switch (v) {
    case "v1":
      return {
        top: [
          { items: [one(P.summary)] },
          { title: "Проверки", items: [one(P.assets), one(P.creds), SCAN] },
          { title: "Результаты", items: [one(P.findings), { ...one(P.compl), label: "Нормативы" }, one(P.reports)] },
          { title: "Настройка", collapsible: true, items: [one(P.projects), ...ADMIN.map((p) => one(p))] },
        ],
      };
    case "v2":
    case "v3":
      return {
        top: [
          {
            items: [
              one(P.summary),
              one(P.projects),
              ASSETS,
              SCAN,
              one(P.findings),
              { ...one(P.compl), label: "Нормативы", short: "Нормативы" },
              one(P.reports),
            ],
          },
        ],
        bottom: SETTINGS,
      };
    case "v4":
      return {
        top: [
          { items: [one(P.summary)] },
          { title: "Подготовка", step: 1, items: [one(P.projects), one(P.assets), one(P.creds)] },
          { title: "Проверка", step: 2, items: [one(P.reach), one(P.runs), one(P.sched)] },
          { title: "Результаты", step: 3, items: [one(P.findings), { ...one(P.compl), label: "Нормативы" }, one(P.reports)] },
        ],
        bottom: SETTINGS,
      };
    default:
      return { top: [] };
  }
}

function ItemLink({ it, path, rail }: { it: Item; path: string; rail?: boolean }) {
  const first = it.pages[0];
  const active = itemActive(it, path);
  return (
    <NavLink
      to={first.to}
      end={first.to === "/"}
      className={() => `nav-link ${rail ? "rail-link" : ""} ${active ? "active" : ""}`}
      title={rail ? it.label : undefined}
    >
      {it.icon(rail ? 20 : 18)}
      <span>{rail ? it.short ?? it.label : it.label}</span>
    </NavLink>
  );
}

/** Боковое меню выбранного варианта (кроме «now» — его рисует Layout). */
export function VariantNav({ variant, has }: { variant: MenuVariant; has: Has }) {
  const { pathname } = useLocation();
  const { top, bottom } = structure(variant);
  const sections = top
    .map((s) => ({ ...s, items: s.items.map((i) => visible(i, has)).filter((i): i is Item => !!i) }))
    .filter((s) => s.items.length);
  const bottomItem = bottom ? visible(bottom, has) : null;
  const activeStep = sections.find((s) => s.step && s.items.some((i) => itemActive(i, pathname)))?.step;
  const [openSteps, setOpenSteps] = useState<Record<number, boolean>>({});
  const adminActive = sections.some((s) => s.collapsible && s.items.some((i) => itemActive(i, pathname)));
  const [adminOpen, setAdminOpen] = useState(false);
  const rail = variant === "v3";

  return (
    <>
      {sections.map((s, idx) => {
        if (s.step) {
          const open = openSteps[s.step] ?? s.step === activeStep;
          return (
            <div key={idx} className={`nav-step ${s.step === activeStep ? "current" : ""}`}>
              <button type="button" className="nav-step-head" aria-expanded={open} onClick={() => setOpenSteps({ ...openSteps, [s.step!]: !open })}>
                <span className="step-num">{s.step}</span>
                <span>{s.title}</span>
                {open ? <ChevronDown size={15} /> : <ChevronRight size={15} />}
              </button>
              {open && (
                <div className="nav-step-items">
                  {s.items.map((i) => (
                    <ItemLink key={i.label} it={i} path={pathname} />
                  ))}
                </div>
              )}
            </div>
          );
        }
        if (s.collapsible) {
          const open = adminOpen || adminActive;
          return (
            <div key={idx}>
              <button type="button" className="nav-section nav-section-btn" aria-expanded={open} onClick={() => setAdminOpen(!open)}>
                <span>{s.title}</span>
                <span className="nav-count">{s.items.length}</span>
                {open ? <ChevronDown size={14} /> : <ChevronRight size={14} />}
              </button>
              {open && s.items.map((i) => <ItemLink key={i.label} it={i} path={pathname} />)}
            </div>
          );
        }
        return (
          <div key={idx} className={rail ? "rail-group" : undefined}>
            {s.title && <div className="nav-section">{s.title}</div>}
            {s.items.map((i) => (
              <ItemLink key={i.label} it={i} path={pathname} rail={rail} />
            ))}
          </div>
        );
      })}
      {bottomItem && (
        <div className={rail ? "rail-bottom" : "nav-bottom"}>
          <ItemLink it={bottomItem} path={pathname} rail={rail} />
        </div>
      )}
    </>
  );
}

/** Вкладки над страницей, если пункт меню объединяет несколько страниц. */
export function SectionTabs({ variant, has }: { variant: MenuVariant; has: Has }) {
  const { pathname } = useLocation();
  if (variant === "now") return null;
  const { top, bottom } = structure(variant);
  const all = [...top.flatMap((s) => s.items), ...(bottom ? [bottom] : [])];
  const it = all.map((i) => visible(i, has)).find((i) => i && i.pages.length > 1 && itemActive(i, pathname));
  if (!it) return null;
  return (
    <div className="section-tabs">
      <div className="tabs" role="tablist">
        {it.pages.map((p) => (
          <NavLink key={p.to} to={p.to} role="tab" aria-selected={isOn(pathname, p.to)} className="tab">
            {p.icon(15)}
            {it.tabLabels?.[p.to] ?? p.label}
          </NavLink>
        ))}
      </div>
    </div>
  );
}
