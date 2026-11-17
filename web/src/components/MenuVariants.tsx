// Макеты меню для утверждения (предложение В4 разбора продукта). Вариант выбирается
// ключом localStorage «scanner.menu» (now | v1 | v2 | v3 | v4); по умолчанию — текущее меню.
// Страницы и URL не меняются: варианты только по-разному группируют пункты. Если пункт
// объединяет несколько страниц, его подпункты раскрываются прямо в боковом меню, пока
// открыта одна из этих страниц. В узкой панели (v3) подпунктам нет места, там второй
// уровень остаётся полосой под шапкой.
// У вариантов v1–v4 включается «угловатый» вид (data-look="sharp" на <html>):
// скругления 2–4 px, размеры меню — из ряда Фибоначчи (см. конец styles.css).
import type { ReactNode } from "react";
import { useEffect, useState } from "react";
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
import { api, ApiError } from "../api/client";
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

/** Пункт меню; если страниц несколько — они раскрываются подпунктами в боковом меню. */
interface Item {
  label: string;
  icon: (size: number) => ReactNode;
  pages: Page[];
  /** Короткая подпись для узкой панели. */
  short?: string;
  /** Подписи второго уровня, если они отличаются от названий страниц. */
  tabLabels?: Record<string, string>;
  /** Вместо значка — лампочка состояния сервиса (активен / не активен). */
  lamp?: boolean;
}

const one = (p: Page, over: Partial<Item> = {}): Item => ({ label: p.label, icon: p.icon, pages: [p], ...over });

const SCAN: Item = {
  label: "Сканирование",
  icon: P.runs.icon,
  pages: [P.runs, P.reach, P.sched],
  tabLabels: { "/runs": "Прогоны" },
};
const NORMS = one(P.compl, { label: "Нормативы" });
const CREDS = one(P.creds, { short: "Учётки" });
const SETTINGS: Item = { label: "Настройка", icon: (s) => <Settings size={s} />, pages: ADMIN };
// «Короткий список» и «Узкая панель»: «Состояние» — отдельный пункт с лампочкой под «Настройкой», в ней остаются 5 страниц.
const HEALTH = one(P.health, { lamp: true });
const SETTINGS_NO_HEALTH: Item = { ...SETTINGS, pages: ADMIN.filter((p) => p !== P.health) };

/** Состояние самого сервиса: отвечает ли API. Проблемы отдельных компонентов показывает плашка в шапке. */
export type ServiceState = "on" | "off" | "unknown";
const LAMP_POLL_MS = 30000;
const SERVICE_LABEL: Record<ServiceState, string> = { on: "Активен", off: "Не активен", unknown: "Проверка…" };

function useServiceState(enabled: boolean): ServiceState {
  const [state, setState] = useState<ServiceState>("unknown");
  useEffect(() => {
    if (!enabled) return;
    let alive = true;
    let timer: ReturnType<typeof setTimeout> | undefined;
    const tick = async () => {
      try {
        await api.systemHealth();
        if (alive) setState("on");
      } catch (e) {
        // нет ответа или 5xx — сервис не работает; 401/403 — это про вход, а не про сервис
        const status = e instanceof ApiError ? e.status : 0;
        if (alive && (status === 0 || status >= 500)) setState("off");
      }
      if (alive) timer = setTimeout(tick, LAMP_POLL_MS);
    };
    void tick();
    return () => {
      alive = false;
      if (timer) clearTimeout(timer);
    };
  }, [enabled]);
  return state;
}

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

function structure(v: MenuVariant): { top: Section[]; bottom?: Item[] } {
  switch (v) {
    case "v1":
      return {
        top: [
          { items: [one(P.summary)] },
          { title: "Проверки", items: [one(P.projects), one(P.assets), CREDS, SCAN] },
          { title: "Результаты", items: [one(P.findings), NORMS, one(P.reports)] },
          { title: "Настройка", collapsible: true, items: ADMIN.map((p) => one(p)) },
        ],
      };
    case "v2":
    case "v3":
      return {
        top: [{ items: [one(P.summary), one(P.projects), one(P.assets), CREDS, SCAN, one(P.findings), NORMS, one(P.reports)] }],
        bottom: [SETTINGS_NO_HEALTH, HEALTH],
      };
    case "v4":
      return {
        top: [
          { items: [one(P.summary)] },
          { title: "Подготовка", step: 1, items: [one(P.projects), one(P.assets), one(P.creds)] },
          { title: "Проверка", step: 2, items: [one(P.reach), one(P.runs), one(P.sched)] },
          { title: "Результаты", step: 3, items: [one(P.findings), NORMS, one(P.reports)] },
        ],
        bottom: [SETTINGS],
      };
    default:
      return { top: [] };
  }
}

function ItemLink({ it, path, mode, service }: { it: Item; path: string; mode?: "rail" | "step"; service?: ServiceState }) {
  const first = it.pages[0];
  const active = itemActive(it, path);
  const lamp = it.lamp && service ? service : null;
  const title = lamp ? `${it.label}: сервис ${SERVICE_LABEL[lamp].toLowerCase()}` : it.label;
  return (
    <NavLink
      to={first.to}
      end={first.to === "/"}
      className={() => `nav-link ${mode === "rail" ? "rail-link" : ""} ${mode === "step" ? "step-link" : ""} ${active ? "active" : ""}`}
      title={mode === "rail" || lamp ? title : undefined}
      aria-label={lamp ? title : undefined}
    >
      {mode !== "step" && (
        <span className="nav-ic">{lamp ? <span className={`lamp ${lamp}`} aria-hidden="true" /> : it.icon(mode === "rail" ? 21 : 18)}</span>
      )}
      <span>{mode === "rail" ? it.short ?? it.label : it.label}</span>
      {lamp && mode !== "rail" && <span className={`nav-state ${lamp}`}>{SERVICE_LABEL[lamp]}</span>}
    </NavLink>
  );
}

/** Пункт с несколькими страницами: переход в него открывает первую страницу и раскрывает подпункты под ним. */
function ItemGroup({ it, path }: { it: Item; path: string }) {
  const open = itemActive(it, path);
  return (
    <>
      <NavLink to={it.pages[0].to} className={() => `nav-link nav-parent ${open ? "open" : ""}`} aria-expanded={open}>
        <span className="nav-ic">{it.icon(18)}</span>
        <span>{it.label}</span>
        <span className="nav-chev" aria-hidden="true">
          {open ? <ChevronDown size={13} /> : <ChevronRight size={13} />}
        </span>
      </NavLink>
      {open && (
        <div className="nav-sub" role="group" aria-label={it.label}>
          {it.pages.map((p) => (
            <NavLink key={p.to} to={p.to} className={() => `nav-link sub-link ${isOn(path, p.to) ? "active" : ""}`}>
              {it.tabLabels?.[p.to] ?? p.label}
            </NavLink>
          ))}
        </div>
      )}
    </>
  );
}

/** Боковое меню выбранного варианта (кроме «now» — его рисует Layout). */
export function VariantNav({ variant, has }: { variant: MenuVariant; has: Has }) {
  const { pathname } = useLocation();
  const { top, bottom } = structure(variant);
  const sections = top
    .map((s) => ({ ...s, items: s.items.map((i) => visible(i, has)).filter((i): i is Item => !!i) }))
    .filter((s) => s.items.length);
  const bottomItems = (bottom ?? []).map((i) => visible(i, has)).filter((i): i is Item => !!i);
  const service = useServiceState(bottomItems.some((i) => i.lamp));
  const activeStep = sections.find((s) => s.step && s.items.some((i) => itemActive(i, pathname)))?.step;
  const adminActive = sections.some((s) => s.collapsible && s.items.some((i) => itemActive(i, pathname)));
  const [adminOpen, setAdminOpen] = useState(false);
  const rail = variant === "v3";
  const link = (i: Item, withService = false) =>
    !rail && i.pages.length > 1 ? (
      <ItemGroup key={i.label} it={i} path={pathname} />
    ) : (
      <ItemLink key={i.label} it={i} path={pathname} mode={rail ? "rail" : undefined} service={withService ? service : undefined} />
    );

  return (
    <div className={`nav-body ${rail ? "rail-body" : ""}`}>
      {sections.map((s, idx) => {
        if (s.step) {
          // Шаги всегда раскрыты: любая страница — в один щелчок, номера показывают порядок работы.
          return (
            <div key={idx} className={`nav-step ${s.step === activeStep ? "current" : ""}`}>
              <div className="nav-step-head">
                <span className="step-num">{s.step}</span>
                <span>{s.title}</span>
              </div>
              <div className="nav-step-items">
                {s.items.map((i) => (
                  <ItemLink key={i.label} it={i} path={pathname} mode="step" />
                ))}
              </div>
            </div>
          );
        }
        if (s.collapsible) {
          const open = adminOpen || adminActive;
          return (
            <div key={idx} className="nav-group">
              <button type="button" className="nav-section nav-section-btn" aria-expanded={open} onClick={() => setAdminOpen(!open)}>
                <span>{s.title}</span>
                <span className="nav-count">{s.items.length}</span>
                {open ? <ChevronDown size={13} /> : <ChevronRight size={13} />}
              </button>
              {open && s.items.map((i) => <ItemLink key={i.label} it={i} path={pathname} />)}
            </div>
          );
        }
        return (
          <div key={idx} className="nav-group">
            {s.title && <div className="nav-section">{s.title}</div>}
            {s.items.map((i) => link(i))}
          </div>
        );
      })}
      {bottomItems.length > 0 && <div className="nav-group nav-bottom">{bottomItems.map((i) => link(i, true))}</div>}
    </div>
  );
}

/** Второй уровень меню под шапкой — только в узкой панели, где подпунктам нет места в самом меню. */
export function SubNav({ variant, has }: { variant: MenuVariant; has: Has }) {
  const { pathname } = useLocation();
  if (variant !== "v3") return null;
  const { top, bottom } = structure(variant);
  const all = [...top.flatMap((s) => s.items), ...(bottom ?? [])];
  const it = all.map((i) => visible(i, has)).find((i) => i && i.pages.length > 1 && itemActive(i, pathname));
  if (!it) return null;
  return (
    <nav className="subnav" aria-label={it.label}>
      {it.pages.map((p) => (
        <NavLink key={p.to} to={p.to} aria-current={isOn(pathname, p.to) ? "page" : undefined} className="subnav-link">
          {p.icon(15)}
          {it.tabLabels?.[p.to] ?? p.label}
        </NavLink>
      ))}
    </nav>
  );
}
