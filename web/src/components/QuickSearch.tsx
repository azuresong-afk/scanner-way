import { useCallback, useEffect, useMemo, useRef, useState, type ReactNode } from "react";
import { useNavigate } from "react-router-dom";
import { Check, Package, Search, Server, ShieldAlert, Terminal, Wrench } from "lucide-react";
import { api } from "../api/client";
import type { SearchOut, Severity } from "../api/types";
import { useAuth } from "../auth/AuthContext";
import { useEngagement } from "../auth/EngagementContext";
import { copyText } from "../lib/clipboard";
import { SEVERITY_SHORT } from "../lib/labels";

/** Строка результата: что показать и что сделать по Enter. */
interface Item {
  id: string;
  icon: ReactNode;
  title: string;
  sub: string;
  mono?: boolean;
  severity?: Severity | null;
  badge?: string;
  /** Плашка без уровня: warn — есть уязвимости, acc — справка (ОС). */
  tone?: "warn" | "acc";
  hint: string;
  /** Путь для перехода; без него — копирование `copy`. */
  to?: string;
  copy?: string;
}

interface Group {
  title: string;
  count: number;
  items: Item[];
}

const ru = (n: number) => n.toLocaleString("ru-RU");

function plural(n: number, one: string, few: string, many: string): string {
  const m10 = n % 10;
  const m100 = n % 100;
  if (m10 === 1 && m100 !== 11) return one;
  if (m10 >= 2 && m10 <= 4 && (m100 < 12 || m100 > 14)) return few;
  return many;
}

/** Подсветка совпадения (без учёта регистра) — первое вхождение. */
function Hit({ text, q }: { text: string; q: string }) {
  const i = q ? text.toLocaleLowerCase("ru-RU").indexOf(q.toLocaleLowerCase("ru-RU")) : -1;
  if (i < 0) return <>{text}</>;
  return (
    <>
      {text.slice(0, i)}
      <mark>{text.slice(i, i + q.length)}</mark>
      {text.slice(i + q.length)}
    </>
  );
}

/** Результаты API → группы палитры. commandsOnly — запрос начинался с «>». */
function toGroups(r: SearchOut, commandsOnly: boolean): Group[] {
  const run = r.run_id ? `run=${r.run_id}` : "";
  const qs = (...parts: string[]) => {
    const s = parts.filter(Boolean).join("&");
    return s ? `?${s}` : "";
  };
  const enc = encodeURIComponent;
  const groups: Group[] = [];
  const commands: Group = {
    title: "Команды",
    count: r.counts.commands,
    items: r.commands.map((c) => ({
      id: `cmd:${c.key}`,
      icon: <Terminal size={15} />,
      title: c.title,
      sub: c.command,
      mono: true,
      badge: c.os ?? undefined,
      hint: "Копировать",
      copy: c.commands.join("\n"),
    })),
  };
  if (commandsOnly) return commands.items.length ? [commands] : [];
  groups.push({
    title: "Действия",
    count: r.counts.actions,
    items: r.actions.map((a) => ({
      id: `act:${a.key}`,
      icon: <Wrench size={15} />,
      title: a.title,
      sub: [
        `закроет ${ru(a.finding_count)} ${plural(a.finding_count, "находку", "находки", "находок")} на ${ru(a.host_count)} ${plural(a.host_count, "хосте", "хостах", "хостах")}`,
        a.priority !== null ? `приоритет ${a.priority} из 100` : "",
        a.os ?? "",
      ]
        .filter(Boolean)
        .join(" · "),
      severity: a.severity,
      hint: "Что исправить",
      to: `/findings${qs(run, `q=${enc(r.q)}`, `task=${enc(a.key)}`)}`,
    })),
  });
  groups.push({
    title: "Хосты",
    count: r.counts.hosts,
    items: r.hosts.map((h) => ({
      id: `host:${h.host}`,
      icon: <Server size={15} />,
      title: [h.hostname, h.match].filter(Boolean).join(" · ") || h.host,
      sub: [h.host, h.os ?? ""].filter(Boolean).join(" · "),
      mono: true,
      severity: h.vulns ? h.max_severity : null,
      badge: h.vulns ? `${ru(h.vulns)} уязв.` : undefined,
      hint: "Карточка",
      to: `/hosts/${enc(h.host)}`,
    })),
  });
  groups.push({
    title: "ПО",
    count: r.counts.software,
    items: r.software.map((s) => {
      const versions = `${s.versions.length} ${plural(s.versions.length, "версия", "версии", "версий")}`;
      const where = `на ${ru(s.host_count)} ${plural(s.host_count, "хосте", "хостах", "хостах")}`;
      const vuln = s.vulnerable_hosts ? `уязвимы ${ru(s.vulnerable_hosts)} ${plural(s.vulnerable_hosts, "хост", "хоста", "хостов")}` : "уязвимостей нет";
      return {
        id: `sw:${s.source}:${s.name}`,
        icon: <Package size={15} />,
        title: s.name,
        sub: [s.versions.length === 1 ? s.versions[0] : versions, where, vuln, s.source === "service" ? "по баннеру сервиса" : ""]
          .filter(Boolean)
          .join(" · "),
        badge: s.vulns ? `${ru(s.vulns)} уязв.` : undefined,
        tone: "warn" as const,
        hint: s.vulns ? "Что исправить" : "Карточка",
        to: s.vulns ? `/findings${qs(run, `q=${enc(s.name)}`)}` : s.hosts[0] ? `/hosts/${enc(s.hosts[0])}` : undefined,
      };
    }),
  });
  groups.push({
    title: "CVE и БДУ",
    count: r.counts.vulns,
    items: r.vulns.map((v) => {
      const ids = [...new Set([v.id, ...v.cves, ...v.bdu_ids])];
      return {
        id: `vuln:${v.id}`,
        icon: <ShieldAlert size={15} />,
        title: `${ids[0]} · ${v.title}`,
        sub: [...ids.slice(1), `${ru(v.host_count)} ${plural(v.host_count, "хост", "хоста", "хостов")}`].join(" · "),
        mono: true,
        severity: v.severity,
        hint: "Находки",
        to: `/findings${qs("view=all", run, `q=${enc(v.id)}`)}`,
      };
    }),
  });
  groups.push(commands);
  return groups.filter((g) => g.items.length > 0);
}

/**
 * Быстрый поиск по текущему проекту: поле в верхней панели и палитра по Ctrl+K
 * (⌘K на macOS) с любой страницы. Ищет хосты, ПО, CVE/БДУ, действия и команды
 * плана исправлений; ↑/↓ — выбор, Enter — открыть (команду — скопировать),
 * «>» в начале запроса — только команды.
 */
export function QuickSearch() {
  const { has } = useAuth();
  const { current } = useEngagement();
  const [open, setOpen] = useState(false);
  const enabled = has("view_report") && !!current;

  useEffect(() => {
    if (!enabled) return;
    const onKey = (e: KeyboardEvent) => {
      if ((e.ctrlKey || e.metaKey) && !e.altKey && !e.shiftKey && (e.key === "k" || e.key === "K" || e.code === "KeyK")) {
        e.preventDefault();
        setOpen((v) => !v);
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [enabled]);

  if (!enabled) return null;
  return (
    <>
      <button type="button" className="qs-trigger" onClick={() => setOpen(true)} aria-label="Поиск по проекту (Ctrl+K)" aria-haspopup="dialog">
        <Search size={15} aria-hidden="true" />
        <span className="qs-trigger-text">Хост, ПО, CVE, БДУ, команда…</span>
        <kbd className="hide-sm">Ctrl K</kbd>
      </button>
      {open && <Palette engagementId={current!.id} project={current!.client ? `${current!.client} · ${current!.name}` : current!.name} onClose={() => setOpen(false)} />}
    </>
  );
}

function Palette({ engagementId, project, onClose }: { engagementId: number; project: string; onClose: () => void }) {
  const navigate = useNavigate();
  const [text, setText] = useState("");
  const [data, setData] = useState<SearchOut | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [sel, setSel] = useState(0);
  const [copied, setCopied] = useState<string | null>(null);
  const inputRef = useRef<HTMLInputElement>(null);
  const listRef = useRef<HTMLDivElement>(null);
  const returnFocus = useRef<Element | null>(null);

  const commandsOnly = text.trimStart().startsWith(">");
  const q = (commandsOnly ? text.trimStart().slice(1) : text).trim();

  useEffect(() => {
    returnFocus.current = document.activeElement;
    inputRef.current?.focus();
    return () => (returnFocus.current as HTMLElement | null)?.focus?.();
  }, []);

  useEffect(() => {
    if (!q) {
      setData(null);
      setError(null);
      setLoading(false);
      return;
    }
    const ctl = new AbortController();
    setLoading(true);
    const t = window.setTimeout(() => {
      api
        .search(engagementId, q, { signal: ctl.signal })
        .then((r) => {
          setData(r);
          setError(null);
          setSel(0);
        })
        .catch((e: Error) => {
          if (!ctl.signal.aborted) setError(e.message);
        })
        .finally(() => {
          if (!ctl.signal.aborted) setLoading(false);
        });
    }, 180);
    return () => {
      ctl.abort();
      window.clearTimeout(t);
    };
  }, [engagementId, q]);

  const groups = useMemo(() => (data ? toGroups(data, commandsOnly) : []), [data, commandsOnly]);
  const flat = useMemo(() => groups.flatMap((g) => g.items), [groups]);
  const active = flat[Math.min(sel, flat.length - 1)];

  useEffect(() => {
    if (!active) return;
    listRef.current?.querySelector<HTMLElement>(`[data-id="${CSS.escape(active.id)}"]`)?.scrollIntoView?.({ block: "nearest" });
  }, [active]);

  const run = useCallback(
    async (it: Item | undefined) => {
      if (!it) return;
      if (it.to) {
        onClose();
        navigate(it.to);
        return;
      }
      if (it.copy) {
        if (await copyText(it.copy)) {
          setCopied(it.id);
          window.setTimeout(() => setCopied((c) => (c === it.id ? null : c)), 1500);
        } else {
          setError("Буфер обмена недоступен: откройте действие и выделите команду вручную");
        }
      }
    },
    [navigate, onClose],
  );

  const onKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === "Escape") {
      e.preventDefault();
      onClose();
    } else if (e.key === "ArrowDown") {
      e.preventDefault();
      setSel((s) => (flat.length ? (Math.min(s, flat.length - 1) + 1) % flat.length : 0));
    } else if (e.key === "ArrowUp") {
      e.preventDefault();
      setSel((s) => (flat.length ? (Math.min(s, flat.length - 1) - 1 + flat.length) % flat.length : 0));
    } else if (e.key === "Enter") {
      e.preventDefault();
      void run(active);
    } else if (e.key === "Tab") {
      e.preventDefault(); // фокус остаётся в поле: выбор — стрелками
    }
  };

  const shown = q && data && data.q === q;
  const total = data ? Object.values(data.counts).reduce((a, b) => a + b, 0) : 0;

  return (
    <div className="modal-scrim qs-scrim" onMouseDown={(e) => e.target === e.currentTarget && onClose()}>
      <div className="qs" role="dialog" aria-modal="true" aria-label="Быстрый поиск" onKeyDown={onKeyDown}>
        <div className="qs-head">
          <Search size={18} aria-hidden="true" />
          <input
            ref={inputRef}
            type="search"
            className="qs-input"
            placeholder="Хост, ПО, CVE, БДУ, действие · «>» — только команды"
            aria-label="Поиск по хостам, ПО, CVE, БДУ и действиям"
            role="combobox"
            aria-expanded={flat.length > 0}
            aria-controls="qs-list"
            aria-activedescendant={active ? `qs-${active.id}` : undefined}
            autoComplete="off"
            spellCheck={false}
            value={text}
            onChange={(e) => setText(e.target.value)}
          />
          <span className="qs-scope hide-sm" title="Поиск идёт по текущему проекту">
            {project}
          </span>
          <kbd>Esc</kbd>
        </div>
        <div className="qs-list" id="qs-list" role="listbox" aria-label="Результаты" ref={listRef}>
          {error && <div className="qs-empty qs-error">{error}</div>}
          {!q && !error && (
            <div className="qs-empty">
              Найдите хост по адресу или имени, пакет, CVE или БДУ, действие из «Что исправить» или команду обновления.
            </div>
          )}
          {shown && !error && flat.length === 0 && <div className="qs-empty">Ничего не найдено по «{q}»</div>}
          {q && !shown && loading && !error && <div className="qs-empty">Поиск…</div>}
          {shown &&
            groups.map((g) => (
              <div key={g.title} role="group" aria-label={g.title}>
                <div className="qs-group">
                  <span>{g.title}</span>
                  <span>{g.count > g.items.length ? `${g.items.length} из ${ru(g.count)}` : ru(g.count)}</span>
                </div>
                {g.items.map((it) => (
                  <div
                    key={it.id}
                    id={`qs-${it.id}`}
                    data-id={it.id}
                    role="option"
                    aria-selected={it === active}
                    className="qs-row"
                    onMouseMove={() => it !== active && setSel(flat.indexOf(it))}
                    onClick={() => void run(it)}
                  >
                    <span className="qs-icon" aria-hidden="true">
                      {it.icon}
                    </span>
                    <span className="qs-text">
                      <span className="qs-title">
                        <Hit text={it.title} q={q} />
                      </span>
                      <span className={`qs-sub${it.mono ? " mono" : ""}`}>
                        <Hit text={it.sub} q={q} />
                      </span>
                    </span>
                    {it.severity && <span className={`qs-badge qs-sev-${it.severity}`}>{it.badge ?? SEVERITY_SHORT[it.severity]}</span>}
                    {!it.severity && it.badge && <span className={`qs-badge qs-${it.tone ?? "acc"}`}>{it.badge}</span>}
                    <span className="qs-hint">
                      {copied === it.id ? (
                        <>
                          <Check size={13} aria-hidden="true" /> Скопировано
                        </>
                      ) : (
                        it.hint
                      )}
                    </span>
                  </div>
                ))}
              </div>
            ))}
        </div>
        <div className="qs-foot">
          <span>
            <kbd>↑</kbd> <kbd>↓</kbd> выбрать
          </span>
          <span>
            <kbd>Enter</kbd> открыть
          </span>
          <span>
            <kbd>&gt;</kbd> только команды
          </span>
          {data && (
            <span className="qs-foot-scope">
              {shown && total > 0 ? `${ru(total)} ${plural(total, "совпадение", "совпадения", "совпадений")} · ` : ""}
              {ru(data.assets)} {plural(data.assets, "хост", "хоста", "хостов")}
              {data.run_id ? `, ${ru(data.findings)} ${plural(data.findings, "находка", "находки", "находок")} прогона ${data.run_name ? `«${data.run_name}»` : `№${data.run_id}`}` : ", прогонов ещё нет"}
            </span>
          )}
        </div>
      </div>
    </div>
  );
}
