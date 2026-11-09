import { useEffect, useRef, useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { Check, Copy, RotateCw, Search, Wrench } from "lucide-react";
import { api } from "../api/client";
import type { FindingOut, FixHostOut, FixKind, FixTaskOut, Severity } from "../api/types";
import { SEVERITIES, SEVERITY_LABEL } from "../lib/labels";
import { useAsync } from "../lib/useAsync";
import { PAGE_SIZES, useDebounced } from "../lib/useFindingsPage";
import { FindingDrawer } from "./FindingDrawer";
import { Pager } from "./Pager";
import { Empty, ErrorAlert, Loading, RefTags, SeverityBadge } from "./ui";

/** Фильтр «вид действия»: пакеты с версией и без — одна плашка. */
const KIND_FILTERS: { id: FixKind; label: string; of: FixKind[] }[] = [
  { id: "package", label: "Обновить пакет", of: ["package", "package_upgrade"] },
  { id: "kernel", label: "Ядро и перезагрузка", of: ["kernel"] },
  { id: "package_nofix", label: "Исправления нет", of: ["package_nofix"] },
  { id: "software", label: "Обновить ПО", of: ["software"] },
  { id: "config", label: "Настройка", of: ["config"] },
  { id: "cred", label: "Учётные записи", of: ["cred"] },
  { id: "vuln", label: "Прочие уязвимости", of: ["vuln", "other"] },
];

const PRIORITY_PILL: Record<string, string> = {
  critical: "pill-danger",
  high: "pill-warn",
  medium: "pill-info",
  low: "pill-muted",
};

const MAX_CHIPS = 6;

function toggle<T>(list: T[], v: T): T[] {
  return list.includes(v) ? list.filter((x) => x !== v) : [...list, v];
}

function plural(n: number, one: string, few: string, many: string): string {
  const m10 = n % 10;
  const m100 = n % 100;
  if (m10 === 1 && m100 !== 11) return one;
  if (m10 >= 2 && m10 <= 4 && (m100 < 12 || m100 > 14)) return few;
  return many;
}

/** Подпись ссылки: сайт и последний сегмент адреса (DSA-5532-1, CVE-…). */
function refLabel(url: string): string {
  try {
    const u = new URL(url);
    const host = u.hostname.replace(/^www\./, "");
    const tail = decodeURIComponent(u.pathname.split("/").filter(Boolean).at(-1) ?? "");
    return tail ? `${host} · ${tail.replace(/\.html?$/, "")}` : host;
  } catch {
    return url;
  }
}

const isHttp = (u: string) => /^https?:\/\//i.test(u);

/** Блок команд с кнопкой «Скопировать». */
function Commands({ title, lines }: { title: string; lines: string[] }) {
  const [copied, setCopied] = useState(false);
  if (!lines.length) return null;
  const copy = async () => {
    try {
      await navigator.clipboard.writeText(lines.join("\n"));
      setCopied(true);
      window.setTimeout(() => setCopied(false), 1500);
    } catch {
      /* буфер обмена недоступен (http без TLS) — текст можно выделить вручную */
    }
  };
  return (
    <div className="fix-cmd">
      <div className="fix-cmd-head">
        <span className="faint">{title}</span>
        <button type="button" className="btn btn-sm btn-ghost" onClick={copy} aria-label={`Скопировать: ${title}`}>
          {copied ? <Check size={14} aria-hidden="true" /> : <Copy size={14} aria-hidden="true" />}
          {copied ? "Скопировано" : "Скопировать"}
        </button>
      </div>
      <pre className="mono">{lines.join("\n")}</pre>
    </div>
  );
}

function HostRow({ h, runId, onFinding }: { h: FixHostOut; runId: number | null; onFinding: (id: number) => void }) {
  const chips = h.findings.slice(0, MAX_CHIPS);
  return (
    <tr>
      <td className="mono" style={{ whiteSpace: "nowrap" }}>
        <Link to={`/hosts/${encodeURIComponent(h.host)}${runId === null ? "" : `?run=${runId}`}`}>{h.host}</Link>
        {h.ports.length > 0 && <span className="faint">:{h.ports.join(", ")}</span>}
      </td>
      <td className="mono" style={{ whiteSpace: "nowrap" }}>{h.installed ?? <span className="faint">—</span>}</td>
      <td>
        {h.note && <div className="muted" style={{ marginBottom: 4 }}>{h.note}</div>}
        <span className="inline" style={{ gap: 4 }}>
          {chips.map((f) => (
            <button
              key={f.id}
              type="button"
              className={`chip chip-static fix-finding sev-edge-${f.severity}`}
              title="Открыть находку: подробности и отметка «ложное срабатывание»"
              onClick={() => onFinding(f.id)}
            >
              {f.label}
            </button>
          ))}
          {h.findings.length > MAX_CHIPS && <span className="faint">+{h.findings.length - MAX_CHIPS}</span>}
        </span>
      </td>
    </tr>
  );
}

function FixCard({ t, runId, open, focus, onFinding }: { t: FixTaskOut; runId: number | null; open: boolean; focus?: boolean; onFinding: (id: number) => void }) {
  const vulns = t.cves.length + t.bdu_ids.length;
  const ref = useRef<HTMLDetailsElement>(null);
  // действие, выбранное в быстром поиске (?task=…), раскрыто и прокручено в видимую область
  useEffect(() => {
    if (focus) ref.current?.scrollIntoView?.({ block: "start", behavior: "smooth" });
  }, [focus]);
  return (
    <details ref={ref} className={`fix-card${focus ? " fix-card-focus" : ""}`} open={open || focus}>
      <summary>
        <SeverityBadge severity={t.severity} short />
        <span className="fix-title">{t.title}</span>
        {t.os && <span className="pill pill-muted">{t.os}</span>}
        {t.reboot && <span className="pill pill-warn">перезагрузка</span>}
        <span className="faint fix-meta">
          {t.host_count} {plural(t.host_count, "хост", "хоста", "хостов")}
          {vulns > 0 && ` · ${t.cves.length || t.bdu_ids.length} ${t.cves.length ? "CVE" : "БДУ"}`}
          {vulns === 0 && ` · ${t.finding_count} ${plural(t.finding_count, "находка", "находки", "находок")}`}
        </span>
        {t.priority && (
          <span className={`pill ${PRIORITY_PILL[t.priority.label] ?? "pill-muted"}`} title={`Приоритет: ${t.priority.label_ru}, балл ${t.priority.score.toFixed(0)}`}>
            {t.priority.score.toFixed(0)}
          </span>
        )}
      </summary>
      <div className="fix-body">
        <div className="stack" style={{ gap: 13 }}>
          <section aria-label="Что сделать">
            <h3>Что сделать</h3>
            <ol className="fix-steps">
              {t.steps.map((s) => (
                <li key={s}>{s}</li>
              ))}
            </ol>
          </section>
          <Commands title={t.manager ? `Команды (${t.os ?? t.manager})` : "Команды"} lines={t.commands} />
          <Commands title="Проверка результата" lines={t.verify} />
          {t.commands.length > 0 && (
            <p className="faint" style={{ margin: 0, fontSize: 12 }}>
              Команды — для ОС хостов по данным сканирования. Перед массовым применением проверьте их на одном хосте или в тестовой среде.
            </p>
          )}
          {t.details && (
            <details className="fix-details">
              <summary>Меры по описанию уязвимости{t.details_source ? ` · ${t.details_source}` : ""}</summary>
              <p style={{ whiteSpace: "pre-line", margin: "8px 0 0" }}>{t.details}</p>
            </details>
          )}
        </div>
        <div className="stack" style={{ gap: 13 }}>
          <section aria-label="Хосты">
            <h3>Хосты</h3>
            <div className="table-wrap">
              <table className="table">
                <thead>
                  <tr>
                    <th>Хост</th>
                    <th>{t.kind === "kernel" ? "Работает ядро" : "Установлено"}</th>
                    <th>Находки</th>
                  </tr>
                </thead>
                <tbody>
                  {t.hosts.map((h) => (
                    <HostRow key={h.host} h={h} runId={runId} onFinding={onFinding} />
                  ))}
                </tbody>
              </table>
            </div>
          </section>
          {(vulns > 0 || t.advisories.length > 0) && (
            <section aria-label="Закрывает">
              <h3>Закрывает</h3>
              <div className="stack" style={{ gap: 6 }}>
                {vulns > 0 && <RefTags cve={t.cves} bdu={t.bdu_ids} limit={14} />}
                {t.advisories.length > 0 && <span className="faint">Бюллетени: {t.advisories.join(", ")}</span>}
              </div>
            </section>
          )}
          {t.references.some(isHttp) && (
            <section aria-label="Ссылки на устранение">
              <h3>Ссылки на устранение</h3>
              <ul className="fix-refs">
                {t.references.filter(isHttp).map((u) => (
                  <li key={u}>
                    <a href={u} target="_blank" rel="noopener noreferrer">
                      {refLabel(u)}
                    </a>
                  </li>
                ))}
              </ul>
            </section>
          )}
        </div>
      </div>
    </details>
  );
}

/**
 * План исправлений прогона для администраторов: находки, собранные в действия
 * («обновить пакет до версии V на Debian 12»), с командами для ОС хостов,
 * проверкой результата и списком хостов. Фильтры — в адресной строке.
 * С host — план одного актива (карточка хоста в «Активах»): только действия,
 * которые касаются этого хоста, без отдельных карточек и фильтра по ОС.
 */
export function FixPlan({
  runId,
  onHost,
  host,
  engagementId,
}: {
  /** Прогон; null — последние известные данные актива (нужны host и engagementId). */
  runId: number | null;
  onHost: (host: string) => void;
  host?: string;
  engagementId?: number;
}) {
  const [params, setParams] = useSearchParams();
  const severities = params.getAll("sev").filter((s): s is Severity => (SEVERITIES as string[]).includes(s));
  const kinds = params.getAll("kind");
  const oses = params.getAll("os");
  const focusKey = params.get("task");
  const size = PAGE_SIZES.includes(Number(params.get("size"))) ? Number(params.get("size")) : 25;
  const offset = Math.max(0, (Number(params.get("page")) || 1) - 1) * size;
  const [query, setQuery] = useState(params.get("q") ?? "");
  const q = useDebounced(query.trim());

  const update = (patch: Record<string, string | string[] | null>, keepPage = false) => {
    const next = new URLSearchParams(params);
    for (const [k, v] of Object.entries(patch)) {
      next.delete(k);
      if (Array.isArray(v)) v.forEach((x) => next.append(k, x));
      else if (v !== null && v !== "") next.set(k, v);
    }
    if (!keepPage) next.delete("page");
    setParams(next, { replace: true });
  };
  const urlQ = params.get("q") ?? "";
  useEffect(() => {
    if (q !== urlQ) update({ q: q || null });
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [q]);
  // запрос сменился снаружи (переход из быстрого поиска) — поле поиска следует за адресом
  useEffect(() => {
    if (urlQ !== query.trim()) setQuery(urlQ);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [urlQ]);

  const kindParam = KIND_FILTERS.filter((k) => kinds.includes(k.id)).flatMap((k) => k.of);
  const key = JSON.stringify([severities, kindParam, oses, urlQ, offset, size, host, engagementId]);
  const plan = useAsync(
    () => {
      const common = { severity: severities, kind: kindParam, q: urlQ || undefined, limit: size, offset };
      if (runId === null) return api.hostFixes(engagementId!, host!, common);
      return api.fixes(runId, { ...common, os: host ? [] : oses, host });
    },
    [runId, key],
    runId !== null || (!!host && engagementId !== undefined),
  );
  const source = runId === null ? "Последние данные хоста" : `Прогон №${runId}`;
  const [open, setOpen] = useState<FindingOut | null>(null);
  const [opening, setOpening] = useState<Error | null>(null);
  const openFinding = async (id: number) => {
    try {
      setOpen(await api.finding(id));
      setOpening(null);
    } catch (e) {
      setOpening(e as Error);
    }
  };

  const d = plan.data;
  const active = severities.length + kinds.length + oses.length + (urlQ ? 1 : 0);
  const kindCount = (k: (typeof KIND_FILTERS)[number]) => k.of.reduce((n, x) => n + (d?.kinds[x] ?? 0), 0);
  const osList = host ? [] : Object.entries(d?.os ?? {}).sort((a, b) => b[1] - a[1]);

  const filters = (
    <>
        {d && (
          <p className="fix-lead">
            <Wrench size={16} aria-hidden="true" />
            <span>
              <b>{d.tasks.toLocaleString("ru-RU")}</b> {plural(d.tasks, "действие", "действия", "действий")} закрывают{" "}
              <b>{d.findings.toLocaleString("ru-RU")}</b> {plural(d.findings, "находку", "находки", "находок")}
              {host ? (
                " на этом хосте"
              ) : (
                <>
                  {" "}на <b>{d.hosts}</b> {plural(d.hosts, "хосте", "хостах", "хостах")}
                </>
              )}
              {d.false_positives > 0 && <span className="faint"> · без {d.false_positives} ложных срабатываний</span>}
            </span>
          </p>
        )}
        <div className="inline" style={{ gap: 10 }}>
          <div className="search" style={{ flex: "1 1 280px" }}>
            <Search size={15} aria-hidden="true" />
            <input
              className="input"
              type="search"
              placeholder="Поиск: пакет, CVE, БДУ, бюллетень, хост"
              aria-label="Поиск по плану исправлений"
              value={query}
              onChange={(e) => setQuery(e.target.value)}
            />
          </div>
          {active > 0 && (
            <button
              type="button"
              className="btn btn-sm btn-ghost"
              onClick={() => {
                setQuery("");
                update({ sev: null, kind: null, os: null, q: null });
              }}
            >
              Сбросить ({active})
            </button>
          )}
        </div>
        <div className="inline" role="group" aria-label="Уровень опасности">
          <span className="faint" style={{ fontSize: 12, minWidth: 80 }}>
            Опасность
          </span>
          {SEVERITIES.filter((s) => s !== "info").map((s) => (
            <button key={s} type="button" className="chip" aria-pressed={severities.includes(s)} onClick={() => update({ sev: toggle<string>(severities, s) })}>
              <span className={`sev sev-${s}`}>
                <i aria-hidden="true" />
              </span>
              {SEVERITY_LABEL[s]} <span className="faint">{d?.severities[s] ?? 0}</span>
            </button>
          ))}
        </div>
        <div className="inline" role="group" aria-label="Что сделать">
          <span className="faint" style={{ fontSize: 12, minWidth: 80 }}>
            Действие
          </span>
          {KIND_FILTERS.filter((k) => kindCount(k) > 0 || kinds.includes(k.id)).map((k) => (
            <button key={k.id} type="button" className="chip" aria-pressed={kinds.includes(k.id)} onClick={() => update({ kind: toggle(kinds, k.id) })}>
              {k.label} <span className="faint">{kindCount(k)}</span>
            </button>
          ))}
        </div>
        {osList.length > 0 && (
          <div className="inline" role="group" aria-label="ОС хостов">
            <span className="faint" style={{ fontSize: 12, minWidth: 80 }}>
              ОС
            </span>
            {osList.map(([os, n]) => (
              <button key={os} type="button" className="chip" aria-pressed={oses.includes(os)} onClick={() => update({ os: toggle(oses, os) })}>
                {os === "-" ? "Без привязки к ОС" : os} <span className="faint">{n}</span>
              </button>
            ))}
          </div>
        )}
    </>
  );
  const reload = (
    <button type="button" className="btn btn-sm btn-ghost" onClick={() => void plan.reload()} aria-label="Обновить план">
      <RotateCw size={14} aria-hidden="true" />
    </button>
  );
  const list = (
    <>
        {plan.loading && !d ? (
          <Loading />
        ) : !d || d.items.length === 0 ? (
          <Empty title={active ? "Ничего не найдено по фильтрам" : host ? "На этом хосте исправлять нечего" : "Исправлять нечего: открытых находок нет"} />
        ) : (
          <div className="fix-list">
            {d.items.map((t, i) => (
              <FixCard key={t.key} t={t} runId={runId} open={offset === 0 && i < 3} focus={t.key === focusKey} onFinding={openFinding} />
            ))}
          </div>
        )}
        {d && d.total > 0 && (
          <Pager
            total={d.total}
            offset={offset}
            limit={size}
            label="Страницы плана исправлений"
            onChange={(o) => update({ page: o ? String(Math.floor(o / size) + 1) : null }, true)}
            onLimit={(n) => update({ size: n === 25 ? null : String(n) })}
          />
        )}
    </>
  );
  const errors = (
    <>
      {plan.error && <ErrorAlert error={plan.error} onRetry={plan.reload} />}
      {opening && <ErrorAlert error={opening} />}
    </>
  );

  return (
    <>
      {host ? (
        <>
          <div className="card-pad stack fix-embedded" style={{ gap: 14 }}>
            {filters}
            {errors}
            <span className="faint" style={{ fontSize: 12 }}>
              {source} · сначала — самые важные по приоритету {reload}
            </span>
          </div>
          {list}
        </>
      ) : (
        <>
          <section className="card card-pad stack" style={{ gap: 14 }}>
            {filters}
          </section>
          {errors}
          <section className="card" style={{ overflow: "hidden" }}>
            <div className="card-head">
              <h2>Что исправить: {(d?.total ?? 0).toLocaleString("ru-RU")}</h2>
              <span className="faint" style={{ fontSize: 12 }}>
                {source} · сначала — самые важные по приоритету
              </span>
              {reload}
            </div>
            {list}
          </section>
        </>
      )}
      {open && (
        <FindingDrawer
          finding={open}
          onClose={() => setOpen(null)}
          onHost={onHost}
          onChanged={(u) => {
            setOpen(u);
            void plan.reload();
          }}
        />
      )}
    </>
  );
}
