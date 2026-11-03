import { useMemo, useState } from "react";
import { Link, useParams } from "react-router-dom";
import { Pencil, Radar } from "lucide-react";
import { api } from "../api/client";
import { useAuth } from "../auth/AuthContext";
import { useEngagement } from "../auth/EngagementContext";
import type { AssetOut, FindingOut, PackageOut, ServiceOut } from "../api/types";
import { AssetModal, CriticalityBadge } from "../components/AssetEditing";
import { SeverityBars } from "../components/charts/SeverityBars";
import { FindingDrawer } from "../components/FindingDrawer";
import { FindingsTable } from "../components/FindingsTable";
import { ReachabilityCheck } from "../components/ReachabilityCheck";
import { RunPicker } from "../components/RunPicker";
import { ServicesTable } from "../components/ServicesTable";
import { SoftwareTable } from "../components/SoftwareTable";
import { Empty, ErrorAlert, Kpi, Loading, Modal } from "../components/ui";
import { fmtDate } from "../lib/format";
import { MODULE_LABEL } from "../lib/labels";
import { byHost, emptyCounts, isFalsePositive, isIssue, replaceFinding } from "../lib/stats";
import { useAsync } from "../lib/useAsync";
import { useRunSelection } from "../lib/useRunSelection";

type VulnView = "software" | "list";

const SOURCE_LABEL: Record<string, string> = { manual: "", discovery: "прогоном", netscan: "сканированием портов" };

interface HostData {
  findings: FindingOut[];
  services: ServiceOut[];
  packages: PackageOut[];
  /** Прогон выбранный, а без выбора — последний, где хост проверялся (null — не проверялся). */
  runId: number | null;
  /** Без выбора прогона: вид проверки → прогон, из которого её данные. */
  moduleRuns: Record<string, number> | null;
}
const VIEWS: { id: VulnView; label: string }[] = [
  { id: "software", label: "По ПО" },
  { id: "list", label: "Списком" },
];
const VIEW_KEY = "scanner.host.vulnView";

function loadView(): VulnView {
  try {
    return localStorage.getItem(VIEW_KEY) === "list" ? "list" : "software";
  } catch {
    return "software";
  }
}

function saveView(v: VulnView) {
  try {
    localStorage.setItem(VIEW_KEY, v);
  } catch {
    // без localStorage — просто не запоминаем
  }
}

/**
 * Детальная информация по хосту: сервисы и уязвимости. Без выбранного прогона —
 * последние известные данные по всем прогонам (по каждому виду проверки — из
 * последнего прогона, где хост проверялся); с ?run=ID — данные этого прогона.
 */
export function HostDetailPage() {
  const host = decodeURIComponent(useParams().host ?? "");
  const { runs, run, latest, setRun, loading, error } = useRunSelection({ latest: true });
  const { current } = useEngagement();
  const eid = current?.id;
  const data = useAsync(
    async (): Promise<HostData> => {
      if (run) {
        const withPackages = run.modules.includes("auth_inventory");
        const [findings, services, packages] = await Promise.all([
          api.findings(run.id, { host }),
          api.services(run.id),
          withPackages ? api.packages(run.id, host) : Promise.resolve([]),
        ]);
        return { findings, services: services.filter((s) => s.host === host), packages, runId: run.id, moduleRuns: null };
      }
      const [lt, inventory] = await Promise.all([api.hostLatest(eid!, host), api.hosts(eid!)]);
      const inv = inventory.find((h) => h.host === host);
      const packages = inv?.packages_run_id ? await api.packages(inv.packages_run_id, host) : [];
      return { findings: lt.findings, services: inv?.services ?? [], packages, runId: lt.checked_run_id, moduleRuns: lt.module_runs };
    },
    [run?.id, host, eid],
    !!run || (latest && !!eid),
  );
  const [open, setOpen] = useState<FindingOut | null>(null);
  const [checking, setChecking] = useState(false);
  const [view, setView] = useState<VulnView>(loadView);
  const { has } = useAuth();
  const row = useMemo(() => {
    if (!data.data) return undefined;
    // без прогона хост с данными есть, даже если уязвимостей нет
    const r = byHost(data.data.findings.filter(isIssue), data.data.services)[0];
    return r ?? (data.data.runId !== null ? { host, counts: emptyCounts(), total: 0, maxSeverity: "info" as const, findings: [], services: [], summary: "" } : undefined);
  }, [data.data, host]);
  const info = data.data?.findings.filter((f) => f.severity === "info" && !isFalsePositive(f)) ?? [];
  const falsePositives = data.data?.findings.filter(isFalsePositive) ?? [];
  // «По ПО» показывает и ложные срабатывания (не считая их) — чтобы отметку ПО можно было снять одной кнопкой
  const softwareFindings = useMemo(() => data.data?.findings.filter((f) => f.severity !== "info") ?? [], [data.data]);

  return (
    <>
      <div className="page-head">
        <div>
          <span className="crumbs">
            <Link to={run ? `/hosts?run=${run.id}` : "/hosts"}>Активы</Link> / {host}
          </span>
          <h1 className="mono" style={{ fontSize: 24 }}>
            {host}
          </h1>
          {row?.summary && <span className="muted">{row.summary}</span>}
        </div>
        <div className="actions">
          {has("run_scan") && current && (
            <button type="button" className="btn" onClick={() => setChecking(true)}>
              <Radar size={15} /> Проверить доступность
            </button>
          )}
          {runs.length > 0 && <RunPicker runs={runs} value={run?.id ?? null} onChange={setRun} latestLabel="Последние данные" />}
        </div>
      </div>
      {error && <ErrorAlert error={error} />}
      {current && has("view_engagements") && <HostAccounting engagementId={current.id} host={host} canWrite={has("manage_engagements")} />}
      {data.error && <ErrorAlert error={data.error} onRetry={data.reload} />}
      {(loading && !runs.length) || (data.loading && !data.data) ? (
        <Loading />
      ) : !runs.length ? (
        <div className="card">
          <Empty title="Нет завершённых прогонов" />
        </div>
      ) : !row || data.data?.runId == null ? (
        <div className="card">
          <Empty title={run ? "Хост не найден в этом прогоне" : "Хост ещё не проверялся"}>
            {run ? "Выберите «Последние данные», чтобы увидеть последние известные уязвимости хоста." : "Уязвимости появятся после прогона, который проверит этот хост."}
          </Empty>
        </div>
      ) : (
        <>
          {data.data.moduleRuns && <LatestSources moduleRuns={data.data.moduleRuns} onPick={setRun} />}
          <section className="kpis">
            <Kpi label="Уязвимостей" value={row.total} />
            <Kpi label="Критических" value={row.counts.critical} tone={row.counts.critical ? "critical" : undefined} />
            <Kpi label="Высоких" value={row.counts.high} tone={row.counts.high ? "warn" : undefined} />
            <Kpi label="Открытых портов" value={row.services.length} />
            <Kpi label="С привязкой к БДУ" value={row.findings.filter((f) => f.bdu_ids.length).length} />
          </section>
          <section className="row">
            <div className="card card-pad grow-1 stack" style={{ gap: 14, alignSelf: "flex-start" }}>
              <h2>По уровню опасности</h2>
              <SeverityBars counts={row.counts} />
            </div>
            <div className="card grow-2" style={{ overflow: "hidden", alignSelf: "flex-start" }}>
              <div className="card-head">
                <h2>Сервисы</h2>
              </div>
              <ServicesTable services={row.services} />
            </div>
          </section>
          <section className="card" style={{ overflow: "hidden" }}>
            <div className="card-head">
              <h2>Уязвимости хоста</h2>
              <div className="seg seg-sm" role="radiogroup" aria-label="Вид списка уязвимостей">
                {VIEWS.map((v) => (
                  <button
                    key={v.id}
                    type="button"
                    role="radio"
                    aria-checked={view === v.id}
                    onClick={() => {
                      setView(v.id);
                      saveView(v.id);
                    }}
                  >
                    {v.label}
                  </button>
                ))}
              </div>
            </div>
            {view === "software" ? (
              <SoftwareTable
                findings={softwareFindings}
                services={row.services}
                onOpen={setOpen}
                selected={open}
                runId={data.data.runId}
                host={host}
                triage={has("triage_findings")}
                onChanged={() => void data.reload()}
              />
            ) : !row.findings.length ? (
              <Empty title="Уязвимостей не найдено" />
            ) : (
              <FindingsTable findings={row.findings} onOpen={setOpen} selected={open} hideHost />
            )}
          </section>
          {falsePositives.length > 0 && (
            <details className="card">
              <summary style={{ padding: "14px 20px", cursor: "pointer", fontWeight: 600 }}>Ложные срабатывания ({falsePositives.length})</summary>
              <FindingsTable findings={falsePositives} onOpen={setOpen} selected={open} hideHost />
            </details>
          )}
          {data.data!.packages.length > 0 && <PackagesCard packages={data.data!.packages} />}
          {info.length > 0 && (
            <details className="card">
              <summary style={{ padding: "14px 20px", cursor: "pointer", fontWeight: 600 }}>Информационные находки ({info.length})</summary>
              <FindingsTable findings={info} onOpen={setOpen} selected={open} hideHost />
            </details>
          )}
        </>
      )}
      {open && (
        <FindingDrawer
          finding={open}
          onClose={() => setOpen(null)}
          onChanged={(u) => {
            if (data.data) data.setData({ ...data.data, findings: replaceFinding(data.data.findings, u) });
            setOpen(u);
          }}
        />
      )}
      {checking && current && (
        <Modal title="Проверка доступности хоста" onClose={() => setChecking(false)} wide>
          <ReachabilityCheck engagementId={current.id} initialTarget={host} />
        </Modal>
      )}
    </>
  );
}

/** Откуда последние данные хоста: прогон каждого вида проверки, со ссылкой на прогон. */
function LatestSources({ moduleRuns, onPick }: { moduleRuns: Record<string, number>; onPick: (id: number) => void }) {
  const byRun = new Map<number, string[]>();
  for (const [module, id] of Object.entries(moduleRuns)) byRun.set(id, [...(byRun.get(id) ?? []), MODULE_LABEL[module] ?? module]);
  const list = [...byRun.entries()].sort((a, b) => b[0] - a[0]);
  return (
    <p className="muted" style={{ margin: "0 0 13px", fontSize: 13 }}>
      Последние известные данные
      {list.length > 1 ? " — собраны из нескольких прогонов: " : ": "}
      {list.map(([id, mods], i) => (
        <span key={id}>
          {i > 0 && "; "}
          <button type="button" className="link-btn" onClick={() => onPick(id)} title={`Показать только прогон №${id}`}>
            прогон №{id}
          </button>{" "}
          <span className="faint">({mods.sort().join(", ")})</span>
        </span>
      ))}
      . Если в новом прогоне хост был недоступен или не было учётной записи, остаются данные прошлого.
    </p>
  );
}

/**
 * Учётные атрибуты хоста (бывшая вкладка «Активы», R7): критичность для
 * приоритета R6, владелец и группы для уведомлений R9 и разрезов отчётов.
 */
function HostAccounting({ engagementId, host, canWrite }: { engagementId: number; host: string; canWrite: boolean }) {
  const assets = useAsync(() => api.assets(engagementId), [engagementId]);
  const groups = useAsync(() => api.assetGroups(engagementId), [engagementId], canWrite);
  const [editing, setEditing] = useState(false);
  const asset: AssetOut | null = assets.data?.find((a) => a.address === host) ?? null;
  if (assets.error) return <ErrorAlert error={assets.error} onRetry={assets.reload} />;
  if (!assets.data) return null;
  return (
    <section className="card card-pad host-accounting" aria-label="Учёт актива">
      <div className="inline" style={{ gap: 21, flexWrap: "wrap", alignItems: "center" }}>
        <span className="stack" style={{ gap: 2 }}>
          <small className="faint">Критичность</small>
          <CriticalityBadge value={asset?.criticality ?? "medium"} implicit={!asset} />
        </span>
        <span className="stack" style={{ gap: 2 }}>
          <small className="faint">Владелец</small>
          <span>{asset?.owner ?? <span className="faint">—</span>}</span>
        </span>
        {asset?.last_seen_at && (
          <span className="stack" style={{ gap: 2 }} title={asset.first_seen_at ? `Впервые обнаружен ${fmtDate(asset.first_seen_at)}` : undefined}>
            <small className="faint">Обнаружен</small>
            <span>
              {fmtDate(asset.last_seen_at)} <small className="faint">{SOURCE_LABEL[asset.source ?? "manual"]}</small>
            </span>
          </span>
        )}
        {asset?.hostname && (
          <span className="stack" style={{ gap: 2 }}>
            <small className="faint">Имя</small>
            <span>{asset.hostname}</span>
          </span>
        )}
        <span className="stack" style={{ gap: 2 }}>
          <small className="faint">Группы и теги</small>
          <span className="inline" style={{ gap: 4, flexWrap: "wrap" }}>
            {asset && (asset.groups.length || asset.tags.length) ? (
              <>
                {asset.groups.map((g) => (
                  <span key={`g${g.id}`} className="chip chip-static">
                    {g.name}
                  </span>
                ))}
                {asset.tags.map((t) => (
                  <span key={`t${t}`} className="chip chip-static">
                    #{t}
                  </span>
                ))}
              </>
            ) : (
              <span className="faint">—</span>
            )}
          </span>
        </span>
        {asset?.notes && (
          <span className="stack muted" style={{ gap: 2, flex: "1 1 220px" }}>
            <small className="faint">Заметки</small>
            <span style={{ whiteSpace: "pre-wrap" }}>{asset.notes}</span>
          </span>
        )}
        {canWrite && (
          <button type="button" className="btn btn-sm" style={{ marginLeft: "auto" }} onClick={() => setEditing(true)}>
            <Pencil size={14} /> Изменить
          </button>
        )}
      </div>
      {editing && (
        <AssetModal
          asset={asset}
          presetAddress={asset ? undefined : host}
          groups={groups.data ?? []}
          onClose={() => setEditing(false)}
          onSave={async (data) => {
            if (asset) await api.updateAsset(engagementId, asset.id, data);
            else await api.createAsset(engagementId, data);
            setEditing(false);
            await assets.reload();
          }}
        />
      )}
    </section>
  );
}

/** Установленные пакеты хоста (инвентаризация по учётной записи), с поиском. */
function PackagesCard({ packages }: { packages: PackageOut[] }) {
  const [q, setQ] = useState("");
  const needle = q.trim().toLowerCase();
  const shown = needle ? packages.filter((p) => p.name.toLowerCase().includes(needle) || p.version.toLowerCase().includes(needle)) : packages;
  return (
    <details className="card">
      <summary style={{ padding: "14px 20px", cursor: "pointer", fontWeight: 600 }}>
        Установленные пакеты ({packages.length}) — по учётной записи
      </summary>
      <div style={{ padding: "0 20px 12px" }}>
        <input className="input" value={q} onChange={(e) => setQ(e.target.value)} placeholder="Поиск по имени или версии" aria-label="Поиск пакета" />
      </div>
      <div className="table-wrap" style={{ maxHeight: 480, overflowY: "auto" }}>
        <table className="table">
          <thead>
            <tr>
              <th>Пакет</th>
              <th>Версия</th>
              <th>Архитектура</th>
              <th>Менеджер</th>
            </tr>
          </thead>
          <tbody>
            {shown.slice(0, 2000).map((p) => (
              <tr key={`${p.manager}:${p.name}:${p.version}`}>
                <td className="mono">{p.name}</td>
                <td className="mono muted">{p.version}</td>
                <td className="muted">{p.arch ?? "—"}</td>
                <td className="muted">{p.manager}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </details>
  );
}
