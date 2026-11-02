import { useEffect, useRef, useState } from "react";
import { Download, Eye } from "lucide-react";
import { api } from "../api/client";
import type { AssetGroupOut, ReportFormat, ReportSections, ReportVariant, RunOut } from "../api/types";
import { saveBlob } from "../lib/download";
import { fmtDate } from "../lib/format";
import { Modal } from "./ui";

const FORMATS: { id: ReportFormat; label: string }[] = [
  { id: "pdf", label: "PDF" },
  { id: "docx", label: "Word" },
  { id: "html", label: "HTML" },
  { id: "json", label: "JSON" },
];

const VARIANTS: { id: ReportVariant; label: string; hint: string }[] = [
  { id: "full", label: "Полный", hint: "С планом устранения и рекомендациями по каждой находке" },
  { id: "brief", label: "Краткий", hint: "Без плана устранения; по находкам — только ссылки на устранение" },
];

/**
 * Кнопки выгрузки отчёта: файл скачивается через fetch с Bearer-токеном.
 * По умолчанию кнопки полного размера — как соседние «Новый прогон» и «Остановить»
 * в шапке страницы; `small` — для строк таблицы. Переключатель «Полный / Краткий»
 * задаёт версию для скачивания и просмотра.
 *
 * Отчёт по умолчанию строится только по этому прогону. Если передан список прогонов
 * договора (`runs`), появляется «Сравнить с»: можно выбрать более ранний успешно
 * завершённый прогон, и в отчёт добавятся новые/закрытые/регрессии и тренд.
 *
 * «Разделы» — необязательные части отчёта: «План устранения» (в кратком его нет всегда)
 * и «Соответствие» по каждому профилю договора (ФСТЭК №117 нужен не всем — только ГИС).
 * По умолчанию профили отмечены по признаку «в отчёт» со страницы «Соответствие».
 */
export function ReportMenu({
  runId,
  disabled,
  compact,
  small,
  runs,
  engagementId,
}: {
  runId: number;
  disabled?: boolean;
  compact?: boolean;
  small?: boolean;
  runs?: RunOut[];
  /** Договор: если задан и в нём есть группы активов, появляется «Группа» — отчёт только по её хостам. */
  engagementId?: number;
}) {
  const [busy, setBusy] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [html, setHtml] = useState<string | null>(null);
  const [variant, setVariant] = useState<ReportVariant>("full");
  const [compareTo, setCompareTo] = useState<number | null>(null);
  const [groupId, setGroupId] = useState<number | null>(null);
  const [groups, setGroups] = useState<AssetGroupOut[]>([]);
  const [withPlan, setWithPlan] = useState(true);
  // Профили соответствия договора: id, подпись и отмечен ли для этого отчёта.
  const [profiles, setProfiles] = useState<{ id: string; label: string; on: boolean }[]>([]);
  useEffect(() => {
    if (engagementId === undefined) return;
    Promise.all([api.complianceProfiles(engagementId), api.complianceCatalog().catch(() => [])]).then(
      ([rows, catalog]) =>
        setProfiles(
          rows.map((r) => ({
            id: r.profile,
            label: catalog.find((c) => c.id === r.profile)?.short ?? r.profile,
            on: r.in_report,
          })),
        ),
      () => setProfiles([]),
    );
  }, [engagementId]);
  // «Выбрать все»: план (если он доступен — не в кратком) и все профили соответствия.
  const sectionFlags = [...(variant === "brief" ? [] : [withPlan]), ...profiles.map((p) => p.on)];
  const allOn = sectionFlags.length > 0 && sectionFlags.every(Boolean);
  const someOn = sectionFlags.some(Boolean) && !allOn;
  const allRef = useRef<HTMLInputElement>(null);
  useEffect(() => {
    if (allRef.current) allRef.current.indeterminate = someOn;
  }, [someOn]);
  const setAll = (on: boolean) => {
    setWithPlan(on);
    setProfiles((ps) => ps.map((p) => ({ ...p, on })));
  };
  const sections: ReportSections = {
    ...(withPlan ? {} : { plan: false }),
    ...(profiles.length > 0 ? { compliance: profiles.filter((p) => p.on).map((p) => p.id) } : {}),
  };
  useEffect(() => {
    if (engagementId === undefined) return;
    // Группы нужны только для необязательного разреза; без права на активы отчёт остаётся полным.
    api.assetGroups(engagementId).then((g) => setGroups(g.filter((x) => x.asset_count > 0)), () => setGroups([]));
  }, [engagementId]);
  // Сравнивать можно только с более ранним успешно завершённым прогоном — так же проверяет API.
  const baselines = (runs ?? []).filter((r) => r.id < runId && r.status === "done").sort((a, b) => b.id - a.id);
  const suffix = (variant === "brief" ? "-brief" : "") + (compareTo === null ? "" : `-vs-${compareTo}`) + (groupId === null ? "" : `-group-${groupId}`);

  const download = async (fmt: ReportFormat) => {
    setBusy(fmt);
    setError(null);
    try {
      saveBlob(await api.report(runId, fmt, variant, compareTo, groupId, sections), `report-run-${runId}${suffix}.${fmt}`);
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(null);
    }
  };

  // Предпросмотр — в iframe с пустым sandbox: отчёт содержит данные со сканируемых
  // хостов, поэтому он не получает ни скриптов, ни доступа к origin интерфейса.
  const preview = async () => {
    setBusy("view");
    setError(null);
    try {
      setHtml(await (await api.report(runId, "html", variant, compareTo, groupId, sections)).text());
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(null);
    }
  };

  // Кнопки форматов одной ширины, чтобы ряд PDF/Word/HTML/JSON не «гулял».
  const btn = small ? "btn btn-sm" : "btn btn-report";
  const icon = small ? 14 : 16;

  return (
    <div className="stack" style={{ gap: 6 }}>
      <div className="inline" style={{ gap: small ? 6 : 13 }}>
        <div className={`seg${small ? " seg-sm" : ""}`} role="radiogroup" aria-label="Версия отчёта">
          {VARIANTS.map((v) => (
            <button
              key={v.id}
              type="button"
              role="radio"
              aria-checked={variant === v.id}
              title={v.hint}
              disabled={disabled || !!busy}
              onClick={() => setVariant(v.id)}
            >
              {v.label}
            </button>
          ))}
        </div>
        {baselines.length > 0 && (
          <label className={`inline report-compare${small ? " sm" : ""}`} style={{ gap: 8 }}>
            <span className="faint nowrap" style={{ fontSize: 13 }}>
              Сравнить с
            </span>
            <select
              className="select"
              aria-label="Сравнить с прогоном"
              value={compareTo ?? ""}
              disabled={disabled || !!busy}
              onChange={(e) => setCompareTo(e.target.value === "" ? null : Number(e.target.value))}
            >
              <option value="">без сравнения</option>
              {baselines.map((r) => (
                <option key={r.id} value={r.id}>
                  №{r.id} · {fmtDate(r.finished_at ?? r.started_at)}
                </option>
              ))}
            </select>
          </label>
        )}
        {groups.length > 0 && (
          <label className={`inline report-compare${small ? " sm" : ""}`} style={{ gap: 8 }}>
            <span className="faint nowrap" style={{ fontSize: 13 }}>
              Группа
            </span>
            <select
              className="select"
              aria-label="Группа активов"
              value={groupId ?? ""}
              disabled={disabled || !!busy}
              onChange={(e) => setGroupId(e.target.value === "" ? null : Number(e.target.value))}
            >
              <option value="">все активы</option>
              {groups.map((g) => (
                <option key={g.id} value={g.id}>
                  {g.name}
                </option>
              ))}
            </select>
          </label>
        )}
        {!compact && (
          <button type="button" className={`${btn} btn-report-view`} disabled={disabled || !!busy} onClick={preview}>
            {busy === "view" ? <span className="spinner" style={{ width: icon, height: icon }} /> : <Eye size={icon} />}
            Просмотр
          </button>
        )}
        {FORMATS.map((f) => (
          <button
            key={f.id}
            type="button"
            className={btn}
            disabled={disabled || !!busy}
            onClick={() => download(f.id)}
            aria-label={`Скачать отчёт ${f.label}`}
          >
            {busy === f.id ? <span className="spinner" style={{ width: icon, height: icon }} /> : <Download size={icon} />}
            {f.label}
          </button>
        ))}
      </div>
      {!compact && (
        <div className={`inline report-sections${small ? " sm" : ""}`} role="group" aria-label="Разделы отчёта">
          <span className="faint nowrap">Разделы:</span>
          <label className="inline nowrap">
            <input
              ref={allRef}
              type="checkbox"
              checked={allOn}
              disabled={disabled || !!busy || sectionFlags.length === 0}
              onChange={(e) => setAll(e.target.checked)}
            />
            Выбрать все
          </label>
          <label className="inline nowrap" title={variant === "brief" ? "В кратком отчёте плана устранения нет" : undefined}>
            <input
              type="checkbox"
              checked={withPlan && variant !== "brief"}
              disabled={disabled || !!busy || variant === "brief"}
              onChange={(e) => setWithPlan(e.target.checked)}
            />
            План устранения
          </label>
          {profiles.map((p) => (
            <label key={p.id} className="inline nowrap">
              <input
                type="checkbox"
                checked={p.on}
                disabled={disabled || !!busy}
                onChange={(e) => setProfiles((ps) => ps.map((x) => (x.id === p.id ? { ...x, on: e.target.checked } : x)))}
              />
              Соответствие: {p.label}
            </label>
          ))}
        </div>
      )}
      {error && <span style={{ color: "var(--danger)", fontSize: 12 }}>{error}</span>}
      {html !== null && (
        <Modal
          title={`${variant === "brief" ? "Краткий отчёт" : "Отчёт"} по прогону №${runId}${compareTo === null ? "" : ` · сравнение с №${compareTo}`}${groupId === null ? "" : ` · ${groups.find((g) => g.id === groupId)?.name ?? "группа"}`}`}
          onClose={() => setHtml(null)}
          wide
        >
          <iframe title={`Отчёт по прогону №${runId}`} sandbox="" srcDoc={html} className="report-frame" />
        </Modal>
      )}
    </div>
  );
}
