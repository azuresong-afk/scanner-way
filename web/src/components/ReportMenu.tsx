import { useEffect, useState } from "react";
import { Download, Eye } from "lucide-react";
import { api } from "../api/client";
import type { AssetGroupOut, ReportFormat, ReportVariant, RunOut } from "../api/types";
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
      saveBlob(await api.report(runId, fmt, variant, compareTo, groupId), `report-run-${runId}${suffix}.${fmt}`);
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
      setHtml(await (await api.report(runId, "html", variant, compareTo, groupId)).text());
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
