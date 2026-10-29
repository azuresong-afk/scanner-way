import { useState } from "react";
import { Download, Eye } from "lucide-react";
import { api } from "../api/client";
import type { ReportFormat } from "../api/types";
import { saveBlob } from "../lib/download";
import { Modal } from "./ui";

const FORMATS: { id: ReportFormat; label: string }[] = [
  { id: "pdf", label: "PDF" },
  { id: "docx", label: "Word" },
  { id: "html", label: "HTML" },
  { id: "json", label: "JSON" },
];

/**
 * Кнопки выгрузки отчёта: файл скачивается через fetch с Bearer-токеном.
 * По умолчанию кнопки полного размера — как соседние «Новый прогон» и «Остановить»
 * в шапке страницы; `small` — для строк таблицы.
 */
export function ReportMenu({
  runId,
  disabled,
  compact,
  small,
}: {
  runId: number;
  disabled?: boolean;
  compact?: boolean;
  small?: boolean;
}) {
  const [busy, setBusy] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [html, setHtml] = useState<string | null>(null);

  const download = async (fmt: ReportFormat) => {
    setBusy(fmt);
    setError(null);
    try {
      saveBlob(await api.report(runId, fmt), `report-run-${runId}.${fmt}`);
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
      setHtml(await (await api.report(runId, "html")).text());
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
        <Modal title={`Отчёт по прогону №${runId}`} onClose={() => setHtml(null)} wide>
          <iframe title={`Отчёт по прогону №${runId}`} sandbox="" srcDoc={html} className="report-frame" />
        </Modal>
      )}
    </div>
  );
}
