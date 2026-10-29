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

/** Кнопки выгрузки отчёта: файл скачивается через fetch с Bearer-токеном. */
export function ReportMenu({ runId, disabled, compact }: { runId: number; disabled?: boolean; compact?: boolean }) {
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

  return (
    <div className="stack" style={{ gap: 6 }}>
      <div className="inline" style={{ gap: 6 }}>
        {!compact && (
          <button type="button" className="btn btn-sm" disabled={disabled || !!busy} onClick={preview}>
            {busy === "view" ? <span className="spinner" style={{ width: 14, height: 14 }} /> : <Eye size={14} />}
            Просмотр
          </button>
        )}
        {FORMATS.map((f) => (
          <button
            key={f.id}
            type="button"
            className="btn btn-sm"
            disabled={disabled || !!busy}
            onClick={() => download(f.id)}
            aria-label={`Скачать отчёт ${f.label}`}
          >
            {busy === f.id ? <span className="spinner" style={{ width: 14, height: 14 }} /> : <Download size={14} />}
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
