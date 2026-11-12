import { useState } from "react";
import { Download } from "lucide-react";
import { saveBlob } from "../lib/download";
import type { ExportOption } from "../lib/exports";

/**
 * Кнопки «Выгрузить: Excel · CSV» для таблиц («Все находки», «Что исправить»).
 * Файл приходит с сервера с теми же фильтрами, что на экране (эндпоинты требуют
 * Bearer, поэтому — fetch и сохранение Blob, а не обычная ссылка).
 */
export function ExportButtons({
  options,
  load,
  what,
}: {
  options: ExportOption[];
  load: (id: string) => Promise<{ blob: Blob; name: string }>;
  /** Что выгружается — для подписи кнопок у экранного диктора. */
  what: string;
}) {
  const [busy, setBusy] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const run = async (id: string) => {
    setBusy(id);
    setError(null);
    try {
      const f = await load(id);
      saveBlob(f.blob, f.name);
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(null);
    }
  };
  return (
    <span className="inline" style={{ gap: 6 }} role="group" aria-label={`Выгрузить ${what}`}>
      <span className="faint" style={{ fontSize: 12 }}>
        Выгрузить
      </span>
      {options.map((o) => (
        <button
          key={o.id}
          type="button"
          className="btn btn-sm"
          disabled={!!busy}
          title={o.title}
          aria-label={`Выгрузить ${what}: ${o.label}`}
          onClick={() => void run(o.id)}
        >
          {busy === o.id ? <span className="spinner" style={{ width: 14, height: 14 }} /> : <Download size={14} aria-hidden="true" />}
          {o.label}
        </button>
      ))}
      {error && (
        <small role="alert" style={{ color: "var(--danger)" }}>
          Не удалось выгрузить: {error}
        </small>
      )}
    </span>
  );
}
