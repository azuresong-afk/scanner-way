import { ChevronLeft, ChevronRight } from "lucide-react";
import { PAGE_SIZES } from "../lib/useFindingsPage";


/** «Показано 51–100 из 2 340» и переключение страниц (серверная пагинация). */
export function Pager({
  total,
  offset,
  limit,
  onChange,
  onLimit,
  label = "Страницы",
}: {
  total: number;
  offset: number;
  limit: number;
  onChange: (offset: number) => void;
  onLimit?: (limit: number) => void;
  label?: string;
}) {
  const page = Math.floor(offset / limit) + 1;
  const pages = Math.max(1, Math.ceil(total / limit));
  const from = total === 0 ? 0 : offset + 1;
  const to = Math.min(total, offset + limit);
  const fmt = (n: number) => n.toLocaleString("ru-RU");
  return (
    <nav className="pager" aria-label={label}>
      <span className="muted" aria-live="polite">
        {total === 0 ? "Нет записей" : `Показано ${fmt(from)}–${fmt(to)} из ${fmt(total)}`}
      </span>
      <span className="pager-controls">
        {onLimit && (
          <label className="faint" style={{ fontSize: 12 }}>
            по{" "}
            <select className="input input-sm" value={limit} onChange={(e) => onLimit(Number(e.target.value))} aria-label="Записей на странице">
              {PAGE_SIZES.map((n) => (
                <option key={n} value={n}>
                  {n}
                </option>
              ))}
            </select>
          </label>
        )}
        <button type="button" className="btn btn-sm" disabled={page <= 1} onClick={() => onChange(Math.max(0, offset - limit))} aria-label="Предыдущая страница">
          <ChevronLeft size={14} />
        </button>
        <span className="num" style={{ minWidth: 72, textAlign: "center" }}>
          {fmt(page)} / {fmt(pages)}
        </span>
        <button type="button" className="btn btn-sm" disabled={page >= pages} onClick={() => onChange(offset + limit)} aria-label="Следующая страница">
          <ChevronRight size={14} />
        </button>
      </span>
    </nav>
  );
}
