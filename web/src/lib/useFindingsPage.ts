import { useEffect, useState } from "react";
import { api } from "../api/client";
import type { FindingOut, FindingQuery, Page } from "../api/types";
import type { SortState } from "../components/FindingsTable";
import { useAsync } from "./useAsync";

/** Размеры страницы серверных списков. */
export const PAGE_SIZES = [25, 50, 100, 200];

/** Направление клиентской сортировки -> параметры API (dir 1 — «естественный»
 *  порядок ключа: опасные сначала, ранг 1 первым, А→Я). */
export function sortParams(s: SortState): Pick<FindingQuery, "sort" | "order"> {
  return { sort: s.key, order: s.dir === 1 ? "asc" : "desc" };
}

/** Страница находок прогона с сервера; при смене фильтра — на первую страницу. */
export function useFindingsPage(runId: number | undefined, filter: FindingQuery, opts: { sort: SortState; offset: number; limit: number }) {
  const key = JSON.stringify(filter);
  const page = useAsync<Page<FindingOut>>(
    () => api.findingsPage(runId!, { ...filter, ...sortParams(opts.sort), limit: opts.limit, offset: opts.offset }),
    [runId, key, opts.sort.key, opts.sort.dir, opts.offset, opts.limit],
    runId !== undefined,
  );
  return page;
}

/** Значение с задержкой (поиск по мере ввода не дёргает API на каждую букву). */
export function useDebounced<T>(value: T, ms = 300): T {
  const [v, setV] = useState(value);
  useEffect(() => {
    const t = setTimeout(() => setV(value), ms);
    return () => clearTimeout(t);
  }, [value, ms]);
  return v;
}
