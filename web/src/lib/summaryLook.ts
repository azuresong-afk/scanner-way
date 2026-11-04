import { useCallback, useState } from "react";

/** Вид «Сводки»: новый (2.0) или прежний — оставлен на всякий случай. */
export type SummaryLook = "new" | "classic";

const KEY = "scanner.summaryLook";

function saved(): SummaryLook {
  try {
    return localStorage.getItem(KEY) === "classic" ? "classic" : "new";
  } catch {
    return "new";
  }
}

/** Выбор вида сводки, запоминается в браузере (как тема). */
export function useSummaryLook(): [SummaryLook, (v: SummaryLook) => void] {
  const [look, setLook] = useState<SummaryLook>(saved);
  const set = useCallback((v: SummaryLook) => {
    setLook(v);
    try {
      localStorage.setItem(KEY, v);
    } catch {
      /* выбор продержится до перезагрузки */
    }
  }, []);
  return [look, set];
}
