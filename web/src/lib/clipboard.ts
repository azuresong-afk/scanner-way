import { useCallback, useEffect, useRef, useState } from "react";

/**
 * Копирование текста в буфер обмена.
 *
 * `navigator.clipboard` есть только в защищённом контексте (https или localhost).
 * Стенд обычно открыт по http на IP (http://10.0.0.5:18080) — там `navigator.clipboard`
 * равен undefined, и кнопки «Скопировать» молча ничего не делали. Поэтому сначала
 * пробуем Clipboard API, а если его нет или он отказал — старый способ через скрытое
 * textarea и document.execCommand("copy"), который работает и по http.
 *
 * Возвращает true, если текст скопирован.
 */
export async function copyText(text: string): Promise<boolean> {
  if (typeof navigator !== "undefined" && navigator.clipboard?.writeText) {
    try {
      await navigator.clipboard.writeText(text);
      return true;
    } catch {
      /* нет разрешения — пробуем запасной способ */
    }
  }
  return legacyCopy(text);
}

function legacyCopy(text: string): boolean {
  if (typeof document === "undefined" || typeof document.execCommand !== "function") return false;
  const prevFocus = document.activeElement as HTMLElement | null;
  // Внутри модального окна textarea кладём в само окно, чтобы ловушка фокуса его не увела.
  const host = prevFocus?.closest?.("[role='dialog']") ?? document.body;
  const ta = document.createElement("textarea");
  ta.value = text;
  ta.setAttribute("readonly", "");
  ta.setAttribute("aria-hidden", "true");
  ta.style.position = "fixed";
  ta.style.top = "0";
  ta.style.left = "0";
  ta.style.width = "1px";
  ta.style.height = "1px";
  ta.style.opacity = "0";
  ta.style.pointerEvents = "none";
  host.appendChild(ta);
  let ok = false;
  try {
    ta.focus({ preventScroll: true });
    ta.select();
    ta.setSelectionRange(0, text.length);
    ok = document.execCommand("copy");
  } catch {
    ok = false;
  } finally {
    ta.remove();
    prevFocus?.focus?.({ preventScroll: true });
  }
  return ok;
}

/** Выделяет содержимое элемента, чтобы его можно было скопировать вручную (Ctrl+C). */
export function selectContents(el: Element | null): void {
  if (!el) return;
  const sel = window.getSelection();
  if (!sel) return;
  const range = document.createRange();
  range.selectNodeContents(el);
  sel.removeAllRanges();
  sel.addRange(range);
}

export type CopyState = "idle" | "ok" | "fail";

/**
 * Состояние кнопки «Скопировать»: "ok" — «Скопировано» на 1,5 с,
 * "fail" — подсказка выделить текст вручную (держится 4 с).
 */
export function useCopy(): [CopyState, (text: string, fallbackEl?: Element | null) => Promise<boolean>] {
  const [state, setState] = useState<CopyState>("idle");
  const timer = useRef<number | undefined>(undefined);
  useEffect(() => () => window.clearTimeout(timer.current), []);
  const copy = useCallback(async (text: string, fallbackEl?: Element | null) => {
    const ok = await copyText(text);
    if (!ok) selectContents(fallbackEl ?? null);
    setState(ok ? "ok" : "fail");
    window.clearTimeout(timer.current);
    timer.current = window.setTimeout(() => setState("idle"), ok ? 1500 : 4000);
    return ok;
  }, []);
  return [state, copy];
}
