import { useState } from "react";
import { LogOut } from "lucide-react";
import { api } from "../api/client";
import { fmtDate } from "../lib/format";
import { deviceLabel } from "../lib/session";
import { useAsync } from "../lib/useAsync";
import { ErrorAlert, Loading } from "./ui";

/** Профиль → «Сеансы входа»: где я сейчас вошёл, и завершить лишние. */
export function SessionsCard() {
  const list = useAsync(() => api.mySessions(), []);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const others = (list.data ?? []).filter((s) => !s.current).length;

  const act = async (fn: () => Promise<unknown>) => {
    setBusy(true);
    setError(null);
    try {
      await fn();
      await list.reload();
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  };

  return (
    <section className="card stack" style={{ gap: 13, maxWidth: 720, marginTop: 21 }}>
      <div className="inline" style={{ gap: 8, justifyContent: "space-between", flexWrap: "wrap" }}>
        <h2 style={{ margin: 0, fontSize: 16 }}>Сеансы входа</h2>
        {others > 0 && (
          <button type="button" className="btn btn-sm" disabled={busy} onClick={() => void act(() => api.endOtherSessions())}>
            <LogOut size={14} /> Завершить остальные
          </button>
        )}
      </div>
      <span className="muted" style={{ fontSize: 13 }}>
        Вход продлевается, пока вы работаете. После бездействия (по умолчанию 60 минут) или по истечении предельного срока сеанса нужно войти заново. Кнопка «Выйти» закрывает сеанс сразу.
      </span>
      {list.error && <ErrorAlert error={list.error} onRetry={list.reload} />}
      {error && <ErrorAlert error={error} />}
      {!list.data ? (
        !list.error && <Loading />
      ) : (
        <div className="stack" style={{ gap: 8 }}>
          {list.data.map((s) => (
            <div key={s.id} className="inline" style={{ gap: 10, justifyContent: "space-between", flexWrap: "wrap" }}>
              <div className="stack" style={{ gap: 2 }}>
                <span>
                  {deviceLabel(s.user_agent)}
                  {s.current && <span className="pill pill-ok" style={{ marginLeft: 8 }}>Этот сеанс</span>}
                  {s.method === "ldap" && <span className="pill pill-info" style={{ marginLeft: 8 }}>AD</span>}
                </span>
                <span className="faint" style={{ fontSize: 12 }}>
                  {s.client ?? "адрес неизвестен"} · вход {fmtDate(s.created_at)} · активность {fmtDate(s.last_seen_at)}
                  {s.expires_at ? ` · до ${fmtDate(s.expires_at)}` : ""}
                </span>
              </div>
              {!s.current && (
                <button type="button" className="btn btn-sm btn-ghost" disabled={busy} onClick={() => void act(() => api.endMySession(s.id))}>
                  Завершить
                </button>
              )}
            </div>
          ))}
        </div>
      )}
    </section>
  );
}
