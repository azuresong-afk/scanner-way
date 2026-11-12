import { Clock } from "lucide-react";
import { useAuth } from "../auth/AuthContext";

/** Предупреждение о скором выходе: по бездействию (можно продлить) или по
 * пределу сеанса (SCANNER_API_SESSION_MAX_HOURS — нужен новый вход). */
export function SessionNotice() {
  const { session, extend, logout } = useAuth();
  if (session.kind !== "warn") return null;
  const min = Math.max(1, Math.ceil(session.leftMs / 60_000));
  return (
    <div className="alert alert-warn session-notice" role="status" aria-live="polite">
      <Clock size={16} style={{ flex: "none", marginTop: 1 }} />
      <span style={{ flex: 1 }}>
        {session.final
          ? `Сеанс входа закончится через ${min} мин. Сохраните работу и войдите заново.`
          : `Вы давно ничего не делали: выход через ${min} мин.`}
      </span>
      {session.final ? (
        <button type="button" className="btn btn-sm" onClick={logout}>
          Войти заново
        </button>
      ) : (
        <button type="button" className="btn btn-sm btn-primary" onClick={() => void extend()}>
          Продолжить работу
        </button>
      )}
    </div>
  );
}
