import { useRef, useState } from "react";
import { KeyRound, RotateCcw, Square } from "lucide-react";
import { ApiError, api } from "../api/client";
import type {
  CredHostStatus,
  CredLoginStatus,
  CredentialHostCheckOut,
} from "../api/types";
import { ErrorAlert, Modal } from "./ui";

/** Сколько хостов уходит в один запрос: результаты появляются по мере проверки. */
const CHECK_BATCH = 4;

const CRED_STATUS_LABEL: Record<CredHostStatus, string> = {
  ok: "Вход выполнен",
  partial: "Частично",
  auth_failed: "Отказ в доступе",
  timeout: "Таймаут",
  unreachable: "Недоступен",
  host_key_mismatch: "Ключ хоста изменился",
  no_credential: "Нет учётки",
  not_in_allowlist: "Вне allowlist",
  error: "Ошибка",
};

const TONE: Record<CredHostStatus, string> = {
  ok: "pill-ok",
  partial: "pill-warn",
  auth_failed: "pill-danger",
  timeout: "pill-warn",
  unreachable: "pill-danger",
  host_key_mismatch: "pill-danger",
  no_credential: "pill-muted",
  not_in_allowlist: "pill-muted",
  error: "pill-danger",
};

/** Подсказка, что делать, — для итогов, где причина не очевидна из названия. */
const PROTOCOL_SHORT: Record<string, string> = { ssh: "SSH", winrm: "WinRM", netssh: "SSH", snmp: "SNMP" };

const HINT: Partial<Record<CredLoginStatus | CredHostStatus, string>> = {
  auth_failed:
    "Проверьте логин и пароль/ключ учётки; для SSH — что вход по паролю разрешён (PasswordAuthentication).",
  timeout:
    "Хост выключен или порт закрыт межсетевым экраном между сканером и хостом.",
  unreachable: "Порт закрыт или служба (sshd / WinRM) не запущена.",
  host_key_mismatch:
    "Ключ или сертификат хоста не совпадает с запомненным: возможна подмена. Если хост переустанавливали — удалите старую запись (known_hosts / known_certs).",
  no_credential:
    "Область действия ни одной учётки проекта не покрывает этот адрес — заведите учётку или расширьте область.",
};

export function CredStatusPill({
  status,
  title,
}: {
  status: CredHostStatus;
  title?: string;
}) {
  return (
    <span className={`pill ${TONE[status]}`} title={title}>
      {CRED_STATUS_LABEL[status]}
    </span>
  );
}

function errorMessage(err: unknown): string {
  if (!(err instanceof ApiError)) return (err as Error).message;
  if (err.status === 403)
    return "Недостаточно прав: нужны права на запуск прогонов и на учётные записи активов.";
  if (err.status === 429)
    return "Лимит проверок на минуту исчерпан. Подождите минуту и нажмите «Продолжить».";
  if (err.status === 503)
    return "Не задан ключ шифрования учётных записей (SCANNER_CREDENTIALS_KEY) или он изменился.";
  return err.message;
}

function plural(n: number): string {
  const d = n % 10;
  const dd = n % 100;
  if (d === 1 && dd !== 11) return "хост";
  if (d >= 2 && d <= 4 && (dd < 12 || dd > 14)) return "хоста";
  return "хостов";
}

/**
 * Проверка входа по привязанным учётным записям (SSH / WinRM) для одного или
 * нескольких активов. Только вход и выход, без сканирования; хосты уходят
 * пачками по CHECK_BATCH, таблица заполняется по мере ответа.
 */
export function CredentialCheckModal({
  engagementId,
  hosts,
  onClose,
  onResults,
}: {
  engagementId: number;
  hosts: string[];
  onClose: () => void;
  onResults?: (results: CredentialHostCheckOut[]) => void;
}) {
  const [results, setResults] = useState<Map<string, CredentialHostCheckOut>>(
    new Map(),
  );
  const [running, setRunning] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const stop = useRef(false);

  const pending = hosts.filter((h) => !results.has(h));
  const done = hosts.length - pending.length;
  const failed = hosts.filter((h) => {
    const s = results.get(h)?.status;
    return (
      s !== undefined &&
      s !== "ok" &&
      s !== "no_credential" &&
      s !== "not_in_allowlist"
    );
  });

  async function run(list: string[]) {
    setRunning(true);
    setError(null);
    stop.current = false;
    try {
      for (let i = 0; i < list.length && !stop.current; i += CHECK_BATCH) {
        const r = await api.checkCredentials(engagementId, {
          hosts: list.slice(i, i + CHECK_BATCH),
        });
        setResults((cur) => {
          const next = new Map(cur);
          for (const h of r.hosts) next.set(h.host, h);
          return next;
        });
        onResults?.(r.hosts);
      }
    } catch (err) {
      setError(errorMessage(err));
    } finally {
      setRunning(false);
    }
  }

  function retryFailed() {
    setResults((cur) => {
      const next = new Map(cur);
      for (const h of failed) next.delete(h);
      return next;
    });
    void run(failed);
  }

  const counts = new Map<CredHostStatus, number>();
  for (const r of results.values())
    counts.set(r.status, (counts.get(r.status) ?? 0) + 1);
  const started = running || done > 0;
  const title =
    hosts.length === 1
      ? `Проверка учётных записей ${hosts[0]}`
      : `Проверка учётных записей: ${hosts.length} ${plural(hosts.length)}`;

  return (
    <Modal
      title={title}
      wide
      onClose={() => {
        stop.current = true;
        onClose();
      }}
      footer={
        <>
          {running ? (
            <button
              type="button"
              className="btn"
              onClick={() => (stop.current = true)}
            >
              <Square size={15} /> Остановить
            </button>
          ) : (
            <>
              {failed.length > 0 && pending.length === 0 && (
                <button type="button" className="btn" onClick={retryFailed}>
                  <RotateCcw size={15} /> Повторить неудачные ({failed.length})
                </button>
              )}
              {pending.length > 0 && (
                <button
                  type="button"
                  className="btn btn-primary"
                  onClick={() => void run(pending)}
                >
                  <KeyRound size={16} />{" "}
                  {started
                    ? `Продолжить (${pending.length})`
                    : "Проверить вход"}
                </button>
              )}
            </>
          )}
          <button
            type="button"
            className="btn"
            onClick={() => {
              stop.current = true;
              onClose();
            }}
          >
            Готово
          </button>
        </>
      }
    >
      <div className="stack" style={{ gap: "var(--s3)" }}>
        <p className="muted" style={{ margin: 0, fontSize: 13 }}>
          Для каждого хоста берутся учётные записи проекта, чья область
          действия покрывает его адрес (SSH и WinRM, как в прогоне), и по каждой
          выполняется один вход и сразу выход — без сканирования и без команд на
          хосте. Только адреса из allowlist; каждая проверка — в журнале аудита.
        </p>
        {started && (
          <div
            className="inline"
            style={{ gap: 8, flexWrap: "wrap" }}
            aria-live="polite"
          >
            <span>
              Проверено <b>{done}</b> из {hosts.length}
              {running && "…"}
            </span>
            {[...counts.entries()].map(([s, n]) => (
              <span key={s} className={`pill ${TONE[s]}`}>
                {CRED_STATUS_LABEL[s]}: {n}
              </span>
            ))}
          </div>
        )}
        {error && <ErrorAlert error={error} />}
        <div
          className="table-wrap"
          style={{ maxHeight: "55vh", overflow: "auto" }}
        >
          <table
            className="table"
            aria-label="Результаты проверки учётных записей"
          >
            <thead>
              <tr>
                <th style={{ width: 140 }}>Хост</th>
                <th style={{ width: 170 }}>Итог</th>
                <th>Учётные записи</th>
              </tr>
            </thead>
            <tbody>
              {hosts.map((h) => {
                const r = results.get(h);
                return (
                  <tr key={h}>
                    <td className="mono">{h}</td>
                    <td>
                      {r ? (
                        <CredStatusPill status={r.status} />
                      ) : (
                        <span className="faint">
                          {running ? "ожидает…" : "не проверен"}
                        </span>
                      )}
                    </td>
                    <td>
                      {r && r.results.length === 0 && (
                        <div style={{ fontSize: 13 }}>
                          <span className="muted">{r.message}</span>
                          {HINT[r.status] && (
                            <small
                              className="faint"
                              style={{ display: "block" }}
                            >
                              {HINT[r.status]}
                            </small>
                          )}
                        </div>
                      )}
                      {r?.results.map((x) => (
                        <div
                          key={x.credential_id}
                          className="inline"
                          style={{
                            gap: 6,
                            fontSize: 13,
                            flexWrap: "wrap",
                            padding: "2px 0",
                          }}
                        >
                          <CredStatusPill
                            status={x.status}
                            title={HINT[x.status]}
                          />
                          <b>{x.credential}</b>
                          <span className="mono faint">
                            {x.username} ·{" "}
                            {PROTOCOL_SHORT[x.protocol] ?? "SSH"}:{x.port}
                          </span>
                          <span className="muted">{x.message}</span>
                          <span
                            className="faint"
                            style={{ marginLeft: "auto" }}
                          >
                            {Math.round(x.elapsed_ms)} мс
                          </span>
                        </div>
                      ))}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </div>
    </Modal>
  );
}
