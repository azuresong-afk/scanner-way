import { useRef, useState } from "react";
import { Download, HardDriveUpload, KeyRound, Upload, XCircle } from "lucide-react";
import { ApiError, api } from "../api/client";
import type { OfflineImportOut, OfflineResultHeader, RunOut } from "../api/types";
import { useAuth } from "../auth/AuthContext";
import { fmtDateFull, plural } from "../lib/format";
import { saveBlob } from "../lib/download";
import { useAsync } from "../lib/useAsync";
import { ErrorAlert, Loading, Modal } from "./ui";

const VALID_DAYS = [7, 14, 30, 60];
const PILL: Record<string, string> = { exported: "pill-info pill-running", imported: "pill-ok", cancelled: "pill-muted", expired: "pill-danger" };

/**
 * Автономный прогон на его странице: «Выгрузить задание» → носитель → узел →
 * «Загрузить результат». Связи между центром и узлом нет.
 */
export function OfflineJobPanel({ run, onChanged }: { run: RunOut; onChanged: () => void }) {
  const { has } = useAuth();
  const job = useAsync(
    () => api.offlineJob(run.id).catch((e) => (e instanceof ApiError && e.status === 404 ? null : Promise.reject(e))),
    [run.id, run.status],
  );
  const [days, setDays] = useState(14);
  const [busy, setBusy] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [cancelAsk, setCancelAsk] = useState(false);
  const canRun = has("run_scan");
  const node = run.node_name ?? "автономный узел";

  const act = async (name: string, fn: () => Promise<void>) => {
    setBusy(name);
    setError(null);
    try {
      await fn();
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(null);
    }
  };

  const exportJob = () =>
    act("export", async () => {
      const f = await api.exportOfflineJob(run.id, days);
      saveBlob(f.blob, f.name);
      job.reload();
      onChanged();
    });
  const again = () =>
    act("again", async () => {
      const f = await api.downloadOfflineJob(run.id);
      saveBlob(f.blob, f.name);
    });
  const cancel = () =>
    act("cancel", async () => {
      await api.cancelOfflineJob(run.id);
      setCancelAsk(false);
      job.reload();
      onChanged();
    });

  if (job.loading && job.data === undefined) return <Loading />;
  if (job.error) return <ErrorAlert error={job.error} onRetry={job.reload} />;
  const j = job.data ?? null;

  return (
    <section className="card card-pad stack offline-job" style={{ gap: 12 }} aria-label="Автономный узел">
      <div className="inline" style={{ gap: 10 }}>
        <HardDriveUpload size={18} aria-hidden="true" />
        <h2 style={{ margin: 0 }}>Автономный узел «{node}»</h2>
        {j && <span className={`pill ${PILL[j.status] ?? "pill-muted"}`}>{j.status_label}</span>}
      </div>

      {!j && run.status === "pending" && (
        <>
          <p className="muted" style={{ margin: 0 }}>
            Связи с узлом нет. Выгрузите задание, перенесите файл на узел и выполните там{" "}
            <code>scanner node run-job &lt;файл&gt; --out /media --confirm-authorized</code>. Цели и учётные записи в файле зашифрованы на
            ключ узла, задание подписано ключом центра.
          </p>
          {canRun && (
            <div className="inline" style={{ gap: 10, flexWrap: "wrap" }}>
              <label className="inline" style={{ gap: 6 }}>
                <span className="muted">Срок действия</span>
                <select className="select" value={days} onChange={(e) => setDays(Number(e.target.value))} aria-label="Срок действия задания">
                  {VALID_DAYS.map((d) => (
                    <option key={d} value={d}>
                      {d} {plural(d, ["день", "дня", "дней"])}
                    </option>
                  ))}
                </select>
              </label>
              <button type="button" className="btn btn-primary" onClick={exportJob} disabled={!!busy}>
                <Download size={14} /> {busy === "export" ? "Готовим файл…" : "Выгрузить задание"}
              </button>
            </div>
          )}
        </>
      )}

      {j && (
        <dl className="kv" style={{ gridTemplateColumns: "180px minmax(0,1fr)", margin: 0 }}>
          <dt>Задание</dt>
          <dd className="mono">{j.job_id}</dd>
          <dt>Выгружено</dt>
          <dd>
            {fmtDateFull(j.exported_at)} · {j.exported_by.replace(/^user:/, "")}
          </dd>
          {j.status === "exported" && (
            <>
              <dt>Действует до</dt>
              <dd>{fmtDateFull(j.expires_at)}</dd>
            </>
          )}
          <dt>Ключ узла</dt>
          <dd className="mono">{j.node_fingerprint}</dd>
          {j.imported_at && (
            <>
              <dt>Результат загружен</dt>
              <dd>
                {fmtDateFull(j.imported_at)} · {(j.imported_by ?? "").replace(/^user:/, "")}
              </dd>
              <dt>Выполнено на узле</dt>
              <dd>
                {fmtDateFull(j.result_summary?.started_at)} — {fmtDateFull(j.result_summary?.finished_at)}
              </dd>
              <dt>Справочники узла</dt>
              <dd>{j.result_summary?.reference_as_of ? `на ${j.result_summary.reference_as_of}` : "дата неизвестна"}</dd>
            </>
          )}
        </dl>
      )}

      {j?.status === "exported" && (
        <>
          <p className="muted" style={{ margin: 0 }}>
            Прогон ждёт результат с носителя. Если результат не загрузить в течение 3 дней после срока действия, прогон завершится
            ошибкой.
          </p>
          {canRun && (
            <div className="inline" style={{ gap: 10, flexWrap: "wrap" }}>
              <OfflineResultUpload onDone={() => onChanged()} expectRunId={run.id} />
              <button type="button" className="btn" onClick={again} disabled={!!busy}>
                <Download size={14} /> Скачать задание ещё раз
              </button>
              <button type="button" className="btn btn-ghost" onClick={() => setCancelAsk(true)} disabled={!!busy}>
                <XCircle size={14} /> Отменить задание
              </button>
            </div>
          )}
        </>
      )}

      {error && <ErrorAlert error={error} />}
      {cancelAsk && (
        <Modal
          title="Отменить задание?"
          onClose={() => setCancelAsk(false)}
          footer={
            <>
              <button type="button" className="btn" onClick={() => setCancelAsk(false)}>
                Не отменять
              </button>
              <button type="button" className="btn btn-danger" onClick={cancel} disabled={busy === "cancel"}>
                Отменить задание
              </button>
            </>
          }
        >
          <p style={{ margin: 0 }}>
            Прогон будет остановлен, а результат по этому заданию центр больше не примет, даже если узел его уже выполнил. Файл задания
            на носителе станет бесполезным.
          </p>
        </Modal>
      )}
    </section>
  );
}

/** «Загрузить результат»: выбрать .scnres, посмотреть заголовок, загрузить. */
export function OfflineResultUpload({ onDone, expectRunId }: { onDone: (r: OfflineImportOut) => void; expectRunId?: number }) {
  const input = useRef<HTMLInputElement>(null);
  const [file, setFile] = useState<File | null>(null);
  const [head, setHead] = useState<OfflineResultHeader | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [done, setDone] = useState<OfflineImportOut | null>(null);

  const pick = async (f: File | undefined) => {
    if (!f) return;
    setFile(f);
    setHead(null);
    setDone(null);
    setError(null);
    try {
      setHead(await api.previewOfflineResult(f));
    } catch (e) {
      setError((e as Error).message);
    }
  };
  const close = () => {
    setFile(null);
    setHead(null);
    setError(null);
    if (input.current) input.current.value = "";
  };
  const submit = async () => {
    if (!file) return;
    setBusy(true);
    setError(null);
    try {
      const r = await api.importOfflineResult(file);
      setDone(r);
      onDone(r);
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  };
  const otherRun = head && expectRunId !== undefined && head.run_id !== expectRunId;

  return (
    <>
      <label className="btn btn-primary" style={{ cursor: "pointer" }}>
        <Upload size={14} /> Загрузить результат
        <input ref={input} type="file" accept=".scnres" hidden onChange={(e) => void pick(e.target.files?.[0])} />
      </label>
      {file && (
        <Modal
          title="Результат с автономного узла"
          onClose={close}
          footer={
            done ? (
              <button type="button" className="btn btn-primary" onClick={close}>
                Готово
              </button>
            ) : (
              <>
                <button type="button" className="btn" onClick={close}>
                  Отмена
                </button>
                <button type="button" className="btn btn-primary" onClick={submit} disabled={!head || busy}>
                  {busy ? "Проверяем и сохраняем…" : "Загрузить"}
                </button>
              </>
            )
          }
        >
          <div className="stack" style={{ gap: 10 }}>
            <div className="mono faint" style={{ fontSize: 12 }}>
              {file.name}
            </div>
            {!head && !error && <Loading label="Читаем заголовок…" />}
            {head && (
              <dl className="kv" style={{ gridTemplateColumns: "150px minmax(0,1fr)", margin: 0 }}>
                <dt>Прогон</dt>
                <dd>
                  №{head.run_id} {head.run_name ? `«${head.run_name}»` : ""}
                </dd>
                {head.engagement && (
                  <>
                    <dt>Договор</dt>
                    <dd>{head.engagement}</dd>
                  </>
                )}
                <dt>Узел</dt>
                <dd>{head.node_name}</dd>
                <dt>Выполнено</dt>
                <dd>
                  {fmtDateFull(head.started_at)} — {fmtDateFull(head.finished_at)}
                </dd>
                <dt>Итог</dt>
                <dd>
                  {head.hosts} {plural(head.hosts, ["хост", "хоста", "хостов"])}, {head.findings}{" "}
                  {plural(head.findings, ["находка", "находки", "находок"])}
                </dd>
                <dt>Справочники узла</dt>
                <dd>{head.reference_as_of ? `на ${head.reference_as_of}` : "дата неизвестна"}</dd>
              </dl>
            )}
            {otherRun && (
              <div className="alert alert-warn">
                <span>Файл относится к прогону №{head!.run_id}, а не к этому. Результат загрузится в свой прогон.</span>
              </div>
            )}
            <p className="muted" style={{ margin: 0, fontSize: 13 }}>
              Заголовок показан до проверки. При загрузке центр проверит подпись узла, привязку к выгруженному заданию и allowlist
              договора; подделанный, чужой или повторный файл не примется.
            </p>
            {done && (
              <div className="alert alert-ok">
                <span>
                  Результат загружен: прогон №{done.run_id}, {done.findings ?? 0} {plural(done.findings ?? 0, ["находка", "находки", "находок"])}.
                </span>
              </div>
            )}
            {error && <ErrorAlert error={error} />}
          </div>
        </Modal>
      )}
    </>
  );
}

/**
 * Ключи автономного узла в его карточке на «Сканерах»: ключ центра для
 * установки узла и загрузка node.pub с узла (без ключа узла задание не выгрузить).
 */
export function NodeKeyCard({ nodeId, nodeName, onChanged }: { nodeId: number; nodeName: string; onChanged?: () => void }) {
  const { has } = useAuth();
  const center = useAsync(() => api.centerKey(), []);
  const key = useAsync(() => api.nodeKey(nodeId), [nodeId]);
  const [open, setOpen] = useState(false);
  const [text, setText] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const canEdit = has("manage_nodes");
  const fingerprint = key.data?.fingerprint ?? null;

  const download = async () => {
    try {
      const f = await api.centerKeyFile();
      saveBlob(f.blob, f.name);
    } catch (e) {
      setError((e as Error).message);
    }
  };
  const readFile = async (f: File | undefined) => {
    if (f) setText(await f.text());
  };
  const cancel = () => {
    setOpen(false);
    setText("");
    setError(null);
  };
  const save = async () => {
    setBusy(true);
    setError(null);
    try {
      key.setData(await api.setNodeKey(nodeId, text));
      setText("");
      setOpen(false);
      onChanged?.();
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  };

  return (
    <section className="node-offline stack" style={{ gap: 10 }} aria-label={`Ключи автономного узла «${nodeName}»`}>
      <dl className="node-facts">
        <div>
          <dt>Ключ центра</dt>
          <dd>
            {center.error ? (
              <span style={{ color: "var(--danger)" }}>{center.error.message}</span>
            ) : (
              <span className="inline" style={{ gap: 8, flexWrap: "wrap" }}>
                <span className="mono" style={{ fontSize: 12 }}>
                  {center.data?.fingerprint ?? "…"}
                </span>
                <button type="button" className="btn btn-sm" onClick={download}>
                  <Download size={12} /> center.pub
                </button>
              </span>
            )}
          </dd>
        </div>
        <div>
          <dt>Ключ узла</dt>
          <dd>
            {key.loading && !key.data ? (
              "…"
            ) : fingerprint ? (
              <span className="mono" style={{ fontSize: 12 }}>
                {fingerprint}
              </span>
            ) : (
              <span style={{ color: "var(--warn)" }}>не загружен — задания узлу не выгрузить</span>
            )}
          </dd>
        </div>
      </dl>
      {!fingerprint && !key.loading && (
        <small className="faint">
          Установка: перенесите center.pub на узел, выполните{" "}
          <code>
            scanner node init --name "{nodeName}" --scope &lt;сети&gt; --center-key center.pub --pub-out node.pub
          </code>{" "}
          и загрузите node.pub сюда. Отпечатки сверьте по телефону или по акту.
        </small>
      )}
      {canEdit &&
        (open ? (
          <div className="stack" style={{ gap: 8 }}>
            <textarea
              className="textarea mono"
              value={text}
              onChange={(e) => setText(e.target.value)}
              placeholder="scanner-node-key:v1:…"
              spellCheck={false}
              aria-label={`Открытый ключ узла «${nodeName}»`}
              style={{ fontSize: 12, minHeight: 64 }}
            />
            <div className="inline" style={{ gap: 8, flexWrap: "wrap" }}>
              <label className="btn btn-sm" style={{ cursor: "pointer" }}>
                Из файла node.pub
                <input type="file" accept=".pub,text/plain" hidden onChange={(e) => void readFile(e.target.files?.[0])} />
              </label>
              <button type="button" className="btn btn-sm btn-primary" disabled={!text.trim() || busy} onClick={save}>
                {busy ? "Проверяем…" : "Сохранить"}
              </button>
              <button type="button" className="btn btn-sm" onClick={cancel}>
                Отмена
              </button>
            </div>
            {fingerprint && (
              <small className="faint">Пока у узла есть невыполненные задания, ключ не заменить: сначала загрузите их результаты или отмените.</small>
            )}
          </div>
        ) : (
          <div>
            <button type="button" className="btn btn-sm" onClick={() => setOpen(true)}>
              <KeyRound size={12} /> {fingerprint ? "Заменить ключ узла" : "Загрузить ключ узла"}
            </button>
          </div>
        ))}
      {error && <ErrorAlert error={error} />}
    </section>
  );
}
