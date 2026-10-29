import { useState, type FormEvent } from "react";
import { Link, useNavigate, useParams } from "react-router-dom";
import { Pencil, Play, Plus, Trash2 } from "lucide-react";
import { ApiError, api } from "../api/client";
import { useAuth } from "../auth/AuthContext";
import { useEngagement } from "../auth/EngagementContext";
import { StartRunModal } from "../components/StartRunModal";
import { Empty, ErrorAlert, Loading, Modal, RunStatusPill } from "../components/ui";
import { fmtDate, fmtDuration } from "../lib/format";
import { RATE_PROFILES, moduleList } from "../lib/labels";
import { isIpOrCidr } from "../lib/targets";
import { useAsync } from "../lib/useAsync";
import { EngagementForm } from "../components/EngagementForm";

export function EngagementDetailPage() {
  const id = Number(useParams().id);
  const { has } = useAuth();
  const { reload: reloadList, select, current } = useEngagement();
  const navigate = useNavigate();
  const eng = useAsync(() => api.engagement(id), [id]);
  const allow = useAsync(() => api.allowlist(id), [id]);
  const runs = useAsync(() => api.runs(id), [id], has("view_report"));
  const [editing, setEditing] = useState(false);
  const [deleting, setDeleting] = useState(false);
  const [starting, setStarting] = useState(false);
  const [cidr, setCidr] = useState("");
  const [note, setNote] = useState("");
  const [allowError, setAllowError] = useState<string | null>(null);
  const [dupId, setDupId] = useState<number | null>(null);
  const [busy, setBusy] = useState(false);

  if (eng.loading && !eng.data) return <Loading />;
  if (eng.error) return <ErrorAlert error={eng.error} onRetry={eng.reload} />;
  const e = eng.data!;
  const canAllow = has("manage_allowlist");
  const runList = [...(runs.data ?? [])].sort((a, b) => b.id - a.id);

  const add = async (ev: FormEvent) => {
    ev.preventDefault();
    const value = cidr.trim();
    if (!isIpOrCidr(value)) {
      setAllowError("Укажите IP-адрес или подсеть в нотации CIDR, например 10.0.0.0/24");
      return;
    }
    setBusy(true);
    setAllowError(null);
    setDupId(null);
    try {
      await api.addAllowlist(id, { cidr: value, note: note.trim() || null });
      setCidr("");
      setNote("");
      await allow.reload();
    } catch (err) {
      setAllowError((err as Error).message);
      // 409: цель уже занесена — подсвечиваем запись, которая её покрывает
      const existing = err instanceof ApiError && err.status === 409 ? duplicateOf(err.detail) : null;
      setDupId(existing);
    } finally {
      setBusy(false);
    }
  };

  const remove = async (entryId: number) => {
    setAllowError(null);
    setDupId(null);
    try {
      await api.removeAllowlist(id, entryId);
      await allow.reload();
    } catch (err) {
      setAllowError((err as Error).message);
    }
  };

  return (
    <>
      <div className="page-head">
        <div>
          <span className="crumbs">
            <Link to="/engagements">Договоры</Link> / {e.client ?? "Без заказчика"}
          </span>
          <h1>{e.name}</h1>
          <span className="muted">
            {e.contract_ref ? `Договор ${e.contract_ref} · ` : ""}создан {fmtDate(e.created_at)}
          </span>
        </div>
        <div className="actions">
          {current?.id !== e.id && (
            <button type="button" className="btn" onClick={() => select(e.id)}>
              Сделать текущим
            </button>
          )}
          {has("manage_engagements") && (
            <>
              <button type="button" className="btn" onClick={() => setEditing(true)}>
                <Pencil size={15} /> Изменить
              </button>
              <button type="button" className="btn btn-danger" onClick={() => setDeleting(true)}>
                <Trash2 size={15} /> Удалить
              </button>
            </>
          )}
          {has("run_scan") && (
            <button type="button" className="btn btn-primary" onClick={() => setStarting(true)}>
              <Play size={16} /> Новый прогон
            </button>
          )}
        </div>
      </div>

      <div className="row">
        <section className="card grow-2" style={{ overflow: "hidden", alignSelf: "flex-start" }}>
          <div className="card-head">
            <h2>Allowlist — разрешённые цели</h2>
            <span className="faint" style={{ fontSize: 12 }}>
              Сканер не выходит за эти диапазоны
            </span>
          </div>
          {canAllow && (
            <form onSubmit={add} className="inline" style={{ padding: "0 20px 14px", alignItems: "flex-end" }}>
              <label className="field" style={{ flex: "1 1 180px" }}>
                <span>IP или подсеть</span>
                <input
                  className="input mono"
                  value={cidr}
                  onChange={(ev) => {
                    setCidr(ev.target.value);
                    setDupId(null);
                  }}
                  placeholder="10.0.0.0/24"
                />
              </label>
              <label className="field" style={{ flex: "2 1 220px" }}>
                <span>Комментарий</span>
                <input className="input" value={note} onChange={(ev) => setNote(ev.target.value)} placeholder="ДМЗ, приложение 1 к договору" maxLength={512} />
              </label>
              <button type="submit" className="btn btn-primary" disabled={busy || !cidr.trim()}>
                <Plus size={16} /> Добавить
              </button>
            </form>
          )}
          {allowError && (
            <div style={{ padding: "0 20px 14px" }}>
              <ErrorAlert error={allowError} />
            </div>
          )}
          {allow.loading && !allow.data ? (
            <Loading />
          ) : allow.error ? (
            <div style={{ padding: "0 20px 16px" }}>
              <ErrorAlert error={allow.error} onRetry={allow.reload} />
            </div>
          ) : allow.data!.length === 0 ? (
            <Empty title="Allowlist пуст">Пока здесь нет ни одной цели, запуск прогонов невозможен.</Empty>
          ) : (
            <div className="table-wrap">
              <table className="table">
                <thead>
                  <tr>
                    <th>Диапазон</th>
                    <th>Комментарий</th>
                    <th>Добавлен</th>
                    {canAllow && <th />}
                  </tr>
                </thead>
                <tbody>
                  {allow.data!.map((a) => (
                    <tr key={a.id} className={a.id === dupId ? "selected" : undefined} aria-current={a.id === dupId || undefined}>
                      <td className="mono">{a.cidr}</td>
                      <td className="muted">{a.note ?? "—"}</td>
                      <td className="muted nowrap">{fmtDate(a.added_at)}</td>
                      {canAllow && (
                        <td className="right">
                          <button type="button" className="btn btn-sm btn-ghost" aria-label={`Удалить ${a.cidr}`} onClick={() => remove(a.id)}>
                            <Trash2 size={14} />
                          </button>
                        </td>
                      )}
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </section>

        {has("view_report") && (
          <section className="card grow-3" style={{ overflow: "hidden", alignSelf: "flex-start" }}>
            <div className="card-head">
              <h2>Прогоны по договору</h2>
            </div>
            {runs.loading && !runs.data ? (
              <Loading />
            ) : runs.error ? (
              <div style={{ padding: "0 20px 16px" }}>
                <ErrorAlert error={runs.error} onRetry={runs.reload} />
              </div>
            ) : runList.length === 0 ? (
              <Empty title="Прогонов ещё не было" />
            ) : (
              <div className="table-wrap">
                <table className="table" style={{ minWidth: 560 }}>
                  <thead>
                    <tr>
                      <th>№</th>
                      <th>Модули</th>
                      <th>Профиль</th>
                      <th>Статус</th>
                      <th>Начат</th>
                      <th>Длительность</th>
                    </tr>
                  </thead>
                  <tbody>
                    {runList.map((r) => (
                      <tr key={r.id} className="clickable" onClick={() => navigate(`/runs/${r.id}`)}>
                        <td className="mono">
                          <Link to={`/runs/${r.id}`} onClick={(ev) => ev.stopPropagation()}>
                            #{r.id}
                          </Link>
                        </td>
                        <td className="muted">{moduleList(r.modules)}</td>
                        <td className="muted">{RATE_PROFILES.find((p) => p.id === r.rate_profile)?.label ?? r.rate_profile}</td>
                        <td>
                          <RunStatusPill status={r.status} />
                        </td>
                        <td className="muted nowrap">{fmtDate(r.started_at ?? r.created_at)}</td>
                        <td className="muted nowrap">{fmtDuration(r.started_at, r.finished_at)}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </section>
        )}
      </div>

      {editing && (
        <EngagementForm
          title="Изменить договор"
          initial={e}
          onClose={() => setEditing(false)}
          onSubmit={async (data) => {
            eng.setData(await api.updateEngagement(id, data));
            await reloadList();
            setEditing(false);
          }}
        />
      )}
      {deleting && <DeleteEngagement id={id} name={e.name} onClose={() => setDeleting(false)} onDone={async () => {
        await reloadList();
        navigate("/engagements");
      }} />}
      {starting && (
        <StartRunModal engagement={e} onClose={() => setStarting(false)} onStarted={(run) => navigate(`/runs/${run.id}`)} />
      )}
    </>
  );
}

function DeleteEngagement({ id, name, onClose, onDone }: { id: number; name: string; onClose: () => void; onDone: () => void }) {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const confirm = async () => {
    setBusy(true);
    try {
      await api.deleteEngagement(id);
      onDone();
    } catch (err) {
      const msg = (err as Error).message;
      setError(msg.includes("scan runs") ? "По договору уже были прогоны — его история сохраняется, удаление невозможно." : msg);
      setBusy(false);
    }
  };
  return (
    <Modal
      title="Удалить договор?"
      onClose={onClose}
      footer={
        <>
          <button type="button" className="btn" onClick={onClose}>
            Отмена
          </button>
          <button type="button" className="btn btn-danger" disabled={busy} onClick={confirm}>
            Удалить
          </button>
        </>
      }
    >
      <p style={{ margin: 0 }}>
        Договор «{name}» и его allowlist будут удалены. Договор с прогонами удалить нельзя.
      </p>
      {error && <ErrorAlert error={error} />}
    </Modal>
  );
}

function duplicateOf(detail: unknown): number | null {
  if (detail && typeof detail === "object" && "existing_id" in detail) {
    const v = (detail as { existing_id: unknown }).existing_id;
    return typeof v === "number" ? v : null;
  }
  return null;
}
