import { useState, type FormEvent } from "react";
import { Link, useNavigate, useParams } from "react-router-dom";
import { ListChecks, Pencil, Plus, Trash2 } from "lucide-react";
import { ApiError, api } from "../api/client";
import { useAuth } from "../auth/AuthContext";
import { useEngagement } from "../auth/EngagementContext";
import { CredentialsCard } from "../components/CredentialsCard";
import { CredSetsCard } from "../components/CredSetsCard";
import { Empty, ErrorAlert, Loading, Modal } from "../components/ui";
import { fmtDate } from "../lib/format";
import { compactAddresses, isIpOrCidr, parseTargets, specSize } from "../lib/targets";
import type { AllowlistBulkOut, AllowlistOut } from "../api/types";
import { useAsync } from "../lib/useAsync";
import { EngagementForm } from "../components/EngagementForm";
import { HostPicker } from "../components/HostPicker";

export function EngagementDetailPage() {
  const id = Number(useParams().id);
  const { has } = useAuth();
  const { reload: reloadList, select, current } = useEngagement();
  const navigate = useNavigate();
  const eng = useAsync(() => api.engagement(id), [id]);
  const allow = useAsync(() => api.allowlist(id), [id]);
  const [editing, setEditing] = useState(false);
  const [deleting, setDeleting] = useState(false);
  const [cidr, setCidr] = useState("");
  const [note, setNote] = useState("");
  const [allowError, setAllowError] = useState<string | null>(null);
  const [dupId, setDupId] = useState<number | null>(null);
  const [busy, setBusy] = useState(false);
  const [allowInfo, setAllowInfo] = useState<string | null>(null);
  const [picking, setPicking] = useState(false);
  const [pickError, setPickError] = useState<string | null>(null);

  if (eng.loading && !eng.data) return <Loading />;
  if (eng.error) return <ErrorAlert error={eng.error} onRetry={eng.reload} />;
  const e = eng.data!;
  const canAllow = has("manage_allowlist");

  /** Итог массового добавления — одной строкой; дубль подсвечивает покрывающую запись. */
  const applyBulk = (res: AllowlistBulkOut) => {
    const parts: string[] = [];
    if (res.added.length) {
      const items = new Set(res.added.map((a) => a.range_spec ?? a.cidr));
      parts.push(`Добавлено записей: ${items.size}`);
    }
    if (res.skipped.length) {
      parts.push(`уже в allowlist: ${res.skipped.map((x) => (x.existing_cidr && x.existing_cidr !== x.item ? `${x.item} (входит в ${x.existing_cidr})` : x.item)).slice(0, 5).join(", ")}${res.skipped.length > 5 ? "…" : ""}`);
    }
    if (res.partial.length) parts.push(`частично уже были: ${res.partial.map((x) => x.item).join(", ")}`);
    setAllowInfo(parts.join("; ") || null);
    const first = res.skipped.find((x) => x.existing_cidr);
    const existing = first ? allow.data?.find((a) => a.cidr === first.existing_cidr) : undefined;
    setDupId(existing?.id ?? null);
  };

  const add = async (ev: FormEvent) => {
    ev.preventDefault();
    const { targets: items, invalid } = parseTargets(cidr);
    if (invalid.length || items.length === 0) {
      setAllowError(
        `Не IP-адрес, подсеть или диапазон: ${invalid.slice(0, 5).join(", ")}. Примеры: 10.0.0.5, 10.0.0.0/24, 10.0.0.1-10.0.0.50 или 10.0.0.1-50`,
      );
      return;
    }
    setBusy(true);
    setAllowError(null);
    setAllowInfo(null);
    setDupId(null);
    try {
      if (items.length === 1 && isIpOrCidr(items[0])) {
        await api.addAllowlist(id, { cidr: items[0], note: note.trim() || null });
      } else {
        applyBulk(await api.addAllowlistBulk(id, { items, note: note.trim() || null }));
      }
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

  const addPicked = async (addrs: string[]) => {
    setBusy(true);
    setPickError(null);
    setAllowError(null);
    setDupId(null);
    try {
      applyBulk(await api.addAllowlistBulk(id, { items: compactAddresses(addrs), note: note.trim() || "из «Активов»" }));
      setPicking(false);
      await allow.reload();
    } catch (err) {
      setPickError((err as Error).message);
    } finally {
      setBusy(false);
    }
  };

  const remove = async (entryId: number, wholeRange = false) => {
    setAllowError(null);
    setAllowInfo(null);
    setDupId(null);
    try {
      await api.removeAllowlist(id, entryId, wholeRange);
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
            <Link to="/engagements">Проекты</Link> / {e.client ?? "Без заказчика"}
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
        </div>
      </div>

      <section className="card" style={{ overflow: "hidden" }}>
        <div className="card-head">
          <h2>Allowlist — разрешённые цели</h2>
          <span className="faint" style={{ fontSize: 12 }}>
            Сканер не выходит за эти диапазоны
          </span>
        </div>
        {canAllow && (
          <form onSubmit={add} className="inline" style={{ padding: "0 20px 14px", alignItems: "flex-end" }}>
            <label className="field" style={{ flex: "1 1 240px" }}>
              <span>IP, подсеть или диапазон</span>
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
            {has("view_report") && (
              <button type="button" className="btn" onClick={() => (setPickError(null), setPicking(true))}>
                <ListChecks size={16} /> Из активов…
              </button>
            )}
            <small className="muted" style={{ flexBasis: "100%" }}>
              Можно несколько через запятую или с новой строки. Диапазон: 10.0.0.1-10.0.0.50 или коротко 10.0.0.1-50.
            </small>
          </form>
        )}
        {allowInfo && (
          <div style={{ padding: "0 20px 14px" }}>
            <div className="alert alert-info" role="status">
              {allowInfo}
            </div>
          </div>
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
                {allowRows(allow.data!).map(({ entry: a, label, parts }) => {
                  const hit = parts.some((p) => p.id === dupId);
                  const isRange = parts.length > 1 || !!a.range_spec;
                  return (
                    <tr key={a.id} className={hit ? "selected" : undefined} aria-current={hit || undefined}>
                      <td className="mono">
                        {label}
                        {isRange && (
                          <small className="faint os-name" title={parts.map((p) => p.cidr).join(", ")}>
                            диапазон · {parts.reduce((n, p) => n + specSize(p.cidr), 0).toLocaleString("ru-RU")} адресов
                          </small>
                        )}
                      </td>
                      <td className="muted">{a.note ?? "—"}</td>
                      <td className="muted nowrap">{fmtDate(a.added_at)}</td>
                      {canAllow && (
                        <td className="right">
                          <button
                            type="button"
                            className="btn btn-sm btn-ghost"
                            aria-label={`Удалить ${label}`}
                            onClick={() => remove(a.id, isRange)}
                          >
                            <Trash2 size={14} />
                          </button>
                        </td>
                      )}
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </section>

      {has("host_credentials") && <CredentialsCard engagementId={e.id} />}

      {has("cred_audit") && <CredSetsCard engagementId={e.id} />}

      {editing && (
        <EngagementForm
          title="Изменить проект"
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
      {picking && (
        <HostPicker
          engagementId={id}
          allowlist={(allow.data ?? []).map((a) => a.cidr)}
          mode="allowlist"
          busy={busy}
          error={pickError}
          onClose={() => setPicking(false)}
          onPick={addPicked}
        />
      )}
    </>
  );
}

/** Строки таблицы allowlist: подсети одного диапазона — одной строкой. */
function allowRows(entries: AllowlistOut[]): { entry: AllowlistOut; label: string; parts: AllowlistOut[] }[] {
  const rows: { entry: AllowlistOut; label: string; parts: AllowlistOut[] }[] = [];
  const byRange = new Map<string, { entry: AllowlistOut; label: string; parts: AllowlistOut[] }>();
  for (const e of entries) {
    if (e.range_spec) {
      const row = byRange.get(e.range_spec);
      if (row) {
        row.parts.push(e);
        continue;
      }
      const created = { entry: e, label: e.range_spec, parts: [e] };
      byRange.set(e.range_spec, created);
      rows.push(created);
    } else {
      rows.push({ entry: e, label: e.cidr, parts: [e] });
    }
  }
  return rows;
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
      setError(msg.includes("scan runs") ? "По проекту уже были прогоны — его история сохраняется, удаление невозможно." : msg);
      setBusy(false);
    }
  };
  return (
    <Modal
      title="Удалить проект?"
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
        Проект «{name}» и его allowlist будут удалены. Проект с прогонами удалить нельзя.
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
