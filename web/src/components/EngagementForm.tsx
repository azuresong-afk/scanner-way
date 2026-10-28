import { useState, type FormEvent } from "react";
import type { EngagementIn, EngagementOut } from "../api/types";
import { ErrorAlert, Modal } from "./ui";

export function EngagementForm({
  initial,
  onSubmit,
  onClose,
  title,
}: {
  initial?: EngagementOut;
  onSubmit: (data: EngagementIn) => Promise<void>;
  onClose: () => void;
  title: string;
}) {
  const [name, setName] = useState(initial?.name ?? "");
  const [client, setClient] = useState(initial?.client ?? "");
  const [ref, setRef] = useState(initial?.contract_ref ?? "");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      await onSubmit({ name: name.trim(), client: client.trim() || null, contract_ref: ref.trim() || null });
    } catch (err) {
      setError((err as Error).message);
      setBusy(false);
    }
  };

  return (
    <Modal
      title={title}
      onClose={onClose}
      footer={
        <>
          <button type="button" className="btn" onClick={onClose}>
            Отмена
          </button>
          <button type="submit" form="engagement-form" className="btn btn-primary" disabled={busy || !name.trim()}>
            Сохранить
          </button>
        </>
      }
    >
      <form id="engagement-form" className="stack" onSubmit={submit}>
        <label className="field">
          <span>Название работ</span>
          <input className="input" value={name} onChange={(e) => setName(e.target.value)} required maxLength={256} placeholder="Внешний периметр, 2026 Q4" />
        </label>
        <label className="field">
          <span>Заказчик</span>
          <input className="input" value={client} onChange={(e) => setClient(e.target.value)} maxLength={256} />
        </label>
        <label className="field">
          <span>Номер договора</span>
          <input className="input" value={ref} onChange={(e) => setRef(e.target.value)} maxLength={256} />
        </label>
        {error && <ErrorAlert error={error} />}
      </form>
    </Modal>
  );
}
