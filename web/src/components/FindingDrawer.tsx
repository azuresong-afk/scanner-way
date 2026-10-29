import { useState } from "react";
import { ExternalLink, EyeOff, Undo2 } from "lucide-react";
import { api } from "../api/client";
import type { FindingOut } from "../api/types";
import { useAuth } from "../auth/AuthContext";
import { fmtDateFull } from "../lib/format";
import { FINDING_TYPE_LABEL, MODULE_LABEL } from "../lib/labels";
import { bduUrl, cveUrl } from "../lib/refs";
import { Drawer, FindingStatusPill, SeverityBadge } from "./ui";

/** Карточка находки: идентификаторы БДУ/CVE, хост, доказательство и ссылки на устранение. */
export function FindingDrawer({
  finding,
  onClose,
  onHost,
  onChanged,
}: {
  finding: FindingOut;
  onClose: () => void;
  onHost?: (host: string) => void;
  /** Находка обновилась (поставили или сняли отметку «ложное срабатывание»). */
  onChanged?: (updated: FindingOut) => void;
}) {
  const links = [
    ...finding.bdu_ids.map((id) => ({ label: `БДУ ФСТЭК: ${id}`, url: bduUrl(id) })),
    ...finding.cve_ids.map((id) => ({ label: `NVD: ${id}`, url: cveUrl(id) })),
  ].filter((l): l is { label: string; url: string } => !!l.url);

  return (
    <Drawer
      title={finding.title}
      onClose={onClose}
      header={
        <div className="inline">
          <SeverityBadge severity={finding.severity} />
          {finding.cvss !== null && <span className="muted">CVSS {finding.cvss.toFixed(1)}</span>}
          <FindingStatusPill status={finding.status} />
          {finding.false_positive && <span className="pill pill-muted">Ложное срабатывание</span>}
        </div>
      }
    >
      <FalsePositiveSection key={finding.id} finding={finding} onChanged={onChanged} />
      <dl className="kv">
        <dt>БДУ ФСТЭК</dt>
        <dd>
          {finding.bdu_ids.length ? (
            finding.bdu_ids.map((id) => {
              const url = bduUrl(id);
              return url ? (
                <a key={id} className="tag" href={url} target="_blank" rel="noopener noreferrer">
                  {id}
                </a>
              ) : (
                <span key={id} className="tag">
                  {id}
                </span>
              );
            })
          ) : (
            <span className="faint">нет сопоставления</span>
          )}
        </dd>
        <dt>CVE</dt>
        <dd>
          {finding.cve_ids.length ? (
            finding.cve_ids.map((id) => (
              <span key={id} className="tag tag-muted">
                {id}
              </span>
            ))
          ) : (
            <span className="faint">—</span>
          )}
        </dd>
        <dt>Идентификатор</dt>
        <dd className="mono">{finding.vuln_id ?? "—"}</dd>
        <dt>Хост</dt>
        <dd className="mono">
          {onHost ? (
            <button type="button" className="btn btn-sm btn-ghost mono" style={{ padding: 0, height: "auto" }} onClick={() => onHost(finding.host)}>
              {finding.host}
              {finding.port ? `:${finding.port}` : ""}
            </button>
          ) : (
            <>
              {finding.host}
              {finding.port ? `:${finding.port}` : ""}
            </>
          )}
        </dd>
        <dt>Модуль</dt>
        <dd>{MODULE_LABEL[finding.module] ?? finding.module}</dd>
        <dt>Тип</dt>
        <dd>{FINDING_TYPE_LABEL[finding.finding_type] ?? finding.finding_type}</dd>
        <dt>Обнаружено</dt>
        <dd>{fmtDateFull(finding.detected_at)}</dd>
      </dl>

      {links.length > 0 && (
        <section className="stack" style={{ gap: 8 }}>
          <h3>Ссылки на устранение</h3>
          <div className="links">
            {links.map((l) => (
              <a key={l.url} href={l.url} target="_blank" rel="noopener noreferrer">
                <ExternalLink size={14} aria-hidden="true" />
                {l.label}
              </a>
            ))}
          </div>
          <span className="faint" style={{ fontSize: 12 }}>
            Подробные рекомендации из справочника БДУ и бюллетени производителей — в отчёте по прогону.
          </span>
        </section>
      )}

      <section className="stack" style={{ gap: 8 }}>
        <h3>Доказательство</h3>
        {finding.evidence ? <pre className="evidence">{finding.evidence}</pre> : <span className="faint">Не сохранено</span>}
      </section>
    </Drawer>
  );
}

/** Отметка «ложное срабатывание»: поставить с обоснованием или снять. */
function FalsePositiveSection({ finding, onChanged }: { finding: FindingOut; onChanged?: (updated: FindingOut) => void }) {
  const { has } = useAuth();
  const canTriage = has("triage_findings");
  const [editing, setEditing] = useState(false);
  const [reason, setReason] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const mark = finding.false_positive;
  const where = `${finding.host}${finding.port ? `:${finding.port}` : ""}`;

  const act = async (fn: () => Promise<FindingOut>) => {
    setBusy(true);
    setError(null);
    try {
      const updated = await fn();
      setEditing(false);
      setReason("");
      onChanged?.(updated);
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  };

  if (!mark && !canTriage) return null;
  return (
    <section className="stack" style={{ gap: 8 }} aria-label="Ложное срабатывание">
      {mark ? (
        <div className="alert alert-info" style={{ flexDirection: "column", gap: 6 }}>
          <strong>Отмечено как ложное срабатывание</strong>
          <span>
            {mark.marked_by ?? "—"}
            {mark.marked_at ? `, ${fmtDateFull(mark.marked_at)}` : ""}
          </span>
          {mark.reason && <span style={{ color: "var(--text)" }}>{mark.reason}</span>}
          <span className="faint" style={{ fontSize: 12 }}>
            Не учитывается в сводке, отчётах и сравнении прогонов. Действует для этой находки на {where} во всех прогонах договора.
          </span>
          {canTriage && (
            <div>
              <button type="button" className="btn btn-sm" disabled={busy} onClick={() => void act(() => api.unmarkFalsePositive(finding.id))}>
                <Undo2 size={14} /> Снять отметку
              </button>
            </div>
          )}
        </div>
      ) : editing ? (
        <form
          className="stack"
          style={{ gap: 8 }}
          onSubmit={(e) => {
            e.preventDefault();
            void act(() => api.markFalsePositive(finding.id, reason.trim() || null));
          }}
        >
          <label className="field">
            <span>Обоснование</span>
            <textarea
              className="textarea"
              style={{ fontFamily: "inherit", minHeight: 72 }}
              value={reason}
              onChange={(e) => setReason(e.target.value)}
              maxLength={2000}
              placeholder="Например: исправление перенесено в пакет дистрибутива (бэкпорт)"
              autoFocus
            />
            <small>Необязательно. Попадёт в отчёт и журнал аудита. Отметка действует для этой находки на {where} и в следующих прогонах.</small>
          </label>
          <div className="inline">
            <button type="submit" className="btn btn-sm btn-primary" disabled={busy}>
              Отметить
            </button>
            <button type="button" className="btn btn-sm btn-ghost" disabled={busy} onClick={() => setEditing(false)}>
              Отмена
            </button>
          </div>
        </form>
      ) : (
        <div>
          <button type="button" className="btn btn-sm" onClick={() => setEditing(true)}>
            <EyeOff size={14} /> Отметить как ложное срабатывание
          </button>
        </div>
      )}
      {error && (
        <div className="alert alert-danger" role="alert">
          {error}
        </div>
      )}
    </section>
  );
}
