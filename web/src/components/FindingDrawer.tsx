import { ExternalLink } from "lucide-react";
import type { FindingOut } from "../api/types";
import { fmtDateFull } from "../lib/format";
import { FINDING_TYPE_LABEL, MODULE_LABEL } from "../lib/labels";
import { bduUrl, cveUrl } from "../lib/refs";
import { Drawer, FindingStatusPill, SeverityBadge } from "./ui";

/** Карточка находки: идентификаторы БДУ/CVE, хост, доказательство и ссылки на устранение. */
export function FindingDrawer({ finding, onClose, onHost }: { finding: FindingOut; onClose: () => void; onHost?: (host: string) => void }) {
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
        </div>
      }
    >
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
