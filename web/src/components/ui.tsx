import { useEffect, useRef, type ReactNode } from "react";
import { AlertTriangle, Inbox, X } from "lucide-react";
import type { FindingStatus, RunStatus, Severity } from "../api/types";
import { RUN_STATUS_LABEL, SEVERITY_LABEL, SEVERITY_SHORT, STATUS_LABEL } from "../lib/labels";
import { bduUrl, cveUrl } from "../lib/refs";

export function SeverityBadge({ severity, short }: { severity: Severity; short?: boolean }) {
  return (
    <span className={`sev sev-${severity}`}>
      <i aria-hidden="true" />
      {short ? SEVERITY_SHORT[severity] : SEVERITY_LABEL[severity]}
    </span>
  );
}

const RUN_PILL: Record<RunStatus, string> = {
  pending: "pill-muted pill-running",
  running: "pill-info pill-running",
  done: "pill-ok",
  failed: "pill-danger",
  stopped: "pill-muted",
};

export function RunStatusPill({ status }: { status: RunStatus }) {
  return <span className={`pill ${RUN_PILL[status]}`}>{RUN_STATUS_LABEL[status]}</span>;
}

const FINDING_PILL: Record<FindingStatus, string> = {
  new: "pill-info",
  open: "pill-muted",
  regression: "pill-warn",
  fixed: "pill-ok",
};

export function FindingStatusPill({ status }: { status: FindingStatus | null }) {
  if (!status) return <span className="faint">—</span>;
  return <span className={`pill ${FINDING_PILL[status]}`}>{STATUS_LABEL[status]}</span>;
}

export function RefTags({ cve, bdu, limit }: { cve: string[]; bdu: string[]; limit?: number }) {
  const items = [
    ...bdu.map((id) => ({ id, url: bduUrl(id), kind: "bdu" })),
    ...cve.map((id) => ({ id, url: cveUrl(id), kind: "cve" })),
  ];
  if (!items.length) return <span className="faint">—</span>;
  const shown = limit ? items.slice(0, limit) : items;
  return (
    <span className="inline" style={{ gap: 6 }}>
      {shown.map((r) =>
        r.url ? (
          <a
            key={r.id}
            className={r.kind === "bdu" ? "tag" : "tag tag-muted"}
            href={r.url}
            target="_blank"
            rel="noopener noreferrer"
            onClick={(e) => e.stopPropagation()}
          >
            {r.id}
          </a>
        ) : (
          <span key={r.id} className={r.kind === "bdu" ? "tag" : "tag tag-muted"}>
            {r.id}
          </span>
        ),
      )}
      {limit && items.length > limit && <span className="faint">+{items.length - limit}</span>}
    </span>
  );
}

export function Loading({ label = "Загрузка…" }: { label?: string }) {
  return (
    <div className="loading" role="status">
      <span className="spinner" aria-hidden="true" />
      {label}
    </div>
  );
}

export function ErrorAlert({ error, onRetry }: { error: Error | string; onRetry?: () => void }) {
  return (
    <div className="alert alert-danger" role="alert">
      <AlertTriangle size={16} aria-hidden="true" />
      <span style={{ flex: 1 }}>{typeof error === "string" ? error : error.message}</span>
      {onRetry && (
        <button type="button" className="btn btn-sm" onClick={onRetry}>
          Повторить
        </button>
      )}
    </div>
  );
}

export function Empty({ title, children, icon }: { title: string; children?: ReactNode; icon?: ReactNode }) {
  return (
    <div className="empty">
      {icon ?? <Inbox size={28} aria-hidden="true" />}
      <h3>{title}</h3>
      {children && <div>{children}</div>}
    </div>
  );
}

function useEscape(onClose: () => void) {
  useEffect(() => {
    const h = (e: KeyboardEvent) => e.key === "Escape" && onClose();
    document.addEventListener("keydown", h);
    return () => document.removeEventListener("keydown", h);
  }, [onClose]);
}

function useInitialFocus<T extends HTMLElement>() {
  const ref = useRef<T>(null);
  useEffect(() => {
    const prev = document.activeElement as HTMLElement | null;
    ref.current?.focus();
    return () => prev?.focus?.();
  }, []);
  return ref;
}

export function Modal({
  title,
  onClose,
  children,
  footer,
  wide,
}: {
  title: string;
  onClose: () => void;
  children: ReactNode;
  footer?: ReactNode;
  wide?: boolean;
}) {
  useEscape(onClose);
  const ref = useInitialFocus<HTMLDivElement>();
  return (
    <div className="modal-scrim" onMouseDown={(e) => e.target === e.currentTarget && onClose()}>
      <div className={`modal ${wide ? "modal-wide" : ""}`} role="dialog" aria-modal="true" aria-label={title} tabIndex={-1} ref={ref}>
        <div className="modal-head">
          <h2>{title}</h2>
          <button type="button" className="btn btn-ghost icon-btn" aria-label="Закрыть" onClick={onClose}>
            <X size={18} />
          </button>
        </div>
        <div className="modal-body">{children}</div>
        {footer && <div className="modal-foot">{footer}</div>}
      </div>
    </div>
  );
}

export function Drawer({
  title,
  onClose,
  children,
  header,
}: {
  title: string;
  onClose: () => void;
  children: ReactNode;
  header?: ReactNode;
}) {
  useEscape(onClose);
  const ref = useInitialFocus<HTMLElement>();
  return (
    <>
      <div className="drawer-scrim" onClick={onClose} />
      <aside className="drawer" role="dialog" aria-modal="true" aria-label={title} tabIndex={-1} ref={ref}>
        <div className="drawer-head">
          <div style={{ flex: 1, display: "flex", flexDirection: "column", gap: 8 }}>
            {header}
            <h2>{title}</h2>
          </div>
          <button type="button" className="btn btn-ghost icon-btn" aria-label="Закрыть" onClick={onClose}>
            <X size={18} />
          </button>
        </div>
        <div className="drawer-body">{children}</div>
      </aside>
    </>
  );
}

export function Kpi({
  label,
  value,
  delta,
  tone,
  deltaTone,
}: {
  label: string;
  value: ReactNode;
  delta?: ReactNode;
  tone?: "critical" | "warn";
  deltaTone?: "good" | "bad";
}) {
  return (
    <div className="card kpi">
      <span className="kpi-label">{label}</span>
      <span className={`kpi-value ${tone ?? ""}`}>{value}</span>
      {delta !== undefined && <span className={`kpi-delta ${deltaTone ?? ""}`}>{delta}</span>}
    </div>
  );
}
