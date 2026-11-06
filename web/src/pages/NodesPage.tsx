import { useState } from "react";
import { Copy, KeyRound, Network, Pencil, Plus, Power, Trash2 } from "lucide-react";
import { Link } from "react-router-dom";
import { api } from "../api/client";
import type { NodeMode, ScanNode, ScanNodeCreated } from "../api/types";
import { useAuth } from "../auth/AuthContext";
import { NodeKeyCard, OfflineResultUpload } from "../components/OfflineJob";
import { Empty, ErrorAlert, Loading, Modal } from "../components/ui";
import { fmtDate } from "../lib/format";
import { NODE_MODE_LABEL, NODE_STATUS_LABEL, NODE_STATUS_PILL, needsAllowHttp, nodeEnv, splitScope } from "../lib/nodes";
import { useAsync, useInterval } from "../lib/useAsync";

const TOOL_LABEL: Record<string, string> = { nmap: "nmap", nuclei: "Nuclei", oscap: "OpenSCAP", lynis: "Lynis", snmpget: "SNMP" };

function centerUrl(): string {
  return typeof window !== "undefined" ? window.location.origin : "https://scanner.corp.local";
}

/** Заведение и изменение узла. */
function NodeForm({ node, onClose, onSaved }: { node: ScanNode | null; onClose: () => void; onSaved: (created?: ScanNodeCreated) => void }) {
  const [name, setName] = useState(node?.name ?? "");
  const [description, setDescription] = useState(node?.description ?? "");
  const [mode, setMode] = useState<NodeMode>(node?.mode ?? "online");
  const [scope, setScope] = useState((node?.scope ?? []).join("\n"));
  const [allowCreds, setAllowCreds] = useState(node?.allow_credentials ?? true);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const nets = splitScope(scope);
  const valid = name.trim().length > 0 && nets.length > 0;

  const save = async () => {
    setBusy(true);
    setError(null);
    try {
      if (node) {
        await api.updateNode(node.id, { name: name.trim(), description: description.trim() || null, scope: nets, allow_credentials: allowCreds });
        onSaved();
      } else {
        onSaved(await api.createNode({ name: name.trim(), description: description.trim() || null, mode, scope: nets, allow_credentials: allowCreds }));
      }
    } catch (e) {
      setError((e as Error).message);
      setBusy(false);
    }
  };

  return (
    <Modal
      wide
      title={node ? `Узел: ${node.name}` : "Новый узел-сканер"}
      onClose={onClose}
      footer={
        <>
          <button type="button" className="btn" onClick={onClose}>
            Отмена
          </button>
          <button type="button" className="btn btn-primary" disabled={!valid || busy} onClick={() => void save()}>
            {node ? "Сохранить" : "Добавить узел"}
          </button>
        </>
      }
    >
      {error && <ErrorAlert error={error} />}
      <div className="inline" style={{ gap: 12, flexWrap: "wrap" }}>
        <label className="field" style={{ flex: "1 1 220px" }}>
          <span>Название</span>
          <input className="input" value={name} onChange={(e) => setName(e.target.value)} maxLength={100} placeholder="Филиал Казань" autoFocus />
        </label>
        <label className="field" style={{ flex: "1 1 220px" }}>
          <span>Тип узла</span>
          <select className="select" value={mode} disabled={!!node} onChange={(e) => setMode(e.target.value as NodeMode)} aria-label="Тип узла">
            <option value="online">Сетевой — сам выходит на центр по HTTPS</option>
            <option value="offline">Автономный — задания и результаты файлами</option>
          </select>
        </label>
      </div>
      <p className="muted" style={{ margin: "4px 0 8px" }}>
        {mode === "online"
          ? "На межсетевом экране нужно одно правило: от узла к центру, TCP 443, только исходящее. Входящих портов на узле нет."
          : "Связь с центром не нужна: задание выгружается подписанным файлом, переносится на носителе, результат загружается обратно."}
      </p>
      <label className="field">
        <span>Сети сегмента, которые проверяет узел</span>
        <textarea
          className="input textarea"
          rows={4}
          value={scope}
          onChange={(e) => setScope(e.target.value)}
          placeholder={"10.1.0.0/24\n10.1.5.10-10.1.5.60"}
          aria-label="Сети узла"
        />
        <small className="faint">
          Подсети, диапазоны или адреса — по одной на строке или через запятую. Узел получит только цели, которые входят и в allowlist проекта, и в эти сети. На
          самом узле действует ещё и свой локальный allowlist.
        </small>
      </label>
      <label className="field">
        <span>Описание</span>
        <input className="input" value={description} onChange={(e) => setDescription(e.target.value)} maxLength={500} placeholder="Сегмент АСУ, стойка 3" />
      </label>
      <label className="inline" style={{ gap: 8, marginTop: 8 }}>
        <input type="checkbox" checked={allowCreds} onChange={(e) => setAllowCreds(e.target.checked)} />
        <span>Разрешить передавать узлу учётные записи (проверки по учётной записи, аудит конфигураций)</span>
      </label>
    </Modal>
  );
}

/** Токен показывается один раз — сразу с готовым .env.node и командами установки. */
function TokenModal({ node, onClose }: { node: ScanNodeCreated; onClose: () => void }) {
  const [copied, setCopied] = useState(false);
  const server = centerUrl();
  const env = nodeEnv(server, node.token ?? "", node.scope);
  const plainHttp = needsAllowHttp(server);
  const copy = async () => {
    try {
      await navigator.clipboard.writeText(env);
      setCopied(true);
    } catch {
      setCopied(false);
    }
  };
  return (
    <Modal
      wide
      title={`Токен узла «${node.name}»`}
      onClose={onClose}
      footer={
        <button type="button" className="btn btn-primary" onClick={onClose}>
          Готово, токен сохранён
        </button>
      }
    >
      <div className="alert alert-warn" role="status">
        Токен показывается только сейчас: в центре хранится лишь его отпечаток. Потеряли — перевыпустите токен.
      </div>
      <p style={{ margin: "8px 0 4px" }}>
        1. На машине внутри сегмента положите в каталог сканера файл <code>.env.node</code>:
      </p>
      <pre className="code-block" data-testid="node-env">{env}</pre>
      {plainHttp && (
        <div className="alert alert-warn" role="note" style={{ marginTop: 8 }}>
          Интерфейс открыт по HTTP, а узел подключается к центру только по HTTPS. Опубликуйте центр через HTTPS-прокси
          (docs/INSTALL.md, раздел 13в) и укажите в <code>SCANNER_NODE_SERVER</code> адрес https://. Только для стенда:
          строка <code>SCANNER_NODE_ALLOW_HTTP=1</code> в <code>.env.node</code> — токен тогда идёт по сети открытым текстом.
        </div>
      )}
      <button type="button" className="btn btn-sm" onClick={() => void copy()}>
        <Copy size={12} /> {copied ? "Скопировано" : "Скопировать"}
      </button>
      <p style={{ margin: "12px 0 4px" }}>2. Запустите узел:</p>
      <pre className="code-block">docker compose -f docker-compose.node.yml --env-file .env.node up -d</pre>
      <p className="muted" style={{ margin: "8px 0 0" }}>
        Через несколько секунд узел появится здесь со статусом «На связи». Проверить настройки на узле: <code>docker compose -f docker-compose.node.yml --env-file .env.node run --rm node check</code>
        . Локальный allowlist (<code>SCANNER_NODE_ALLOWLIST</code>) можно сузить на месте — шире сетей узла он всё равно не даст.
      </p>
    </Modal>
  );
}

function NodeCard({ node, canEdit, busy, onEdit, onToken, onToggle, onDelete, onChanged }: {
  node: ScanNode;
  canEdit: boolean;
  busy: boolean;
  onEdit: () => void;
  onToken: () => void;
  onToggle: () => void;
  onDelete: () => void;
  onChanged: () => void;
}) {
  const missing = Object.entries(node.tools).filter(([, ok]) => !ok).map(([t]) => TOOL_LABEL[t] ?? t);
  return (
    <div className="card node-card" data-testid={`node-${node.id}`}>
      <div className="inline" style={{ gap: 10, justifyContent: "space-between", alignItems: "flex-start", flexWrap: "wrap" }}>
        <div>
          <div className="inline" style={{ gap: 8, flexWrap: "wrap" }}>
            <strong style={{ fontSize: 15 }}>{node.name}</strong>
            <span className={`pill ${NODE_STATUS_PILL[node.status]}`}>{NODE_STATUS_LABEL[node.status]}</span>
            {node.mode === "online" && <span className="pill pill-muted">{NODE_MODE_LABEL[node.mode]}</span>}
          </div>
          {node.description && <small className="muted">{node.description}</small>}
        </div>
        {canEdit && (
          <div className="inline" style={{ gap: 6 }}>
            <button type="button" className="btn btn-sm" aria-label={`Изменить: ${node.name}`} onClick={onEdit}>
              <Pencil size={12} />
            </button>
            {node.mode === "online" && (
              <button type="button" className="btn btn-sm" disabled={busy} onClick={onToken} title="Перевыпустить токен">
                <KeyRound size={12} /> Токен
              </button>
            )}
            <button type="button" className="btn btn-sm" disabled={busy} onClick={onToggle} title={node.enabled ? "Отключить узел" : "Включить узел"}>
              <Power size={12} /> {node.enabled ? "Отключить" : "Включить"}
            </button>
            <button type="button" className="btn btn-sm" disabled={busy} aria-label={`Удалить: ${node.name}`} onClick={onDelete}>
              <Trash2 size={12} />
            </button>
          </div>
        )}
      </div>

      <dl className="node-facts">
        <div>
          <dt>Сети узла</dt>
          <dd>{node.scope.join(", ")}</dd>
        </div>
        {node.mode === "online" && (
          <>
            <div>
              <dt>Последняя связь</dt>
              <dd>{node.last_seen_at ? fmtDate(node.last_seen_at) : "—"}</dd>
            </div>
            <div>
              <dt>Хост и версия</dt>
              <dd>{node.hostname ? `${node.hostname}${node.version ? ` · ${node.version}` : ""}` : "—"}</dd>
            </div>
            <div>
              <dt>Локальный allowlist узла</dt>
              <dd>{node.local_allowlist.length ? node.local_allowlist.join(", ") : "—"}</dd>
            </div>
          </>
        )}
        <div>
          <dt>Сейчас</dt>
          <dd>
            {node.active_runs.length > 0
              ? node.active_runs.map((id, i) => (
                  <span key={id}>
                    {i > 0 && ", "}
                    <Link to={`/runs/${id}`}>прогон #{id}</Link>
                  </span>
                ))
              : "простаивает"}
            {node.queued_runs > 0 && <span className="muted"> · в очереди: {node.queued_runs}</span>}
          </dd>
        </div>
        <div>
          <dt>Учётные записи</dt>
          <dd>{node.allow_credentials ? "передаются узлу" : "не передаются"}</dd>
        </div>
        {node.token_prefix && (
          <div>
            <dt>Токен</dt>
            <dd>
              <code>{node.token_prefix}…</code>
            </dd>
          </div>
        )}
      </dl>

      {node.outside_local_allowlist.length > 0 && (
        <div className="alert alert-warn" role="status">
          Эти сети узла не входят в локальный allowlist узла (целиком или частично): адреса вне него узел проверять не будет — {node.outside_local_allowlist.join(", ")}.
        </div>
      )}
      {node.status === "online" && missing.length > 0 && (
        <div className="alert alert-warn" role="status">
          На узле нет: {missing.join(", ")} — соответствующие проверки на нём не выполнятся.
        </div>
      )}
      {node.status === "never" && node.mode === "online" && (
        <small className="faint">Узел ещё не выходил на связь: установите его в сегменте с токеном из окна создания.</small>
      )}
      {node.mode === "offline" && (
        <div className="node-offline-slot">
          <NodeKeyCard nodeId={node.id} nodeName={node.name} onChanged={onChanged} />
        </div>
      )}
    </div>
  );
}

/** «Сканеры»: узлы-сканеры в изолированных сегментах и их состояние. */
export function NodesPage() {
  const { has } = useAuth();
  const nodes = useAsync(() => api.nodes(), []);
  const [editing, setEditing] = useState<ScanNode | "new" | null>(null);
  const [created, setCreated] = useState<ScanNodeCreated | null>(null);
  const [busy, setBusy] = useState<number | null>(null);
  const [error, setError] = useState<string | null>(null);
  const canEdit = has("manage_nodes");
  const list = nodes.data ?? [];
  useInterval(() => void nodes.reload(), 15000, true);

  const act = async (id: number, fn: () => Promise<unknown>) => {
    setBusy(id);
    setError(null);
    try {
      await fn();
      await nodes.reload();
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(null);
    }
  };

  const online = list.filter((n) => n.status === "online").length;
  const hasOffline = list.some((n) => n.mode === "offline");

  return (
    <>
      <div className="page-head">
        <div>
          <span className="crumbs">Администрирование</span>
          <h1>Сканеры</h1>
        </div>
        <div className="inline" style={{ gap: 8 }}>
          {hasOffline && has("run_scan") && <OfflineResultUpload onDone={() => void nodes.reload()} />}
          {canEdit && (
            <button type="button" className="btn btn-primary" onClick={() => setEditing("new")}>
              <Plus size={14} /> Добавить узел
            </button>
          )}
        </div>
      </div>
      <p className="muted" style={{ marginTop: -8 }}>
        Центральный сервер проверяет то, до чего дотягивается сам. Для изолированных сегментов (филиалы, ДМЗ, АСУ ТП) поставьте в сегменте узел-сканер и выбирайте его
        при запуске прогона. Если из сегмента нельзя выйти даже к центру, заведите автономный узел: задание и результат переносятся файлами на носителе.{" "}
        {list.length > 0 && `На связи: ${online} из ${list.filter((n) => n.mode === "online").length} сетевых.`}
      </p>

      {error && <ErrorAlert error={error} />}
      {nodes.error && <ErrorAlert error={nodes.error} onRetry={nodes.reload} />}

      {nodes.loading && !nodes.data ? (
        <div className="card">
          <Loading />
        </div>
      ) : list.length === 0 ? (
        <div className="card">
          <Empty title="Узлов пока нет" icon={<Network size={28} />}>
            Все прогоны выполняет центральный сервер. Добавьте узел, чтобы проверять сегменты, куда центру нет доступа.
          </Empty>
        </div>
      ) : (
        <div className="node-grid">
          {list.map((n) => (
            <NodeCard
              key={n.id}
              node={n}
              canEdit={canEdit}
              busy={busy === n.id}
              onEdit={() => setEditing(n)}
              onToken={() => {
                if (window.confirm(`Перевыпустить токен узла «${n.name}»? Прежний перестанет действовать сразу — узел нужно будет перенастроить.`))
                  void act(n.id, async () => setCreated(await api.rotateNodeToken(n.id)));
              }}
              onToggle={() => void act(n.id, () => api.updateNode(n.id, { enabled: !n.enabled }))}
              onDelete={() => {
                if (window.confirm(`Удалить узел «${n.name}»? Прогоны узла останутся в истории.`)) void act(n.id, () => api.deleteNode(n.id));
              }}
              onChanged={() => void nodes.reload()}
            />
          ))}
        </div>
      )}

      {editing && (
        <NodeForm
          node={editing === "new" ? null : editing}
          onClose={() => setEditing(null)}
          onSaved={(c) => {
            setEditing(null);
            if (c?.token) setCreated(c);
            void nodes.reload();
          }}
        />
      )}
      {created && <TokenModal node={created} onClose={() => setCreated(null)} />}
    </>
  );
}
