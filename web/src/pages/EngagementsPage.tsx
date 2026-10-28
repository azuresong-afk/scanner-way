import { useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { FileText, Plus } from "lucide-react";
import { api } from "../api/client";
import { useAuth } from "../auth/AuthContext";
import { useEngagement } from "../auth/EngagementContext";
import { EngagementForm } from "../components/EngagementForm";
import { Empty, ErrorAlert, Loading } from "../components/ui";
import { fmtDate } from "../lib/format";

export function EngagementsPage() {
  const { has } = useAuth();
  const { engagements, loading, error, reload, select, current } = useEngagement();
  const [creating, setCreating] = useState(false);
  const navigate = useNavigate();

  return (
    <>
      <div className="page-head">
        <div>
          <span className="crumbs">Объём работ и разрешённые цели</span>
          <h1>Договоры и allowlist</h1>
        </div>
        <div className="actions">
          {has("manage_engagements") && (
            <button type="button" className="btn btn-primary" onClick={() => setCreating(true)}>
              <Plus size={16} /> Новый договор
            </button>
          )}
        </div>
      </div>
      {error && <ErrorAlert error={error} onRetry={reload} />}
      <div className="card" style={{ overflow: "hidden" }}>
        {loading && !engagements.length ? (
          <Loading />
        ) : engagements.length === 0 ? (
          <Empty title="Договоров пока нет" icon={<FileText size={28} />}>
            Сканирование возможно только в рамках договора с заданным allowlist.
          </Empty>
        ) : (
          <div className="table-wrap">
            <table className="table" style={{ minWidth: 640 }}>
              <thead>
                <tr>
                  <th>Работы</th>
                  <th>Заказчик</th>
                  <th>Договор</th>
                  <th>Создан</th>
                  <th />
                </tr>
              </thead>
              <tbody>
                {[...engagements].reverse().map((e) => (
                  <tr key={e.id} className="clickable" onClick={() => navigate(`/engagements/${e.id}`)}>
                    <td style={{ fontWeight: 500 }}>
                      <Link to={`/engagements/${e.id}`} onClick={(ev) => ev.stopPropagation()}>
                        {e.name}
                      </Link>
                    </td>
                    <td>{e.client ?? "—"}</td>
                    <td className="muted">{e.contract_ref ?? "—"}</td>
                    <td className="muted nowrap">{fmtDate(e.created_at)}</td>
                    <td className="right">
                      {current?.id === e.id ? (
                        <span className="pill pill-info">Текущий</span>
                      ) : (
                        <button
                          type="button"
                          className="btn btn-sm"
                          onClick={(ev) => {
                            ev.stopPropagation();
                            select(e.id);
                          }}
                        >
                          Сделать текущим
                        </button>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
      {creating && (
        <EngagementForm
          title="Новый договор"
          onClose={() => setCreating(false)}
          onSubmit={async (data) => {
            const e = await api.createEngagement(data);
            await reload();
            select(e.id);
            navigate(`/engagements/${e.id}`);
          }}
        />
      )}
    </>
  );
}
