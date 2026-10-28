import { Link } from "react-router-dom";
import type { ServiceOut } from "../api/types";
import { Empty } from "./ui";

export function ServicesTable({ services, runId }: { services: ServiceOut[]; runId?: number }) {
  if (!services.length) return <Empty title="Сервисы не обнаружены" />;
  return (
    <div className="table-wrap">
      <table className="table" style={{ minWidth: 720 }}>
        <thead>
          <tr>
            <th>Хост</th>
            <th>Порт</th>
            <th>Сервис</th>
            <th>Продукт</th>
            <th>Версия</th>
            <th>CPE</th>
          </tr>
        </thead>
        <tbody>
          {services.map((s, i) => (
            <tr key={`${s.host}:${s.port}/${s.protocol}:${i}`}>
              <td className="mono">
                {runId ? <Link to={`/hosts/${encodeURIComponent(s.host)}?run=${runId}`}>{s.host}</Link> : s.host}
              </td>
              <td className="mono">
                {s.port}/{s.protocol}
              </td>
              <td>{s.service ?? "—"}</td>
              <td>{s.product ?? "—"}</td>
              <td className="muted">{s.version ?? "—"}</td>
              <td className="mono faint" style={{ fontSize: 12 }}>
                {s.cpe ?? "—"}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
