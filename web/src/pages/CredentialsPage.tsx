import { useAuth } from "../auth/AuthContext";
import { useEngagement } from "../auth/EngagementContext";
import { CredentialsCard } from "../components/CredentialsCard";
import { CredSetsCard } from "../components/CredSetsCard";
import { Empty } from "../components/ui";

/**
 * Вкладка «Учётные записи»: учётки активов текущего проекта (SSH, WinRM, сетевое
 * оборудование, СУБД) — добавление, правка, удаление; ниже — наборы проверки
 * учёток для аудита паролей (только с правом cred_audit).
 */
export function CredentialsPage() {
  const { has } = useAuth();
  const { current } = useEngagement();

  if (!current) {
    return (
      <div className="card">
        <Empty title="Выберите или создайте проект" />
      </div>
    );
  }

  return (
    <>
      <div className="page-head">
        <div>
          <span className="crumbs">{current.client ? `${current.client} · ${current.name}` : current.name}</span>
          <h1>Учётные записи</h1>
        </div>
      </div>
      {has("host_credentials") && <CredentialsCard engagementId={current.id} />}
      {has("cred_audit") && <CredSetsCard engagementId={current.id} />}
    </>
  );
}
