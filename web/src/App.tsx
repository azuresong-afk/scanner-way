import type { ReactNode } from "react";
import { Navigate, Route, Routes, useLocation } from "react-router-dom";
import { Lock } from "lucide-react";
import { useAuth, type Perm } from "./auth/AuthContext";
import { EngagementProvider } from "./auth/EngagementContext";
import { Layout } from "./components/Layout";
import { Empty, Loading } from "./components/ui";
import { AssetsPage } from "./pages/AssetsPage";
import { AuditPage } from "./pages/AuditPage";
import { DashboardPage } from "./pages/DashboardPage";
import { EngagementDetailPage } from "./pages/EngagementDetailPage";
import { EngagementsPage } from "./pages/EngagementsPage";
import { FeedsPage } from "./pages/FeedsPage";
import { FindingsPage } from "./pages/FindingsPage";
import { HostDetailPage } from "./pages/HostDetailPage";
import { HostsPage } from "./pages/HostsPage";
import { IntegrationsPage } from "./pages/IntegrationsPage";
import { LoginPage } from "./pages/LoginPage";
import { ReportsPage } from "./pages/ReportsPage";
import { CompliancePage } from "./pages/CompliancePage";
import { RunDetailPage } from "./pages/RunDetailPage";
import { RunsPage } from "./pages/RunsPage";
import { SchedulesPage } from "./pages/SchedulesPage";
import { UsersPage } from "./pages/UsersPage";

function RequireAuth({ children }: { children: ReactNode }) {
  const { me, ready } = useAuth();
  const location = useLocation();
  if (!ready) return <Loading label="Проверка сессии…" />;
  if (!me) return <Navigate to="/login" replace state={{ from: location.pathname + location.search }} />;
  return <>{children}</>;
}

function RequirePerm({ perm, children }: { perm: Perm; children: ReactNode }) {
  const { has } = useAuth();
  if (!has(perm)) {
    return (
      <div className="card">
        <Empty title="Нет доступа" icon={<Lock size={28} />}>
          Для этого раздела нужно право «{perm}». Обратитесь к администратору.
        </Empty>
      </div>
    );
  }
  return <>{children}</>;
}

/** Стартовая страница по правам: у admin без отчётов — договоры, иначе обзор. */
function Home() {
  const { has } = useAuth();
  if (has("view_report")) return <DashboardPage />;
  if (has("view_engagements")) return <Navigate to="/engagements" replace />;
  if (has("manage_users")) return <Navigate to="/users" replace />;
  return (
    <div className="card">
      <Empty title="Нет назначенных ролей" icon={<Lock size={28} />}>
        Обратитесь к администратору, чтобы получить доступ.
      </Empty>
    </div>
  );
}

export function App() {
  return (
    <Routes>
      <Route path="/login" element={<LoginPage />} />
      <Route
        element={
          <RequireAuth>
            <EngagementProvider>
              <Layout />
            </EngagementProvider>
          </RequireAuth>
        }
      >
        <Route index element={<Home />} />
        <Route path="engagements" element={<RequirePerm perm="view_engagements"><EngagementsPage /></RequirePerm>} />
        <Route path="engagements/:id" element={<RequirePerm perm="view_engagements"><EngagementDetailPage /></RequirePerm>} />
        <Route path="assets" element={<RequirePerm perm="view_engagements"><AssetsPage /></RequirePerm>} />
        <Route path="runs" element={<RequirePerm perm="view_report"><RunsPage /></RequirePerm>} />
        <Route path="runs/:id" element={<RequirePerm perm="view_report"><RunDetailPage /></RequirePerm>} />
        <Route path="schedules" element={<RequirePerm perm="view_report"><SchedulesPage /></RequirePerm>} />
        <Route path="findings" element={<RequirePerm perm="view_report"><FindingsPage /></RequirePerm>} />
        <Route path="hosts" element={<RequirePerm perm="view_report"><HostsPage /></RequirePerm>} />
        <Route path="hosts/:host" element={<RequirePerm perm="view_report"><HostDetailPage /></RequirePerm>} />
        <Route path="compliance" element={<RequirePerm perm="view_report"><CompliancePage /></RequirePerm>} />
        <Route path="reports" element={<RequirePerm perm="view_report"><ReportsPage /></RequirePerm>} />
        <Route path="feeds" element={<RequirePerm perm="view_engagements"><FeedsPage /></RequirePerm>} />
        <Route path="integrations" element={<RequirePerm perm="view_engagements"><IntegrationsPage /></RequirePerm>} />
        <Route path="audit" element={<RequirePerm perm="view_audit"><AuditPage /></RequirePerm>} />
        <Route path="users" element={<RequirePerm perm="manage_users"><UsersPage /></RequirePerm>} />
        <Route path="*" element={<div className="card"><Empty title="Страница не найдена" /></div>} />
      </Route>
    </Routes>
  );
}
