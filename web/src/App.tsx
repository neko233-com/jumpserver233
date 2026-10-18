import { lazy, Suspense, type ReactNode } from "react";
import { useTranslation } from "react-i18next";
import { Navigate, Route, Routes, useLocation } from "react-router-dom";
import ConsoleLayout from "./layouts/ConsoleLayout";
import { AuthProvider, useAuth } from "./auth/AuthContext";

const LoginPage = lazy(() => import("./pages/LoginPage"));
const AgentAuditPage = lazy(() => import("./pages/AgentAuditPage"));
const AccountRisksPage = lazy(() => import("./pages/AccountRisksPage"));
const RotationPlansPage = lazy(() => import("./pages/RotationPlansPage"));
const AccessTicketsPage = lazy(() => import("./pages/AccessTicketsPage"));
const NotificationsPage = lazy(() => import("./pages/NotificationsPage"));
const MonitoringPage = lazy(() => import("./pages/MonitoringPage"));
const NotificationSourcePage = lazy(() => import("./pages/NotificationSourcePage"));
const DatabaseAuditPage = lazy(() => import("./pages/DatabaseAuditPage"));
const AuditPage = lazy(() => import("./pages/AuditPage"));
const ConsolePage = lazy(() => import("./pages/ConsolePage"));
const ProfilePage = lazy(() => import("./pages/ProfilePage"));
const SettingsPage = lazy(() => import("./pages/SettingsPage"));
const WorkbenchPage = lazy(() => import("./pages/WorkbenchPage"));
const OrganizationsPage = lazy(() => import("./pages/OrganizationsPage"));
const RolesPage = lazy(() => import("./pages/RolesPage"));
const AccessPoliciesPage = lazy(() => import("./pages/AccessPoliciesPage"));
const LoginReviewsPage = lazy(() => import("./pages/LoginReviewsPage"));
const OIDCSettingsPage = lazy(() => import("./pages/OIDCSettingsPage"));
const LDAPSettingsPage = lazy(() => import("./pages/LDAPSettingsPage"));
const SAMLSettingsPage = lazy(() => import("./pages/SAMLSettingsPage"));
const PasskeySettingsPage = lazy(() => import("./pages/PasskeySettingsPage"));
const CASSettingsPage = lazy(() => import("./pages/CASSettingsPage"));
const SessionSharePage = lazy(() => import("./pages/SessionSharePage"));

function RequireAuth({ children }: { children: ReactNode }) {
  const { authenticated, sessionReady } = useAuth();
  const location = useLocation();
  if (!sessionReady) return null;
  const target = location.pathname.startsWith("/share/")
    ? `/login?next=${encodeURIComponent(location.pathname + location.search)}`
    : "/login";
  return authenticated ? children : <Navigate to={target} replace />;
}

export default function App() {
  const { t } = useTranslation();

  return (
    <AuthProvider>
      <Suspense fallback={<div className="placeholder">{t("placeholder.skeleton")}</div>}>
        <Routes>
          <Route path="/login" element={<LoginPage />} />
          <Route
            path="/share/:shareID"
            element={
              <RequireAuth>
                <SessionSharePage />
              </RequireAuth>
            }
          />
          <Route
            path="/console"
            element={
              <RequireAuth>
                <ConsoleLayout title={t("nav.console")} />
              </RequireAuth>
            }
          >
            <Route index element={<ConsolePage />} />
            <Route path="agent-audit" element={<AgentAuditPage />} />
            <Route path="account-risks" element={<AccountRisksPage />} />
            <Route path="rotation-plans" element={<RotationPlansPage />} />
            <Route path="access-tickets" element={<AccessTicketsPage />} />
            <Route path="notifications" element={<NotificationsPage />} />
            <Route path="monitoring" element={<MonitoringPage />} />
            <Route path="notification-sources/:kind/:id" element={<NotificationSourcePage />} />
            <Route path="database-audit" element={<DatabaseAuditPage />} />
            <Route path="settings" element={<SettingsPage />} />
            <Route path="roles" element={<RolesPage />} />
            <Route path="organizations" element={<OrganizationsPage />} />
            <Route path="organization-roles" element={<RolesPage organization />} />
            <Route path="access-policies" element={<AccessPoliciesPage />} />
            <Route path="login-reviews" element={<LoginReviewsPage />} />
            <Route path="identity" element={<OIDCSettingsPage />} />
            <Route path="directory" element={<LDAPSettingsPage />} />
            <Route path="saml" element={<SAMLSettingsPage />} />
            <Route path="passkeys" element={<PasskeySettingsPage />} />
            <Route path="cas" element={<CASSettingsPage />} />
          </Route>
          <Route
            path="/audit"
            element={
              <RequireAuth>
                <ConsoleLayout title={t("nav.audit")} />
              </RequireAuth>
            }
          >
            <Route
              index
              element={
                <Suspense fallback={<div className="placeholder">{t("placeholder.skeleton")}</div>}>
                  <AuditPage />
                </Suspense>
              }
            />
          </Route>
          <Route
            path="/workbench"
            element={
              <RequireAuth>
                <ConsoleLayout title={t("nav.workbench")} />
              </RequireAuth>
            }
          >
            <Route index element={<WorkbenchPage />} />
          </Route>
          <Route path="/settings" element={<Navigate to="/console/settings" replace />} />
          <Route
            path="/profile"
            element={
              <RequireAuth>
                <ConsoleLayout title={t("nav.profile")} />
              </RequireAuth>
            }
          >
            <Route index element={<ProfilePage />} />
          </Route>
          <Route path="/" element={<Navigate to="/console" replace />} />
          <Route path="*" element={<Navigate to="/console" replace />} />
        </Routes>
      </Suspense>
    </AuthProvider>
  );
}
