import { lazy, Suspense, type ReactNode } from "react";
import { useTranslation } from "react-i18next";
import { Navigate, Route, Routes, useLocation } from "react-router-dom";
import { AuthProvider, useAuth } from "./auth/AuthContext";
import { BrandingProvider } from "./branding/BrandingContext";

const PasswordChangePage = lazy(() => import("./pages/PasswordChangePage"));
const ConsoleLayout = lazy(() => import("./layouts/ConsoleLayout"));
const AnnouncementsPage = lazy(() => import("./pages/AnnouncementsPage"));
const LabelsPage = lazy(() => import("./pages/LabelsPage"));
const SSHCertificatesPage = lazy(() => import("./pages/SSHCertificatesPage"));
const ReplayStoragePage = lazy(() => import("./pages/ReplayStoragePage"));
const IdentitySourcesPage = lazy(() => import("./pages/IdentitySourcesPage"));
const DirectorySyncPage = lazy(() => import("./pages/DirectorySyncPage"));
const EnterpriseLoginSettingsPage = lazy(() => import("./pages/EnterpriseLoginSettingsPage"));
const SMSMFASettingsPage = lazy(() => import("./pages/SMSMFASettingsPage"));
const AssetDiscoveryPage = lazy(() => import("./pages/AssetDiscoveryPage"));
const BrandingPage = lazy(() => import("./pages/BrandingPage"));
const LoginPage = lazy(() => import("./pages/LoginPage"));
const ReportsPage = lazy(() => import("./pages/ReportsPage"));
const AssistantPage = lazy(() => import("./pages/AssistantPage"));
const PAMPage = lazy(() => import("./pages/PAMPage"));
const AgentAuditPage = lazy(() => import("./pages/AgentAuditPage"));
const AccountRisksPage = lazy(() => import("./pages/AccountRisksPage"));
const RotationPlansPage = lazy(() => import("./pages/RotationPlansPage"));
const AccessTicketsPage = lazy(() => import("./pages/AccessTicketsPage"));
const NotificationsPage = lazy(() => import("./pages/NotificationsPage"));
const MonitoringPage = lazy(() => import("./pages/MonitoringPage"));
const LoginAuditPage = lazy(() => import("./pages/LoginAuditPage"));
const NotificationSourcePage = lazy(() => import("./pages/NotificationSourcePage"));
const DatabaseAuditPage = lazy(() => import("./pages/DatabaseAuditPage"));
const AuditPage = lazy(() => import("./pages/AuditPage"));
const ConsolePage = lazy(() => import("./pages/ConsolePage"));
const ProfilePage = lazy(() => import("./pages/ProfilePage"));
const SettingsPage = lazy(() => import("./pages/SettingsPage"));
const WorkbenchPage = lazy(() => import("./pages/WorkbenchPage"));
const OrganizationsPage = lazy(() => import("./pages/OrganizationsPage"));
const OrganizationOverviewPage = lazy(() => import("./pages/OrganizationOverviewPage"));
const RolesPage = lazy(() => import("./pages/RolesPage"));
const AccessPoliciesPage = lazy(() => import("./pages/AccessPoliciesPage"));
const LoginReviewsPage = lazy(() => import("./pages/LoginReviewsPage"));
const OIDCSettingsPage = lazy(() => import("./pages/OIDCSettingsPage"));
const LDAPSettingsPage = lazy(() => import("./pages/LDAPSettingsPage"));
const SAMLSettingsPage = lazy(() => import("./pages/SAMLSettingsPage"));
const PasskeySettingsPage = lazy(() => import("./pages/PasskeySettingsPage"));
const CASSettingsPage = lazy(() => import("./pages/CASSettingsPage"));
const RadiusSettingsPage = lazy(() => import("./pages/RadiusSettingsPage"));
const UsersPage = lazy(() => import("./pages/UsersPage"));
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
    <BrandingProvider>
      <AuthProvider>
        <Suspense fallback={<div className="placeholder">{t("placeholder.skeleton")}</div>}>
          <Routes>
            <Route path="/login" element={<LoginPage />} />
            <Route path="/password-change" element={<PasswordChangePage />} />
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
              <Route path="notifications" element={<NotificationsPage key="organization" />} />
              <Route
                path="platform-notifications"
                element={<NotificationsPage key="platform" platform />}
              />
              <Route path="login-audit" element={<LoginAuditPage />} />
              <Route path="reports" element={<ReportsPage />} />
              <Route path="dashboard" element={<ReportsPage />} />
              <Route path="assistant" element={<AssistantPage />} />
              <Route path="pam" element={<PAMPage />} />
              <Route path="monitoring" element={<MonitoringPage />} />
              <Route path="notification-sources/:kind/:id" element={<NotificationSourcePage />} />
              <Route path="database-audit" element={<DatabaseAuditPage />} />
              <Route path="settings" element={<SettingsPage />} />
              <Route path="asset-discovery" element={<AssetDiscoveryPage />} />
              <Route path="branding" element={<BrandingPage />} />
              <Route path="announcements" element={<AnnouncementsPage />} />
              <Route path="labels" element={<LabelsPage />} />
              <Route path="ssh-certificates" element={<SSHCertificatesPage />} />
              <Route path="replay-storage" element={<ReplayStoragePage />} />
              <Route path="roles" element={<RolesPage />} />
              <Route path="users" element={<UsersPage />} />
              <Route path="organizations" element={<OrganizationsPage />} />
              <Route path="organization-overview" element={<OrganizationOverviewPage />} />
              <Route path="organization-roles" element={<RolesPage organization />} />
              <Route path="access-policies" element={<AccessPoliciesPage />} />
              <Route path="login-reviews" element={<LoginReviewsPage />} />
              <Route path="identity" element={<OIDCSettingsPage />} />
              <Route path="identity-sources" element={<IdentitySourcesPage />} />
              <Route path="directory-sync" element={<DirectorySyncPage />} />
              <Route path="enterprise-login" element={<EnterpriseLoginSettingsPage />} />
              <Route path="directory" element={<LDAPSettingsPage />} />
              <Route path="saml" element={<SAMLSettingsPage />} />
              <Route path="passkeys" element={<PasskeySettingsPage />} />
              <Route path="cas" element={<CASSettingsPage />} />
              <Route path="radius" element={<RadiusSettingsPage />} />
              <Route path="sms-mfa" element={<SMSMFASettingsPage />} />
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
                  <Suspense
                    fallback={<div className="placeholder">{t("placeholder.skeleton")}</div>}
                  >
                    <AuditPage />
                  </Suspense>
                }
              />
              <Route path="reports" element={<ReportsPage />} />
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
    </BrandingProvider>
  );
}
