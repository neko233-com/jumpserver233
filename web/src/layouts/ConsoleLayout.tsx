import { useTranslation } from "react-i18next";
import { NavLink, Outlet, useNavigate } from "react-router-dom";
import { useAuth } from "../auth/AuthContext";
import OrganizationSwitcher from "../components/OrganizationSwitcher";
import { usePermissions } from "../auth/usePermissions";
import { toggleLang } from "../i18n";

export default function ConsoleLayout({ title }: { title: string }) {
  const { t, i18n } = useTranslation();
  const { setAccessToken } = useAuth();
  const navigate = useNavigate();
  const { allows } = usePermissions();
  const isZh = i18n.language !== "en";

  const views = [
    { to: "/console", label: t("nav.console"), end: true },
    { to: "/audit", label: t("nav.audit"), end: false },
    { to: "/workbench", label: t("nav.workbench"), end: false },
  ];
  const consoleNav = [
    ...(allows("accounts.risks.view")
      ? [{ to: "/console/account-risks", label: t("nav.accountRisks"), end: false }]
      : []),
    ...(allows("audit.agents.view_all")
      ? [{ to: "/console/agent-audit", label: t("agentEvents.title"), end: false }]
      : []),
    { to: "/console/database-audit", label: t("database.auditTitle"), end: false },
    { to: "/console/organizations", label: t("organization.title"), end: false },
    { to: "/console/organization-roles", label: t("organization.rolesTitle"), end: false },
    { to: "/console", label: t("assets.title"), end: true },
    { to: "/console/settings", label: t("nav.systemSettings"), end: false },
    { to: "/console/roles", label: t("rbac.title"), end: false },
    { to: "/console/access-policies", label: t("acl.title"), end: false },
    { to: "/console/login-reviews", label: t("platformReview.title"), end: false },
    { to: "/console/identity", label: t("oidc.settingsTitle"), end: false },
    { to: "/console/directory", label: t("ldap.title"), end: false },
    { to: "/console/saml", label: t("saml.title"), end: false },
    { to: "/console/passkeys", label: t("passkey.title"), end: false },
    { to: "/console/cas", label: t("cas.title"), end: false },
  ];

  async function signOut() {
    await fetch("/api/v1/authentication/expire-session/", {
      method: "POST",
      credentials: "same-origin",
    }).catch(() => undefined);
    setAccessToken("");
    navigate("/login", { replace: true });
  }

  return (
    <div className="layout">
      <header className="layout-header">
        <span className="brand">{t("app.name")}</span>
        <nav className="view-switch">
          {views.map((v) => (
            <NavLink
              key={v.to}
              to={v.to}
              end={v.end}
              className={({ isActive }) => (isActive ? "active" : "")}
            >
              {v.label}
            </NavLink>
          ))}
        </nav>
        <OrganizationSwitcher />
        <button type="button" className="lang-switch" onClick={toggleLang} title="中文 / English">
          {isZh ? "EN" : "中文"}
        </button>
        <NavLink to="/profile" className="profile-link">
          {t("nav.profile")}
        </NavLink>
        <button
          type="button"
          className="profile-link sign-out-button"
          onClick={() => {
            void signOut();
          }}
        >
          {t("nav.signOut")}
        </button>
      </header>
      <div className="layout-body">
        <aside className="layout-sidebar">
          <div className="sidebar-title">{title}</div>
          <nav>
            {consoleNav.map((item) => (
              <NavLink
                key={item.to}
                to={item.to}
                end={item.end}
                className={({ isActive }) => (isActive ? "active" : "")}
              >
                {item.label}
              </NavLink>
            ))}
          </nav>
        </aside>
        <main className="layout-main">
          <Outlet />
        </main>
      </div>
    </div>
  );
}
