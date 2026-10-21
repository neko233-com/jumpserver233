import { useId, useRef, useState, type KeyboardEvent } from "react";
import { useTranslation } from "react-i18next";
import { NavLink, Outlet, useLocation, useNavigate } from "react-router-dom";
import { useAuth } from "../auth/AuthContext";
import OrganizationSwitcher from "../components/OrganizationSwitcher";
import NotificationBell from "../components/NotificationBell";
import { usePermissions } from "../auth/usePermissions";
import { toggleLang } from "../i18n";
import { BrandFooter, BrandMark } from "../branding/BrandingContext";
import "./console-shell.css";

// The shipped console contains the standalone SSH workflow. Enterprise page
// sources remain in the repository; they are outside the mini production graph.
const navigationGroups = [
  { id: "operations", routes: ["", "monitoring", "rotation-plans", "account-risks"] },
  {
    id: "access",
    routes: ["access-tickets", "access-policies", "login-reviews", "ssh-certificates"],
  },
  { id: "audit", routes: ["reports", "login-audit", "agent-audit"] },
  { id: "identity", routes: ["users", "organization-roles", "roles", "passkeys"] },
  { id: "platform", routes: ["organizations", "labels", "settings"] },
];
const groupedRoutes = new Set(navigationGroups.flatMap((group) => group.routes));
// Keep less frequent local controls behind a disclosure. Navigation visibility
// never grants or revokes API authority.
const primaryRoutes = new Set([
  "",
  "monitoring",
  "rotation-plans",
  "agent-audit",
  "login-audit",
  "users",
  "roles",
  "organization-roles",
  "access-policies",
  "settings",
]);

export default function ConsoleLayout({ title }: { title: string }) {
  const { t, i18n } = useTranslation();
  const { setAccessToken } = useAuth();
  const navigate = useNavigate();
  const location = useLocation();
  const { allows, systemAllows } = usePermissions();
  const isZh = i18n.language !== "en";
  const [navigationOpen, setNavigationOpen] = useState(false);
  const [search, setSearch] = useState("");
  const [moreState, setMoreState] = useState(() => ({
    path: location.pathname,
    open: !primaryRoutes.has(location.pathname.replace(/^\/console\/?/, "")),
  }));
  const navigationID = useId();
  const searchInput = useRef<HTMLInputElement>(null);
  const menuButton = useRef<HTMLButtonElement>(null);

  const views = [
    { to: "/console", label: t("nav.console"), end: true },
    { to: "/audit", label: t("nav.audit"), end: false },
    { to: "/workbench", label: t("nav.workbench"), end: false },
  ];
  const consoleNav = [
    { to: "/console/labels", label: t("nav.labels"), end: false },
    { to: "/console", label: t("assets.title"), end: true },
    ...(allows("monitoring.view") || allows("monitoring.manage")
      ? [{ to: "/console/monitoring", label: t("nav.monitoring"), end: false }]
      : []),
    ...(allows("accounts.rotation.view") || allows("accounts.password_policy.view")
      ? [{ to: "/console/rotation-plans", label: t("nav.rotationPlans"), end: false }]
      : []),
    ...(allows("accounts.risks.view")
      ? [{ to: "/console/account-risks", label: t("nav.accountRisks"), end: false }]
      : []),
    { to: "/console/access-tickets", label: t("nav.accessTickets"), end: false },
    { to: "/console/access-policies", label: t("acl.title"), end: false },
    { to: "/console/login-reviews", label: t("platformReview.title"), end: false },
    ...(allows("ssh_certificates.view")
      ? [{ to: "/console/ssh-certificates", label: t("nav.sshCertificates"), end: false }]
      : []),
    { to: "/console/reports", label: t("nav.reports"), end: false },
    { to: "/console/login-audit", label: t("nav.loginAudit"), end: false },
    ...(allows("audit.agents.view_all")
      ? [{ to: "/console/agent-audit", label: t("agentEvents.title"), end: false }]
      : []),
    { to: "/console/organization-roles", label: t("organization.rolesTitle"), end: false },
    { to: "/console/roles", label: t("rbac.title"), end: false },
    ...(systemAllows("users.manage")
      ? [{ to: "/console/users", label: t("nav.users"), end: false }]
      : []),
    { to: "/console/passkeys", label: t("passkey.title"), end: false },
    { to: "/console/organizations", label: t("organization.title"), end: false },
    { to: "/console/settings", label: t("nav.systemSettings"), end: false },
  ];
  const query = search.trim().toLocaleLowerCase(i18n.language);
  const matchingLinks = consoleNav.filter((item) =>
    item.label.toLocaleLowerCase(i18n.language).includes(query),
  );
  const groups = navigationGroups.map((group) => ({
    id: group.id,
    links: group.routes.flatMap((route) =>
      matchingLinks.filter((item) => item.to === `/console${route ? `/${route}` : ""}`),
    ),
  }));
  const ungrouped = matchingLinks.filter(
    (item) => !groupedRoutes.has(item.to.replace(/^\/console\/?/, "")),
  );
  if (ungrouped.length) groups.push({ id: "other", links: ungrouped });
  const isPrimary = (to: string) => primaryRoutes.has(to.replace(/^\/console\/?/, ""));
  const primaryGroups = groups.map((group) => ({
    ...group,
    links: group.links.filter((link) => isPrimary(link.to)),
  }));
  const moreGroups = groups.map((group) => ({
    ...group,
    links: group.links.filter((link) => !isPrimary(link.to)),
  }));
  const hasMore = moreGroups.some((group) => group.links.length > 0);
  const moreActive = consoleNav.some(
    (link) =>
      !isPrimary(link.to) &&
      (location.pathname === link.to || location.pathname.startsWith(link.to + "/")),
  );
  const moreExpanded =
    !!query || (moreState.path === location.pathname ? moreState.open : moreActive);

  function renderGroups(rows: typeof groups, region: string) {
    return rows
      .filter((group) => group.links.length > 0)
      .map((group) => (
        <section
          className="console-nav-group"
          key={group.id}
          aria-labelledby={`${navigationID}-${region}-${group.id}`}
        >
          <h2 id={`${navigationID}-${region}-${group.id}`}>{t(`nav.groups.${group.id}`)}</h2>
          {group.links.map((item) => (
            <NavLink
              key={item.to}
              to={item.to}
              end={item.end}
              className={({ isActive }) => (isActive ? "active" : "")}
              onClick={closeNavigation}
              onKeyDown={navigationKeyDown}
            >
              {item.label}
            </NavLink>
          ))}
        </section>
      ));
  }

  function closeNavigation() {
    if (navigationOpen) document.getElementById("console-main")?.focus();
    setNavigationOpen(false);
    setSearch("");
    setMoreState({ path: location.pathname, open: false });
  }

  function navigationKeyDown(event: KeyboardEvent<HTMLElement>) {
    if (event.key !== "Escape" || (!search && !navigationOpen)) return;
    event.preventDefault();
    if (search) setSearch("");
    else {
      setNavigationOpen(false);
      menuButton.current?.focus();
    }
  }

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
      <a
        className="console-skip-link"
        href="#console-main"
        onClick={(event) => {
          event.preventDefault();
          closeNavigation();
          document.getElementById("console-main")?.focus();
        }}
      >
        {t("nav.skipToContent")}
      </a>
      <header className="layout-header">
        <span className="brand">
          <BrandMark />
        </span>
        <nav className="view-switch" aria-label={t("nav.views")}>
          {views.map((v) => (
            <NavLink
              key={v.to}
              to={v.to}
              end={v.end}
              className={({ isActive }) => (isActive ? "active" : "")}
              onClick={closeNavigation}
            >
              {v.label}
            </NavLink>
          ))}
        </nav>
        <OrganizationSwitcher />
        <NotificationBell />
        <button
          type="button"
          className="lang-switch"
          onClick={toggleLang}
          title={t("nav.switchLanguage")}
        >
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
        <aside className="layout-sidebar" data-open={navigationOpen}>
          <button
            type="button"
            ref={menuButton}
            className="console-menu-button"
            aria-expanded={navigationOpen}
            aria-controls={navigationID}
            onKeyDown={navigationKeyDown}
            onClick={() => setNavigationOpen((open) => !open)}
          >
            {t(navigationOpen ? "nav.closeNavigation" : "nav.openNavigation")}
          </button>
          <div className="console-sidebar-content" id={navigationID}>
            <div className="sidebar-title">{title}</div>
            <label className="console-nav-search">
              <span className="console-sr-only">{t("nav.search")}</span>
              <input
                ref={searchInput}
                type="search"
                value={search}
                placeholder={t("nav.search")}
                maxLength={100}
                onChange={(event) => setSearch(event.target.value)}
                onKeyDown={navigationKeyDown}
              />
            </label>
            {search && (
              <span className="console-sr-only" role="status">
                {t("nav.searchResults", { count: matchingLinks.length })}
              </span>
            )}
            <nav aria-label={t("nav.pages")}>
              {renderGroups(primaryGroups, "primary")}
              {hasMore && (
                <>
                  <button
                    type="button"
                    className="console-more-button"
                    aria-expanded={moreExpanded}
                    aria-controls={`${navigationID}-more`}
                    onKeyDown={navigationKeyDown}
                    onClick={() => setMoreState({ path: location.pathname, open: !moreExpanded })}
                    disabled={!!query}
                  >
                    {t("nav.moreFeatures")}
                    <span aria-hidden="true">{moreExpanded ? "−" : "+"}</span>
                  </button>
                  <div id={`${navigationID}-more`} hidden={!moreExpanded}>
                    <p className="console-more-hint">{t("nav.moreFeaturesHint")}</p>
                    {renderGroups(moreGroups, "more")}
                  </div>
                </>
              )}
            </nav>
            {matchingLinks.length === 0 && (
              <div className="console-nav-empty">
                <p>{t("nav.noResults")}</p>
                <button
                  type="button"
                  onKeyDown={navigationKeyDown}
                  onClick={() => {
                    setSearch("");
                    searchInput.current?.focus();
                  }}
                >
                  {t("nav.clearSearch")}
                </button>
              </div>
            )}
          </div>
        </aside>
        <main className="layout-main" id="console-main" tabIndex={-1}>
          <Outlet />
        </main>
      </div>
      <BrandFooter />
    </div>
  );
}
