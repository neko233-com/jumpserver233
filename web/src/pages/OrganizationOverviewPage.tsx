import { useCallback, useEffect, useRef, useState } from "react";
import { useTranslation } from "react-i18next";
import { useAuth } from "../auth/AuthContext";
import { usePermissions } from "../auth/usePermissions";
import "../i18n/locales/features/organization-overview/register";
import "./IdentitySourcesPage.css";
import "./OrganizationOverviewPage.css";

type Counts = {
  assets: number;
  ssh_assets: number;
  online: number;
  offline: number;
  unknown: number;
  nodes: number;
  groups: number;
  active_sessions: number;
  active_jobs: number;
  protocols: Record<string, number>;
};
type Row = {
  id: string;
  name: string;
  revision: number;
  enabled: boolean;
  archived: boolean;
  members: number;
  state: string;
  counts: Counts | null;
};
type Overview = {
  generated_at: string;
  results: Row[];
  totals: Counts;
  enabled_organizations: number;
  collected_organizations: number;
  memberships: number;
  partial: boolean;
};
export default function OrganizationOverviewPage() {
  const { t, i18n } = useTranslation();
  const { accessToken } = useAuth();
  const { systemAllows, ready } = usePermissions();
  const allowed = systemAllows("organizations.overview");
  const [data, setData] = useState<Overview | null>(null);
  const [archived, setArchived] = useState(false);
  const [filter, setFilter] = useState("");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const active = useRef<AbortController | null>(null);
  const load = useCallback(async () => {
    active.current?.abort();
    const ctl = new AbortController();
    active.current = ctl;
    setBusy(true);
    setError("");
    setData(null);
    try {
      const response = await fetch("/api/v1/organizations/overview?include_archived=" + archived, {
        headers: accessToken ? { Authorization: "Bearer " + accessToken } : {},
        signal: AbortSignal.any([ctl.signal, AbortSignal.timeout(20000)]),
      });
      const out = await response.json().catch(() => ({}));
      if (!response.ok) throw Error(out.error_code ?? "organization_overview_unavailable");
      if (!ctl.signal.aborted) setData(out);
    } catch (e) {
      if (!ctl.signal.aborted)
        setError(e instanceof Error ? e.message : "organization_overview_unavailable");
    } finally {
      if (!ctl.signal.aborted) setBusy(false);
    }
  }, [accessToken, archived]);
  useEffect(() => {
    if (!allowed) return;
    let mounted = true;
    queueMicrotask(() => {
      if (mounted) void load();
    });
    return () => {
      mounted = false;
      active.current?.abort();
    };
  }, [allowed, load]);
  if (!ready) return null;
  if (!allowed) return <p role="alert">{t("organizationOverview.denied")}</p>;
  const items =
    data?.results.filter((row) =>
      row.name.toLocaleLowerCase().includes(filter.toLocaleLowerCase()),
    ) ?? [];
  const columns = [
    "assets",
    "ssh_assets",
    "online",
    "offline",
    "unknown",
    "nodes",
    "groups",
    "active_sessions",
    "active_jobs",
  ] as const;
  const labels: Record<(typeof columns)[number], string> = {
    assets: "assets",
    ssh_assets: "ssh",
    online: "online",
    offline: "offline",
    unknown: "unknown",
    nodes: "nodes",
    groups: "groups",
    active_sessions: "sessions",
    active_jobs: "jobs",
  };
  return (
    <section className="jobs-page identity-sources-page">
      <header className="jobs-heading">
        <div>
          <h1>{t("organizationOverview.title")}</h1>
          <p>{t("organizationOverview.hint")}</p>
        </div>
        <button type="button" disabled={busy} onClick={() => void load()}>
          {t("organizationOverview.refresh")}
        </button>
      </header>
      <label className="checkbox-label">
        <input
          type="checkbox"
          checked={archived}
          onChange={(event) => setArchived(event.target.checked)}
        />
        {t("organizationOverview.archived")}
      </label>
      {error && (
        <p role="alert">
          {t("organizationOverview.errors." + error, {
            defaultValue: t("organizationOverview.errors.organization_overview_unavailable"),
          })}
        </p>
      )}
      {data && (
        <>
          <p>
            {t("organizationOverview.generated", {
              time: new Date(data.generated_at).toLocaleString(i18n.language),
            })}
          </p>
          {data.partial && (
            <p role="status">
              {t("organizationOverview.partial", {
                collected: data.collected_organizations,
                enabled: data.enabled_organizations,
              })}
            </p>
          )}
          <dl className="organization-overview-totals">
            <div>
              <dt>{t("organizationOverview.organizations")}</dt>
              <dd>
                {data.collected_organizations}/{data.enabled_organizations}
              </dd>
            </div>
            <div>
              <dt>{t("organizationOverview.memberships")}</dt>
              <dd>{data.memberships}</dd>
            </div>
            {columns.map((key) => (
              <div key={key}>
                <dt>{t("organizationOverview." + labels[key])}</dt>
                <dd>{data.totals[key]}</dd>
              </div>
            ))}
          </dl>
          <label>
            {t("organizationOverview.filter")}
            <input
              type="search"
              value={filter}
              maxLength={128}
              onChange={(e) => setFilter(e.target.value)}
            />
          </label>
          <div className="identity-source-table">
            <table>
              <thead>
                <tr>
                  <th>{t("organizationOverview.organization")}</th>
                  <th>{t("organizationOverview.state")}</th>
                  <th>{t("organizationOverview.members")}</th>
                  {columns.map((key) => (
                    <th key={key}>{t("organizationOverview." + labels[key])}</th>
                  ))}
                  <th>{t("organizationOverview.protocols")}</th>
                </tr>
              </thead>
              <tbody>
                {items.map((row) => (
                  <tr key={row.id}>
                    <th scope="row">{row.name}</th>
                    <td>{t("organizationOverview.states." + row.state)}</td>
                    <td>{row.members}</td>
                    {columns.map((key) => (
                      <td key={key}>{row.counts?.[key] ?? t("organizationOverview.missing")}</td>
                    ))}
                    <td>
                      {row.counts
                        ? Object.entries(row.counts.protocols)
                            .sort(([a], [b]) => a.localeCompare(b))
                            .map(([name, count]) => name + ": " + count)
                            .join(", ")
                        : t("organizationOverview.missing")}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          {items.length === 0 && <p>{t("organizationOverview.empty")}</p>}
        </>
      )}
    </section>
  );
}
