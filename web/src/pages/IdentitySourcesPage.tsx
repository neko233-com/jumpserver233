import { useCallback, useEffect, useState, type FormEvent } from "react";
import { Link } from "react-router-dom";
import { useTranslation } from "react-i18next";
import { usePermissions } from "../auth/usePermissions";
import { identitySourcePrefix, nativeLoginKind, type IdentityKind } from "../auth/identitySource";
import { useIdentitySourceAPI } from "./identity-source-api";
import "../i18n/locales/features/identity-sources/register";
import "./IdentitySourcesPage.css";

type Kind = IdentityKind;
type Source = {
  id: string;
  name: string;
  kind: Kind;
  enabled: boolean;
  archived: boolean;
  revision: number;
  updated_at: string;
};
type Audit = { at: string; actor_id: string; source_id: string; action: string; revision: number };
type Draft = Omit<Source, "updated_at">;
const base = "/api/v1/identity-sources";
const empty: Draft = {
  id: "",
  name: "",
  kind: "ldap",
  enabled: false,
  archived: false,
  revision: 0,
};
const settings: Record<Kind, string> = {
  ldap: "directory",
  oidc: "identity",
  cas: "cas",
  saml: "saml",
  wecom: "enterprise-login",
  dingtalk: "enterprise-login",
  feishu: "enterprise-login",
};

export default function IdentitySourcesPage() {
  const { t, i18n } = useTranslation();
  const { systemAllows, ready } = usePermissions();
  const allowed = systemAllows("security.manage");
  const { request, operation } = useIdentitySourceAPI();
  const [rows, setRows] = useState<Source[]>([]);
  const [audit, setAudit] = useState<Audit[]>([]);
  const [draft, setDraft] = useState<Draft | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [message, setMessage] = useState("");
  const load = useCallback(
    async (signal?: AbortSignal) => {
      try {
        const [sources, events] = await Promise.all([
          request<Source[]>(base, { signal }),
          request<Audit[]>(base + "/audit", { signal }),
        ]);
        if (!signal?.aborted) {
          setRows(sources);
          setAudit(events);
          setError("");
        }
      } catch (e) {
        if (!signal?.aborted)
          setError(e instanceof Error ? e.message : "identity_sources_unavailable");
      }
    },
    [request],
  );
  useEffect(() => {
    if (!allowed) return;
    const c = new AbortController();
    queueMicrotask(() => {
      if (!c.signal.aborted) void load(c.signal);
    });
    return () => c.abort();
  }, [allowed, load]);
  async function save(e: FormEvent) {
    e.preventDefault();
    if (!draft || busy) return;
    setBusy(true);
    setMessage("");
    try {
      const { id, ...body } = draft;
      await request<Source>(base + (id ? "/" + id : ""), {
        method: id ? "PUT" : "POST",
        body: JSON.stringify(operation("source:" + id, body)),
      });
      setDraft(null);
      await load();
      setMessage(t("identitySources.saved"));
    } catch (e) {
      setError(e instanceof Error ? e.message : "identity_sources_unavailable");
    } finally {
      setBusy(false);
    }
  }
  if (!ready) return null;
  if (!allowed) return <p role="alert">{t("identitySources.denied")}</p>;
  return (
    <section className="identity-sources-page">
      <header className="identity-source-header">
        <div>
          <h1>{t("identitySources.title")}</h1>
          <p>{t("identitySources.hint")}</p>
        </div>
        <div>
          <button
            type="button"
            disabled={busy}
            onClick={() => {
              setDraft({ ...empty });
              setError("");
            }}
          >
            {t("identitySources.add")}
          </button>
          <button type="button" disabled={busy} onClick={() => void load()}>
            {t("identitySources.refresh")}
          </button>
        </div>
      </header>
      {error && (
        <p role="alert">
          {t("identitySources.errors." + error, {
            defaultValue: t("identitySources.errors.identity_sources_unavailable"),
          })}
        </p>
      )}
      {message && <p role="status">{message}</p>}
      {draft && (
        <form onSubmit={(e) => void save(e)} className="identity-source-form">
          <h2>{t(draft.id ? "identitySources.edit" : "identitySources.add")}</h2>
          <label>
            {t("identitySources.name")}
            <input
              required
              maxLength={160}
              value={draft.name}
              onChange={(e) => setDraft({ ...draft, name: e.target.value })}
            />
          </label>
          <label>
            {t("identitySources.kind")}
            <select
              disabled={!!draft.id}
              value={draft.kind}
              onChange={(e) => setDraft({ ...draft, kind: e.target.value as Kind })}
            >
              {(["ldap", "oidc", "cas", "saml", "wecom", "dingtalk", "feishu"] as const).map(
                (kind) => (
                  <option key={kind} value={kind}>
                    {t("identitySources.kinds." + kind)}
                  </option>
                ),
              )}
            </select>
          </label>
          <label className="identity-source-check">
            <input
              type="checkbox"
              checked={draft.enabled}
              disabled={draft.archived}
              onChange={(e) => setDraft({ ...draft, enabled: e.target.checked })}
            />
            {t("identitySources.enabled")}
          </label>
          {draft.id && (
            <label className="identity-source-check">
              <input
                type="checkbox"
                checked={draft.archived}
                onChange={(e) =>
                  setDraft({
                    ...draft,
                    archived: e.target.checked,
                    enabled: e.target.checked ? false : draft.enabled,
                  })
                }
              />
              {t("identitySources.archived")}
            </label>
          )}
          <p>{t("identitySources.disableHint")}</p>
          <div>
            <button disabled={busy} type="submit">
              {t("identitySources.save")}
            </button>
            <button disabled={busy} type="button" onClick={() => setDraft(null)}>
              {t("identitySources.cancel")}
            </button>
          </div>
        </form>
      )}
      {rows.length === 0 && <p>{t("identitySources.empty")}</p>}
      <div className="identity-source-grid">
        {rows.map((row) => (
          <article key={row.id}>
            <h2>{row.name}</h2>
            <p>
              {t("identitySources.kinds." + row.kind)} ·{" "}
              {t(
                row.archived
                  ? "identitySources.archived"
                  : row.enabled
                    ? "identitySources.enabled"
                    : "identitySources.disabled",
              )}
            </p>
            <code>{row.id}</code>
            <div className="identity-source-actions">
              <button
                type="button"
                disabled={busy}
                onClick={() =>
                  setDraft({
                    id: row.id,
                    name: row.name,
                    kind: row.kind,
                    enabled: row.enabled,
                    archived: row.archived,
                    revision: row.revision,
                  })
                }
              >
                {t("identitySources.edit")}
              </button>
              <Link
                to={`/console/${settings[row.kind]}?source_id=${row.id}${nativeLoginKind(row.kind) ? "&provider=" + row.kind : ""}`}
              >
                {t("identitySources.configure")}
              </Link>
              {row.kind === "ldap" && (
                <Link to={`/console/directory-sync?source_id=${row.id}`}>
                  {t("identitySources.sync")}
                </Link>
              )}
            </div>
            {row.kind !== "ldap" && (
              <label>
                {t("identitySources.callback")}
                <input
                  aria-label={t("identitySources.callback") + " " + row.name}
                  readOnly
                  value={
                    location.origin +
                    identitySourcePrefix(row.id) +
                    "/api/v1/authentication/" +
                    row.kind +
                    (row.kind === "saml" ? "/acs" : "/callback")
                  }
                  onFocus={(e) => e.target.select()}
                />
              </label>
            )}
          </article>
        ))}
      </div>
      <details>
        <summary>{t("identitySources.audit")}</summary>
        <div className="identity-source-table">
          <table>
            <thead>
              <tr>
                <th>{t("identitySources.at")}</th>
                <th>{t("identitySources.name")}</th>
                <th>{t("identitySources.actor")}</th>
                <th>{t("identitySources.revision")}</th>
              </tr>
            </thead>
            <tbody>
              {audit.slice(0, 100).map((event, i) => (
                <tr key={i}>
                  <td>{new Date(event.at).toLocaleString(i18n.language)}</td>
                  <td>{rows.find((r) => r.id === event.source_id)?.name ?? event.source_id}</td>
                  <td>{event.actor_id}</td>
                  <td>{event.revision}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </details>
    </section>
  );
}
