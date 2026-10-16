import { useCallback, useEffect, useState, type FormEvent } from "react";
import { useTranslation } from "react-i18next";
import { useAuth } from "../auth/AuthContext";
import { usePermissions } from "../auth/usePermissions";
type Config = {
  entity_id: string;
  acs_url: string;
  metadata_xml: string;
  idp_entity_id: string;
  sp_fingerprint: string;
  allow_loopback_http: boolean;
  enabled: boolean;
  provision_new: boolean;
  revision: number;
  rotate_sp?: boolean;
};
type Audit = { at: string; actor: string; config: Config };
const empty: Config = {
  entity_id: "",
  acs_url: "",
  metadata_xml: "",
  idp_entity_id: "",
  sp_fingerprint: "",
  allow_loopback_http: false,
  enabled: false,
  provision_new: false,
  revision: 0,
};
export default function SAMLSettingsPage() {
  const { t, i18n } = useTranslation();
  const { accessToken } = useAuth();
  const { allows, ready } = usePermissions();
  const canManage = allows("security.manage");
  const [config, setConfig] = useState(empty);
  const [audit, setAudit] = useState<Audit[]>([]);
  const [subject, setSubject] = useState("");
  const [username, setUsername] = useState("");
  const [created, setCreated] = useState("");
  const [busy, setBusy] = useState(false);
  const [loaded, setLoaded] = useState(false);
  const [error, setError] = useState(false);
  const [message, setMessage] = useState("");
  const request = useCallback(
    (path: string, init?: RequestInit) => {
      const headers = new Headers(init?.headers);
      if (accessToken) headers.set("Authorization", `Bearer ${accessToken}`);
      if (init?.body) headers.set("Content-Type", "application/json");
      return fetch("/api/v1/settings/security/saml" + path, { ...init, headers });
    },
    [accessToken],
  );
  const load = useCallback(
    async (signal?: AbortSignal) => {
      try {
        const [a, b] = await Promise.all([request("", { signal }), request("/audit", { signal })]);
        if (!a.ok || !b.ok) throw new Error("SAML settings unavailable");
        const [c, events] = (await Promise.all([a.json(), b.json()])) as [Config, Audit[]];
        if (signal?.aborted) return;
        setConfig(c);
        setAudit(events);
        setLoaded(true);
        setError(false);
      } catch {
        if (!signal?.aborted) setError(true);
      }
    },
    [request],
  );
  useEffect(() => {
    if (!canManage) return;
    const c = new AbortController();
    queueMicrotask(() => {
      if (!c.signal.aborted) void load(c.signal);
    });
    return () => c.abort();
  }, [canManage, load]);
  async function save(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    setMessage("");
    try {
      const r = await request("", { method: "PUT", body: JSON.stringify(config) });
      if (!r.ok) throw new Error("SAML save failed");
      setConfig((await r.json()) as Config);
      await load();
      setMessage("saved");
    } catch {
      setError(true);
    } finally {
      setBusy(false);
    }
  }
  async function provision(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    try {
      const r = await request("/users", {
        method: "POST",
        body: JSON.stringify({ subject, username }),
      });
      if (!r.ok) throw new Error("provision failed");
      const u = (await r.json()) as { username: string };
      setCreated(u.username);
      setSubject("");
      setUsername("");
      setError(false);
    } catch {
      setError(true);
    } finally {
      setBusy(false);
    }
  }
  if (!ready) return <p className="placeholder">{t("placeholder.skeleton")}</p>;
  if (!canManage)
    return (
      <section className="jobs-page">
        <h1>{t("saml.title")}</h1>
        <p>{t("oidc.denied")}</p>
      </section>
    );
  return (
    <section className="jobs-page rbac-page oidc-settings">
      <header className="jobs-heading">
        <div>
          <h1>{t("saml.title")}</h1>
          <p>{t("saml.description")}</p>
        </div>
        <button
          type="button"
          disabled={busy}
          onClick={() => {
            void load();
          }}
        >
          {t("oidc.refresh")}
        </button>
      </header>
      {error && (
        <p role="alert" className="login-error">
          {t("saml.settingsError")}
        </p>
      )}
      {message && <p role="status">{t(`saml.${message}`)}</p>}
      <div className="rbac-columns">
        <section>
          <h2>{t("saml.provider")}</h2>
          <form
            className="rbac-form"
            onSubmit={(e) => {
              void save(e);
            }}
          >
            <label className="rbac-check">
              <input
                type="checkbox"
                checked={config.enabled}
                onChange={(e) => setConfig({ ...config, enabled: e.target.checked })}
              />
              {t("saml.enabled")}
            </label>
            <label>
              {t("saml.entityID")}
              <input
                type="url"
                required
                maxLength={2048}
                value={config.entity_id}
                onChange={(e) => setConfig({ ...config, entity_id: e.target.value })}
              />
            </label>
            <label>
              {t("saml.acsURL")}
              <input
                type="url"
                required
                maxLength={1900}
                value={config.acs_url}
                onChange={(e) => setConfig({ ...config, acs_url: e.target.value })}
              />
            </label>
            <p>{t("saml.acsHint")}</p>
            <label>
              {t("saml.metadata")}
              <textarea
                rows={5}
                maxLength={262144}
                value={config.metadata_xml}
                onChange={(e) => setConfig({ ...config, metadata_xml: e.target.value })}
              />
            </label>
            <p>{t("saml.metadataHint")}</p>
            <label className="rbac-check">
              <input
                type="checkbox"
                checked={config.allow_loopback_http}
                onChange={(e) => setConfig({ ...config, allow_loopback_http: e.target.checked })}
              />
              {t("oidc.loopback")}
            </label>
            <label className="rbac-check">
              <input
                type="checkbox"
                checked={config.provision_new}
                onChange={(e) => setConfig({ ...config, provision_new: e.target.checked })}
              />
              {t("oidc.jit")}
            </label>
            <label className="rbac-check">
              <input
                type="checkbox"
                checked={config.rotate_sp ?? false}
                onChange={(e) => setConfig({ ...config, rotate_sp: e.target.checked })}
              />
              {t("saml.rotate")}
            </label>
            <div>
              <button type="submit" disabled={busy || !loaded}>
                {t("saml.save")}
              </button>
            </div>
          </form>
          {config.sp_fingerprint && (
            <p className="saml-fingerprint">
              {t("saml.fingerprint")}: <code>{config.sp_fingerprint}</code>
            </p>
          )}
          {config.revision > 0 && (
            <a href="/api/v1/authentication/saml/metadata" target="_blank" rel="noreferrer">
              {t("saml.download")}
            </a>
          )}
        </section>
        <section>
          <h2>{t("oidc.provisionTitle")}</h2>
          <p>{t("saml.provisionHint")}</p>
          <form
            className="rbac-form"
            onSubmit={(e) => {
              void provision(e);
            }}
          >
            <label>
              {t("saml.subject")}
              <input
                required
                maxLength={1024}
                value={subject}
                onChange={(e) => setSubject(e.target.value)}
              />
            </label>
            <label>
              {t("oidc.username")}
              <input
                minLength={3}
                maxLength={64}
                value={username}
                onChange={(e) => setUsername(e.target.value)}
              />
            </label>
            <button type="submit" disabled={busy || !config.revision}>
              {t("oidc.provision")}
            </button>
          </form>
          {created && <p role="status">{t("oidc.provisioned", { username: created })}</p>}
          <h3>{t("oidc.boundaryTitle")}</h3>
          <p>{t("saml.boundary")}</p>
        </section>
      </div>
      <h2>{t("oidc.audit")}</h2>
      <div className="jobs-table-scroll">
        <table className="jobs-table">
          <thead>
            <tr>
              <th>{t("rbac.time")}</th>
              <th>{t("rbac.actor")}</th>
              <th>{t("saml.entityID")}</th>
              <th>{t("saml.enabled")}</th>
              <th>{t("oidc.revision")}</th>
            </tr>
          </thead>
          <tbody>
            {audit.slice(0, 50).map((a) => (
              <tr key={a.config.revision}>
                <td>{new Date(a.at).toLocaleString(i18n.language)}</td>
                <td>{a.actor}</td>
                <td>{a.config.entity_id}</td>
                <td>{t(a.config.enabled ? "oidc.yes" : "oidc.no")}</td>
                <td>{a.config.revision}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </section>
  );
}
