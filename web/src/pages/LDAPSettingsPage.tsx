import { useIdentitySource } from "../auth/identitySource";
import { useCallback, useEffect, useState, type FormEvent } from "react";
import { useTranslation } from "react-i18next";
import { useAuth } from "../auth/AuthContext";
import { usePermissions } from "../auth/usePermissions";
type Config = {
  url: string;
  base_dn: string;
  bind_dn: string;
  filter: string;
  identity_attribute: string;
  ca_pem: string;
  enabled: boolean;
  provision_new: boolean;
  revision: number;
  has_bind_password: boolean;
};
type Audit = { at: string; actor: string; config: Config };
const empty: Config = {
  url: "",
  base_dn: "",
  bind_dn: "",
  filter: "(uid={username})",
  identity_attribute: "entryUUID",
  ca_pem: "",
  enabled: false,
  provision_new: false,
  revision: 0,
  has_bind_password: false,
};
export default function LDAPSettingsPage() {
  const { t, i18n } = useTranslation();
  const { accessToken } = useAuth();
  const { prefix } = useIdentitySource();
  const { allows, ready } = usePermissions();
  const canManage = allows("security.manage");
  const [config, setConfig] = useState<Config>(empty);
  const [audit, setAudit] = useState<Audit[]>([]);
  const [password, setPassword] = useState("");
  const [clearPassword, setClearPassword] = useState(false);
  const [directoryUsername, setDirectoryUsername] = useState("");
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
      return fetch(prefix + "/api/v1/settings/security/ldap" + path, { ...init, headers });
    },
    [accessToken, prefix],
  );
  const load = useCallback(
    async (signal?: AbortSignal) => {
      try {
        const [a, b] = await Promise.all([request("", { signal }), request("/audit", { signal })]);
        if (!a.ok || !b.ok) throw new Error("settings unavailable");
        const [c, events] = (await Promise.all([a.json(), b.json()])) as [Config, Audit[]];
        if (signal?.aborted) return;
        setConfig(c);
        setAudit(events);
        setPassword("");
        setClearPassword(false);
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
      const { has_bind_password: ignored, ...body } = config;
      void ignored;
      const r = await request("", {
        method: "PUT",
        body: JSON.stringify({ ...body, bind_password: password, clear_password: clearPassword }),
      });
      if (!r.ok) throw new Error("save failed");
      setConfig((await r.json()) as Config);
      setPassword("");
      setClearPassword(false);
      await load();
      setMessage("saved");
    } catch {
      setError(true);
    } finally {
      setBusy(false);
    }
  }
  async function check() {
    setBusy(true);
    setMessage("");
    try {
      const r = await request("/check", { method: "POST" });
      if (!r.ok) throw new Error("check failed");
      await r.json();
      setError(false);
      setMessage("checked");
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
        body: JSON.stringify({ directory_username: directoryUsername, username }),
      });
      if (!r.ok) throw new Error("provision failed");
      const u = (await r.json()) as { username: string };
      setCreated(u.username);
      setDirectoryUsername("");
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
        <h1>{t("ldap.title")}</h1>
        <p>{t("oidc.denied")}</p>
      </section>
    );
  const fields = ["url", "base_dn", "bind_dn", "filter", "identity_attribute"] as const;
  return (
    <section className="jobs-page rbac-page oidc-settings">
      <header className="jobs-heading">
        <div>
          <h1>{t("ldap.title")}</h1>
          <p>{t("ldap.description")}</p>
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
          {t("ldap.error")}
        </p>
      )}
      {message && <p role="status">{t(`ldap.${message}`)}</p>}
      <div className="rbac-columns">
        <section>
          <h2>{t("ldap.provider")}</h2>
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
              {t("ldap.enabled")}
            </label>
            {fields.map((field) => (
              <label key={field}>
                {t(`ldap.${field}`)}
                <input
                  required
                  maxLength={field === "identity_attribute" ? 64 : 2048}
                  value={config[field]}
                  onChange={(e) => setConfig({ ...config, [field]: e.target.value })}
                />
              </label>
            ))}
            <p>{t("ldap.transportHint")}</p>
            <label>
              {t("ldap.password")}
              <input
                type="password"
                autoComplete="new-password"
                maxLength={4096}
                value={password}
                onChange={(e) => setPassword(e.target.value)}
              />
            </label>
            <p>{t(config.has_bind_password ? "ldap.passwordSaved" : "ldap.passwordMissing")}</p>
            <label className="rbac-check">
              <input
                type="checkbox"
                checked={clearPassword}
                onChange={(e) => setClearPassword(e.target.checked)}
              />
              {t("ldap.clearPassword")}
            </label>
            <label>
              {t("ldap.ca")}
              <textarea
                rows={5}
                maxLength={262144}
                value={config.ca_pem}
                onChange={(e) => setConfig({ ...config, ca_pem: e.target.value })}
              />
            </label>
            <p>{t("ldap.caHint")}</p>
            <label className="rbac-check">
              <input
                type="checkbox"
                checked={config.provision_new}
                onChange={(e) => setConfig({ ...config, provision_new: e.target.checked })}
              />
              {t("oidc.jit")}
            </label>
            <div>
              <button type="submit" disabled={busy || !loaded}>
                {t("ldap.save")}
              </button>
              <button
                type="button"
                disabled={busy || !config.revision}
                onClick={() => {
                  void check();
                }}
              >
                {t("ldap.check")}
              </button>
            </div>
          </form>
        </section>
        <section>
          <h2>{t("oidc.provisionTitle")}</h2>
          <p>{t("ldap.provisionHint")}</p>
          <form
            className="rbac-form"
            onSubmit={(e) => {
              void provision(e);
            }}
          >
            <label>
              {t("ldap.directoryUsername")}
              <input
                required
                maxLength={256}
                value={directoryUsername}
                onChange={(e) => setDirectoryUsername(e.target.value)}
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
          <p>{t("ldap.boundary")}</p>
        </section>
      </div>
      <h2>{t("oidc.audit")}</h2>
      <div className="jobs-table-scroll">
        <table className="jobs-table">
          <thead>
            <tr>
              <th>{t("rbac.time")}</th>
              <th>{t("rbac.actor")}</th>
              <th>{t("ldap.url")}</th>
              <th>{t("ldap.enabled")}</th>
              <th>{t("oidc.revision")}</th>
            </tr>
          </thead>
          <tbody>
            {audit.slice(0, 50).map((a) => (
              <tr key={a.config.revision}>
                <td>{new Date(a.at).toLocaleString(i18n.language)}</td>
                <td>{a.actor}</td>
                <td>{a.config.url}</td>
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
