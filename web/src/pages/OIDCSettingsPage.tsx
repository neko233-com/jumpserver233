import { useCallback, useEffect, useState, type FormEvent } from "react";
import { useTranslation } from "react-i18next";
import { useAuth } from "../auth/AuthContext";
import { usePermissions } from "../auth/usePermissions";
type Config = {
  enabled: boolean;
  issuer: string;
  client_id: string;
  redirect_url: string;
  token_auth_method: string;
  allow_loopback_http: boolean;
  provision_new: boolean;
  revision: number;
  has_client_secret: boolean;
};
type Audit = { at: string; actor: string; config: Config };
const empty: Config = {
  enabled: false,
  issuer: "",
  client_id: "",
  redirect_url: "",
  token_auth_method: "client_secret_basic",
  allow_loopback_http: false,
  provision_new: false,
  revision: 0,
  has_client_secret: false,
};
export default function OIDCSettingsPage() {
  const { t, i18n } = useTranslation();
  const { accessToken } = useAuth();
  const { allows, ready } = usePermissions();
  const canManage = allows("security.manage");
  const [config, setConfig] = useState<Config>(empty);
  const [secret, setSecret] = useState("");
  const [clearSecret, setClearSecret] = useState(false);
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
      return fetch(path, { ...init, headers });
    },
    [accessToken],
  );
  const load = useCallback(
    async (signal?: AbortSignal) => {
      try {
        const [a, b] = await Promise.all([
          request("/api/v1/settings/security/oidc", { signal }),
          request("/api/v1/settings/security/oidc/audit", { signal }),
        ]);
        if (!a.ok || !b.ok) throw new Error("settings unavailable");
        const [c, events] = (await Promise.all([a.json(), b.json()])) as [Config, Audit[]];
        if (signal?.aborted) return;
        setConfig(c);
        setAudit(events);
        setSecret("");
        setClearSecret(false);
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
      const { has_client_secret: ignored, ...body } = config;
      void ignored;
      const r = await request("/api/v1/settings/security/oidc", {
        method: "PUT",
        body: JSON.stringify({ ...body, client_secret: secret, clear_secret: clearSecret }),
      });
      if (!r.ok) throw new Error("save failed");
      const saved = (await r.json()) as Config;
      setConfig(saved);
      setSecret("");
      setClearSecret(false);
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
    try {
      const r = await request("/api/v1/settings/security/oidc/check", { method: "POST" });
      if (!r.ok) throw new Error("discovery failed");
      setError(false);
      setMessage("discovered");
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
      const r = await request("/api/v1/settings/security/oidc/users", {
        method: "POST",
        body: JSON.stringify({ subject, username }),
      });
      if (!r.ok) throw new Error("provisioning failed");
      const user = (await r.json()) as { username: string };
      setCreated(user.username);
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
        <h1>{t("oidc.settingsTitle")}</h1>
        <p>{t("oidc.denied")}</p>
      </section>
    );
  return (
    <section className="jobs-page rbac-page oidc-settings">
      <header className="jobs-heading">
        <div>
          <h1>{t("oidc.settingsTitle")}</h1>
          <p>{t("oidc.description")}</p>
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
          {t("oidc.settingsError")}
        </p>
      )}
      {message && <p role="status">{t(`oidc.${message}`)}</p>}
      <div className="rbac-columns">
        <section>
          <h2>{t("oidc.provider")}</h2>
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
              {t("oidc.enabled")}
            </label>
            <label>
              {t("oidc.issuer")}
              <input
                required
                type="url"
                maxLength={2048}
                value={config.issuer}
                onChange={(e) => setConfig({ ...config, issuer: e.target.value })}
              />
            </label>
            <label>
              {t("oidc.clientID")}
              <input
                required
                maxLength={256}
                value={config.client_id}
                onChange={(e) => setConfig({ ...config, client_id: e.target.value })}
              />
            </label>
            <label>
              {t("oidc.redirectURL")}
              <input
                required
                type="url"
                maxLength={2048}
                value={config.redirect_url}
                onChange={(e) => setConfig({ ...config, redirect_url: e.target.value })}
              />
            </label>
            <p>{t("oidc.publicURLHint")}</p>
            <label>
              {t("oidc.authMethod")}
              <select
                value={config.token_auth_method}
                onChange={(e) => {
                  setConfig({ ...config, token_auth_method: e.target.value });
                  if (e.target.value === "none") {
                    setSecret("");
                    setClearSecret(true);
                  }
                }}
              >
                <option value="client_secret_basic">{t("oidc.basic")}</option>
                <option value="client_secret_post">{t("oidc.post")}</option>
                <option value="none">{t("oidc.none")}</option>
              </select>
            </label>
            <label>
              {t("oidc.secret")}
              <input
                type="password"
                autoComplete="new-password"
                maxLength={4096}
                disabled={config.token_auth_method === "none"}
                value={secret}
                onChange={(e) => setSecret(e.target.value)}
              />
            </label>
            <p>{t(config.has_client_secret ? "oidc.secretSaved" : "oidc.secretMissing")}</p>
            <label className="rbac-check">
              <input
                type="checkbox"
                checked={clearSecret}
                onChange={(e) => setClearSecret(e.target.checked)}
              />
              {t("oidc.clearSecret")}
            </label>
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
            <div>
              <button type="submit" disabled={busy || !loaded}>
                {t("oidc.save")}
              </button>
              <button
                type="button"
                disabled={busy || !config.revision}
                onClick={() => {
                  void check();
                }}
              >
                {t("oidc.check")}
              </button>
            </div>
          </form>
        </section>
        <section>
          <h2>{t("oidc.provisionTitle")}</h2>
          <p>{t("oidc.provisionHint")}</p>
          <form
            className="rbac-form"
            onSubmit={(e) => {
              void provision(e);
            }}
          >
            <label>
              {t("oidc.subject")}
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
                maxLength={64}
                value={username}
                onChange={(e) => setUsername(e.target.value)}
              />
            </label>
            <button type="submit" disabled={busy || !config.issuer}>
              {t("oidc.provision")}
            </button>
          </form>
          {created && <p role="status">{t("oidc.provisioned", { username: created })}</p>}
          <h3>{t("oidc.boundaryTitle")}</h3>
          <p>{t("oidc.boundary")}</p>
        </section>
      </div>
      <h2>{t("oidc.audit")}</h2>
      <div className="jobs-table-scroll">
        <table className="jobs-table">
          <thead>
            <tr>
              <th>{t("rbac.time")}</th>
              <th>{t("rbac.actor")}</th>
              <th>{t("oidc.issuer")}</th>
              <th>{t("oidc.enabled")}</th>
              <th>{t("oidc.revision")}</th>
            </tr>
          </thead>
          <tbody>
            {audit.slice(0, 50).map((a) => (
              <tr key={a.config.revision}>
                <td>{new Date(a.at).toLocaleString(i18n.language)}</td>
                <td>{a.actor}</td>
                <td>{a.config.issuer}</td>
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
