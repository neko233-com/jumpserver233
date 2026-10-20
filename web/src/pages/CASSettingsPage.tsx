import { useIdentitySource } from "../auth/identitySource";
import { useCallback, useEffect, useState, type FormEvent } from "react";
import { useTranslation } from "react-i18next";
import { useAuth } from "../auth/AuthContext";
import { usePermissions } from "../auth/usePermissions";
type Config = {
  base_url: string;
  protocol: string;
  callback_url: string;
  ca_pem: string;
  allow_loopback_http: boolean;
  enabled: boolean;
  provision_new: boolean;
  revision: number;
};
type Audit = { at: string; actor: string; config: Config };
const empty: Config = {
  base_url: "",
  protocol: "3",
  callback_url: "",
  ca_pem: "",
  allow_loopback_http: false,
  enabled: false,
  provision_new: false,
  revision: 0,
};
export default function CASSettingsPage() {
  const { t, i18n } = useTranslation();
  const { accessToken } = useAuth();
  const { prefix } = useIdentitySource();
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
      return fetch(prefix + "/api/v1/settings/security/cas" + path, { ...init, headers });
    },
    [accessToken, prefix],
  );
  const load = useCallback(
    async (signal?: AbortSignal) => {
      try {
        const [a, b] = await Promise.all([request("", { signal }), request("/audit", { signal })]);
        if (!a.ok || !b.ok) throw new Error("CAS settings unavailable");
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
      if (!r.ok) throw new Error("CAS save failed");
      setConfig((await r.json()) as Config);
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
      if (!r.ok) throw new Error("CAS unavailable");
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
        <h1>{t("cas.title")}</h1>
        <p>{t("oidc.denied")}</p>
      </section>
    );
  return (
    <section className="jobs-page rbac-page oidc-settings">
      <header className="jobs-heading">
        <div>
          <h1>{t("cas.title")}</h1>
          <p>{t("cas.description")}</p>
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
          {t("cas.settingsError")}
        </p>
      )}
      {message && <p role="status">{t(`cas.${message}`)}</p>}
      <div className="rbac-columns">
        <section>
          <h2>{t("cas.provider")}</h2>
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
              {t("cas.enabled")}
            </label>
            <label>
              {t("cas.baseURL")}
              <input
                type="url"
                required
                maxLength={2048}
                value={config.base_url}
                onChange={(e) => setConfig({ ...config, base_url: e.target.value })}
              />
            </label>
            <label>
              {t("cas.protocol")}
              <select
                aria-label={t("cas.protocol")}
                value={config.protocol}
                onChange={(e) => setConfig({ ...config, protocol: e.target.value })}
              >
                <option value="3">{t("cas.protocol3")}</option>
                <option value="2">{t("cas.protocol2")}</option>
              </select>
            </label>
            <label>
              {t("oidc.redirectURL")}
              <input
                type="url"
                required
                maxLength={1900}
                value={config.callback_url}
                onChange={(e) => setConfig({ ...config, callback_url: e.target.value })}
              />
            </label>
            <p>{t("cas.callbackHint")}</p>
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
                {t("cas.save")}
              </button>
              <button
                type="button"
                disabled={busy || !config.revision}
                onClick={() => {
                  void check();
                }}
              >
                {t("cas.check")}
              </button>
            </div>
          </form>
        </section>
        <section>
          <h2>{t("oidc.provisionTitle")}</h2>
          <p>{t("cas.provisionHint")}</p>
          <form
            className="rbac-form"
            onSubmit={(e) => {
              void provision(e);
            }}
          >
            <label>
              {t("cas.subject")}
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
          <p>{t("cas.boundary")}</p>
        </section>
      </div>
      <h2>{t("oidc.audit")}</h2>
      <div className="jobs-table-scroll">
        <table className="jobs-table">
          <thead>
            <tr>
              <th>{t("rbac.time")}</th>
              <th>{t("rbac.actor")}</th>
              <th>{t("cas.baseURL")}</th>
              <th>{t("cas.enabled")}</th>
              <th>{t("oidc.revision")}</th>
            </tr>
          </thead>
          <tbody>
            {audit.slice(0, 50).map((a) => (
              <tr key={a.config.revision}>
                <td>{new Date(a.at).toLocaleString(i18n.language)}</td>
                <td>{a.actor}</td>
                <td>{a.config.base_url}</td>
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
