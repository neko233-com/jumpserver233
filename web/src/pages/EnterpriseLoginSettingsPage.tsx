import { useCallback, useEffect, useState, type FormEvent } from "react";
import { Link, useLocation } from "react-router-dom";
import { useTranslation } from "react-i18next";
import { useIdentitySource, nativeLoginKind, type NativeLoginKind } from "../auth/identitySource";
import { usePermissions } from "../auth/usePermissions";
import { useIdentitySourceAPI } from "./identity-source-api";
import "../i18n/locales/features/enterprise-login/register";
import "./IdentitySourcesPage.css";
type Config = {
  provider: NativeLoginKind;
  client_id: string;
  tenant_id: string;
  agent_id: string;
  region: "cn" | "global";
  oauth_version: "v2" | "v3";
  callback_url: string;
  scopes: string[];
  ca_pem: string;
  allow_loopback_http: boolean;
  enabled: boolean;
  provision_new: boolean;
  revision: number;
  has_client_secret: boolean;
};
type Audit = { at: string; actor: string; revision: number; secret_changed: boolean };
function empty(kind: NativeLoginKind, callback: string): Config {
  return {
    provider: kind,
    client_id: "",
    tenant_id: "",
    agent_id: "",
    region: "cn",
    oauth_version: "v3",
    callback_url: callback,
    scopes: [],
    ca_pem: "",
    allow_loopback_http: false,
    enabled: false,
    provision_new: false,
    revision: 0,
    has_client_secret: false,
  };
}
export default function EnterpriseLoginSettingsPage() {
  const { t, i18n } = useTranslation();
  const location = useLocation();
  const selected = new URLSearchParams(location.search).get("provider");
  const kind = nativeLoginKind(selected) ? selected : null;
  const { id, prefix } = useIdentitySource();
  const { systemAllows, ready } = usePermissions();
  const allowed = systemAllows("security.manage");
  const { request, operation, completed } = useIdentitySourceAPI();
  const base = prefix + "/api/v1/settings/security/" + (kind ?? "wecom");
  const callback =
    window.location.origin + prefix + "/api/v1/authentication/" + (kind ?? "wecom") + "/callback";
  const [config, setConfig] = useState<Config>(() => empty(kind ?? "wecom", callback));
  const [secret, setSecret] = useState("");
  const [clearSecret, setClearSecret] = useState(false);
  const [scopes, setScopes] = useState("");
  const [audit, setAudit] = useState<Audit[]>([]);
  const [subject, setSubject] = useState("");
  const [alias, setAlias] = useState("");
  const [busy, setBusy] = useState(false);
  const [loaded, setLoaded] = useState(false);
  const [error, setError] = useState("");
  const [message, setMessage] = useState("");
  const load = useCallback(
    async (signal?: AbortSignal) => {
      try {
        const [c, a] = await Promise.all([
          request<Config>(base, { signal }),
          request<Audit[]>(base + "/audit", { signal }),
        ]);
        if (!signal?.aborted) {
          setConfig({ ...c, callback_url: c.callback_url || callback });
          setScopes(c.scopes.join(" "));
          setSecret("");
          setClearSecret(false);
          setAudit(a);
          setLoaded(true);
          setError("");
        }
      } catch (e) {
        if (!signal?.aborted)
          setError(e instanceof Error ? e.message : "enterprise_login_unavailable");
      }
    },
    [request, base, callback],
  );
  useEffect(() => {
    if (!allowed || !id || !kind) return;
    const c = new AbortController();
    queueMicrotask(() => {
      if (!c.signal.aborted) void load(c.signal);
    });
    return () => c.abort();
  }, [load, allowed, id, kind]);
  async function save(e: FormEvent) {
    e.preventDefault();
    if (busy) return;
    setBusy(true);
    setMessage("");
    try {
      const { has_client_secret: ignored, ...c } = config;
      void ignored;
      const out = await request<Config>(base, {
        method: "PUT",
        body: JSON.stringify(
          operation("native-provider:" + id, {
            ...c,
            scopes: scopes.trim() ? scopes.trim().split(/\s+/) : [],
            client_secret: secret,
            clear_secret: clearSecret,
          }),
        ),
      });
      completed("native-provider:" + id);
      setConfig(out);
      setSecret("");
      setClearSecret(false);
      setScopes(out.scopes.join(" "));
      setMessage(t("enterpriseLogin.saved"));
      setError("");
      await load();
    } catch (e) {
      setError(e instanceof Error ? e.message : "enterprise_login_unavailable");
    } finally {
      setBusy(false);
    }
  }
  async function check() {
    setBusy(true);
    setMessage("");
    try {
      await request(base + "/check", { method: "POST" });
      setMessage(t("enterpriseLogin.checkOK"));
      setError("");
    } catch (e) {
      setError(e instanceof Error ? e.message : "enterprise_login_unavailable");
    } finally {
      setBusy(false);
    }
  }
  async function prepare(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    setMessage("");
    try {
      const result = await request<{ username: string }>(base + "/users", {
        method: "POST",
        body: JSON.stringify({ subject, username: alias }),
      });
      setMessage(t("enterpriseLogin.prepared", { username: result.username }));
      setError("");
    } catch (e) {
      setError(e instanceof Error ? e.message : "enterprise_login_unavailable");
    } finally {
      setBusy(false);
    }
  }
  if (!ready) return null;
  if (!allowed || !id || !kind) return <p role="alert">{t("enterpriseLogin.denied")}</p>;
  return (
    <section className="identity-sources-page">
      <header>
        <h1>{t("enterpriseLogin.title", { provider: t("enterpriseLogin.providers." + kind) })}</h1>
        <p>{t("enterpriseLogin.hint")}</p>
        <Link to="/console/identity-sources">{t("enterpriseLogin.sources")}</Link>
      </header>
      {error && (
        <p role="alert">
          {t("enterpriseLogin.errors." + error, {
            defaultValue: t("enterpriseLogin.errors.enterprise_login_unavailable"),
          })}
        </p>
      )}
      {message && <p role="status">{message}</p>}
      <form onSubmit={(e) => void save(e)} className="identity-source-form">
        <fieldset disabled={!loaded || busy}>
          <legend>{t("enterpriseLogin.application")}</legend>
          <label>
            {t("enterpriseLogin.fields.client_id")}
            <input
              required
              maxLength={256}
              value={config.client_id}
              onChange={(e) =>
                setConfig({
                  ...config,
                  client_id: e.target.value,
                  ...(kind === "wecom" ? { tenant_id: e.target.value } : {}),
                })
              }
            />
          </label>
          {kind !== "wecom" && (
            <label>
              {t("enterpriseLogin.fields.tenant_id")}
              <input
                required
                maxLength={256}
                value={config.tenant_id}
                onChange={(e) => setConfig({ ...config, tenant_id: e.target.value })}
              />
            </label>
          )}
          {kind === "wecom" && (
            <label>
              {t("enterpriseLogin.fields.agent_id")}
              <input
                required
                maxLength={32}
                inputMode="numeric"
                value={config.agent_id}
                onChange={(e) => setConfig({ ...config, agent_id: e.target.value })}
              />
            </label>
          )}
          <label>
            {t("enterpriseLogin.fields.client_secret")}
            <input
              type="password"
              autoComplete="new-password"
              maxLength={4096}
              value={secret}
              disabled={clearSecret}
              onChange={(e) => setSecret(e.target.value)}
            />
          </label>
          <p>
            {t(
              config.has_client_secret
                ? "enterpriseLogin.secretSaved"
                : "enterpriseLogin.secretMissing",
            )}
          </p>
          <label className="identity-source-check">
            <input
              type="checkbox"
              checked={clearSecret}
              onChange={(e) => {
                setClearSecret(e.target.checked);
                setSecret("");
              }}
            />
            {t("enterpriseLogin.clearSecret")}
          </label>
          <label>
            {t("enterpriseLogin.fields.callback_url")}
            <input
              required
              type="url"
              maxLength={2048}
              value={config.callback_url}
              onChange={(e) => setConfig({ ...config, callback_url: e.target.value })}
            />
          </label>
          <p>{t("enterpriseLogin.callbackHint")}</p>
          {kind === "feishu" && (
            <>
              <label>
                {t("enterpriseLogin.fields.region")}
                <select
                  value={config.region}
                  onChange={(e) =>
                    setConfig({ ...config, region: e.target.value as Config["region"] })
                  }
                >
                  <option value="cn">{t("enterpriseLogin.regions.cn")}</option>
                  <option value="global">{t("enterpriseLogin.regions.global")}</option>
                </select>
              </label>
              <label>
                {t("enterpriseLogin.fields.oauth_version")}
                <select
                  value={config.oauth_version}
                  onChange={(e) =>
                    setConfig({
                      ...config,
                      oauth_version: e.target.value as Config["oauth_version"],
                    })
                  }
                >
                  <option value="v3">{t("enterpriseLogin.versions.v3")}</option>
                  <option value="v2">{t("enterpriseLogin.versions.v2")}</option>
                </select>
              </label>
              <label>
                {t("enterpriseLogin.fields.scopes")}
                <input
                  maxLength={2048}
                  value={scopes}
                  onChange={(e) => setScopes(e.target.value)}
                />
              </label>
            </>
          )}
          <details>
            <summary>{t("enterpriseLogin.advanced")}</summary>
            <label>
              {t("enterpriseLogin.fields.ca_pem")}
              <textarea
                rows={4}
                maxLength={262144}
                value={config.ca_pem}
                onChange={(e) => setConfig({ ...config, ca_pem: e.target.value })}
              />
            </label>
            <label className="identity-source-check">
              <input
                type="checkbox"
                checked={config.allow_loopback_http}
                onChange={(e) => setConfig({ ...config, allow_loopback_http: e.target.checked })}
              />
              {t("enterpriseLogin.loopback")}
            </label>
          </details>
          <label className="identity-source-check">
            <input
              type="checkbox"
              checked={config.enabled}
              onChange={(e) => setConfig({ ...config, enabled: e.target.checked })}
            />
            {t("enterpriseLogin.enabled")}
          </label>
          <label className="identity-source-check">
            <input
              type="checkbox"
              checked={config.provision_new}
              onChange={(e) => setConfig({ ...config, provision_new: e.target.checked })}
            />
            {t("enterpriseLogin.provision")}
          </label>
          <p>{t("enterpriseLogin.permissions")}</p>
          <div className="identity-source-toolbar">
            <button type="submit">{t("enterpriseLogin.save")}</button>
            <button type="button" onClick={() => void check()}>
              {t("enterpriseLogin.check")}
            </button>
            <button type="button" onClick={() => void load()}>
              {t("enterpriseLogin.reload")}
            </button>
          </div>
        </fieldset>
      </form>
      <form className="identity-source-form" onSubmit={(e) => void prepare(e)}>
        <h2>{t("enterpriseLogin.prepare")}</h2>
        <p>{t("enterpriseLogin.subjectHint")}</p>
        <label>
          {t("enterpriseLogin.fields.subject")}
          <input
            required
            maxLength={1024}
            value={subject}
            onChange={(e) => setSubject(e.target.value)}
          />
        </label>
        <label>
          {t("enterpriseLogin.fields.alias")}
          <input maxLength={64} value={alias} onChange={(e) => setAlias(e.target.value)} />
        </label>
        <button disabled={busy || !loaded || !config.client_id}>
          {t("enterpriseLogin.prepare")}
        </button>
      </form>
      <details>
        <summary>{t("enterpriseLogin.audit")}</summary>
        <div className="identity-source-table">
          <table>
            <thead>
              <tr>
                <th>{t("enterpriseLogin.at")}</th>
                <th>{t("enterpriseLogin.actor")}</th>
                <th>{t("enterpriseLogin.revision")}</th>
              </tr>
            </thead>
            <tbody>
              {audit.slice(0, 100).map((a, i) => (
                <tr key={i}>
                  <td>{new Date(a.at).toLocaleString(i18n.language)}</td>
                  <td>{a.actor}</td>
                  <td>{a.revision}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </details>
    </section>
  );
}
