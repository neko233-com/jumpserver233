import { useCallback, useEffect, useState, type FormEvent } from "react";
import { useNavigate } from "react-router-dom";
import { useTranslation } from "react-i18next";
import { useAuth } from "../auth/AuthContext";
import { usePermissions } from "../auth/usePermissions";
type Config = {
  enabled: boolean;
  revision: number;
  available: boolean;
  origin: string;
  rp_id: string;
};
type Audit = {
  at: string;
  actor: string;
  kind: string;
  credential_id?: string;
  enabled: boolean;
  revision: number;
};
export default function PasskeySettingsPage() {
  const { t, i18n } = useTranslation();
  const { accessToken, setAccessToken } = useAuth();
  const navigate = useNavigate();
  const { allows, ready } = usePermissions();
  const canManage = allows("security.manage");
  const [config, setConfig] = useState<Config | null>(null);
  const [audit, setAudit] = useState<Audit[]>([]);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState(false);
  const [saved, setSaved] = useState(false);
  const request = useCallback(
    (path: string, init?: RequestInit) => {
      const headers = new Headers(init?.headers);
      if (accessToken) headers.set("Authorization", `Bearer ${accessToken}`);
      if (init?.body) headers.set("Content-Type", "application/json");
      return fetch("/api/v1/settings/security/passkeys" + path, { ...init, headers });
    },
    [accessToken],
  );
  const load = useCallback(
    async (signal?: AbortSignal) => {
      try {
        const [a, b] = await Promise.all([request("", { signal }), request("/audit", { signal })]);
        if (a.status === 401 || b.status === 401) {
          await Promise.all([a.text(), b.text()]);
          setAccessToken("");
          navigate("/login", { replace: true });
          return;
        }
        if (!a.ok || !b.ok) throw new Error("Passkey settings unavailable");
        const [c, events] = (await Promise.all([a.json(), b.json()])) as [Config, Audit[]];
        if (!signal?.aborted) {
          setConfig(c);
          setAudit(events);
          setError(false);
        }
      } catch {
        if (!signal?.aborted) setError(true);
      }
    },
    [request, navigate, setAccessToken],
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
    if (!config) return;
    setBusy(true);
    setSaved(false);
    try {
      const r = await request("", {
        method: "PUT",
        body: JSON.stringify({ enabled: config.enabled, revision: config.revision }),
      });
      if (!r.ok) throw new Error("Passkey settings rejected");
      setConfig((await r.json()) as Config);
      await load();
      setSaved(true);
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
        <h1>{t("passkey.title")}</h1>
        <p>{t("oidc.denied")}</p>
      </section>
    );
  return (
    <section className="jobs-page rbac-page oidc-settings">
      <header className="jobs-heading">
        <div>
          <h1>{t("passkey.title")}</h1>
          <p>{t("passkey.description")}</p>
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
          {t("passkey.settingsError")}
        </p>
      )}
      {saved && <p role="status">{t("passkey.saved")}</p>}
      {config && (
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
              disabled={!config.rp_id && !config.enabled}
              onChange={(e) => setConfig({ ...config, enabled: e.target.checked })}
            />
            {t("passkey.enabled")}
          </label>
          <p>
            {t("passkey.origin")}: <code>{config.origin || t("passkey.notConfigured")}</code>
          </p>
          <p>
            {t("passkey.rpID")}: <code>{config.rp_id || t("passkey.notConfigured")}</code>
          </p>
          {!config.rp_id && <p>{t("passkey.originHint")}</p>}
          <p>{t("passkey.policy")}</p>
          <button disabled={busy}>{t("passkey.save")}</button>
        </form>
      )}
      <h2>{t("passkey.audit")}</h2>
      <div className="jobs-table-scroll">
        <table className="jobs-table">
          <thead>
            <tr>
              <th>{t("rbac.time")}</th>
              <th>{t("rbac.actor")}</th>
              <th>{t("passkey.event")}</th>
              <th>{t("oidc.revision")}</th>
            </tr>
          </thead>
          <tbody>
            {audit.slice(0, 50).map((a, index) => (
              <tr key={a.at + index}>
                <td>{new Date(a.at).toLocaleString(i18n.language)}</td>
                <td>{a.actor}</td>
                <td>{t(`passkey.events.${a.kind}`)}</td>
                <td>{a.revision}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </section>
  );
}
