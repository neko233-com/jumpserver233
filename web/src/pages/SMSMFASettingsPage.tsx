import { useCallback, useEffect, useRef, useState, type FormEvent } from "react";
import { Link } from "react-router-dom";
import { useTranslation } from "react-i18next";
import { useAuth } from "../auth/AuthContext";
import { usePermissions } from "../auth/usePermissions";
import "../i18n/locales/features/sms-mfa/register";
import "./IdentitySourcesPage.css";
type Config = {
  enabled: boolean;
  policy: "opt_in" | "admins" | "all" | "selected";
  user_ids: string[];
  revision: number;
};
type Audit = { at: string; actor_id: string; user_id?: string; action: string; revision: number };
export default function SMSMFASettingsPage() {
  const { t, i18n } = useTranslation();
  const { accessToken } = useAuth();
  const { systemAllows, ready } = usePermissions();
  const allowed = systemAllows("security.manage");
  const [config, setConfig] = useState<Config | null>(null);
  const [users, setUsers] = useState("");
  const [audit, setAudit] = useState<Audit[]>([]);
  const [error, setError] = useState("");
  const [message, setMessage] = useState("");
  const [busy, setBusy] = useState(false);
  const pending = useRef<{ body: string; id: string } | null>(null);
  const request = useCallback(
    async <T,>(suffix: string, init: RequestInit = {}): Promise<T> => {
      const headers = new Headers(init.headers);
      if (accessToken) headers.set("Authorization", "Bearer " + accessToken);
      if (init.body) headers.set("Content-Type", "application/json");
      const r = await fetch("/api/v1/settings/security/sms-mfa" + suffix, { ...init, headers });
      const v = await r.json().catch(() => ({}));
      if (!r.ok) throw Error(v.error_code ?? "sms_unavailable");
      return v;
    },
    [accessToken],
  );
  const load = useCallback(
    async (signal?: AbortSignal) => {
      try {
        const [cfg, events] = await Promise.all([
          request<Config>("", { signal }),
          request<Audit[]>("/audit", { signal }),
        ]);
        if (!signal?.aborted) {
          setConfig(cfg);
          setUsers(cfg.user_ids.join("\n"));
          setAudit(events);
          setError("");
        }
      } catch (e) {
        if (!signal?.aborted) setError(e instanceof Error ? e.message : "sms_unavailable");
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
  }, [load, allowed]);
  async function save(event: FormEvent) {
    event.preventDefault();
    if (!config || busy) return;
    setBusy(true);
    setMessage("");
    try {
      const body = {
        ...config,
        user_ids: config.policy === "selected" ? users.split(/\s+/).filter(Boolean) : [],
      };
      const raw = JSON.stringify(body);
      if (pending.current?.body !== raw) pending.current = { body: raw, id: crypto.randomUUID() };
      const result = await request<Config>("", {
        method: "PUT",
        body: JSON.stringify({ ...body, request_id: pending.current.id }),
      });
      pending.current = null;
      setConfig(result);
      setUsers(result.user_ids.join("\n"));
      setMessage(t("smsMFA.saved"));
      setError("");
      await load();
    } catch (e) {
      setError(e instanceof Error ? e.message : "sms_unavailable");
    } finally {
      setBusy(false);
    }
  }
  if (!ready) return null;
  if (!allowed) return <p role="alert">{t("smsMFA.denied")}</p>;
  return (
    <section className="identity-sources-page">
      <h1>{t("smsMFA.title")}</h1>
      <p>{t("smsMFA.hint")}</p>
      <Link to="/console/platform-notifications">{t("smsMFA.transport")}</Link>
      {error && (
        <p role="alert">
          {t("smsMFA.errors." + error, { defaultValue: t("smsMFA.errors.sms_unavailable") })}
        </p>
      )}
      {message && <p role="status">{message}</p>}
      {config && (
        <form onSubmit={(e) => void save(e)} className="identity-source-form">
          <fieldset disabled={busy}>
            <label>
              <input
                type="checkbox"
                checked={config.enabled}
                onChange={(e) => setConfig({ ...config, enabled: e.target.checked })}
              />
              {t("smsMFA.enabled")}
            </label>
            <label>
              {t("smsMFA.policy")}
              <select
                value={config.policy}
                onChange={(e) =>
                  setConfig({ ...config, policy: e.target.value as Config["policy"] })
                }
              >
                {(["opt_in", "admins", "all", "selected"] as const).map((v) => (
                  <option value={v} key={v}>
                    {t("smsMFA.policies." + v)}
                  </option>
                ))}
              </select>
            </label>
            {config.policy === "selected" && (
              <label>
                {t("smsMFA.users")}
                <textarea
                  rows={5}
                  value={users}
                  maxLength={1_290_000}
                  onChange={(e) => setUsers(e.target.value)}
                />
              </label>
            )}
            <button>{t("smsMFA.save")}</button>
            <button type="button" onClick={() => void load()}>
              {t("smsMFA.reload")}
            </button>
          </fieldset>
        </form>
      )}
      <h2>{t("smsMFA.audit")}</h2>
      <div className="rotation-table">
        <table>
          <thead>
            <tr>
              {["at", "actor", "user", "action", "revision"].map((v) => (
                <th key={v}>{t("smsMFA." + v)}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {audit.slice(0, 100).map((v, i) => (
              <tr key={v.at + v.action + i}>
                <td>{new Date(v.at).toLocaleString(i18n.language)}</td>
                <td>{v.actor_id}</td>
                <td>{v.user_id}</td>
                <td>{t("smsMFA.actions." + v.action)}</td>
                <td>{v.revision}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </section>
  );
}
