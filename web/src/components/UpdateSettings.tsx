import { requestID as newRequestID } from "../utils/requestID";
import "../i18n/locales/features/updates/register";
import "./update-settings.css";
import { useEffect, useRef, useState, type FormEvent } from "react";
import { useTranslation } from "react-i18next";
import { useAuth } from "../auth/AuthContext";
import ServiceMaintenance from "./ServiceMaintenance";
import InstallationSchedule from "./InstallationSchedule";

type Settings = { automatic: boolean; interval_hours: number; revision: number };
type Status = {
  settings: Settings;
  current_version: string;
  current_known: boolean;
  platform: string;
  architecture: string;
  last_attempt: string;
  last_success: string;
  next_check: string;
  error?: string;
  checking: boolean;
  result: {
    status: string;
    version?: string;
    release_url?: string;
    artifact?: { name: string; url: string; sha256: string; bytes: number };
  };
};
type Audit = { at: string; actor: string; action: string; error?: string };
const endpoint = "/api/v1/settings/security/updates";

export default function UpdateSettings() {
  const { t, i18n } = useTranslation();
  const { accessToken } = useAuth();
  const [status, setStatus] = useState<Status | null>(null);
  const [settings, setSettings] = useState<Settings | null>(null);
  const [audit, setAudit] = useState<Audit[]>([]);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState(false);
  const request = useRef("");
  const auth = accessToken ? { Authorization: `Bearer ${accessToken}` } : undefined;
  useEffect(() => {
    const controller = new AbortController();
    const headers = accessToken ? { Authorization: `Bearer ${accessToken}` } : undefined;
    void Promise.all([
      fetch(endpoint, { headers, signal: controller.signal }),
      fetch(endpoint + "/audit", { headers, signal: controller.signal }),
    ])
      .then(async ([current, history]) => {
        if (!current.ok || !history.ok) throw new Error("unavailable");
        const [value, records] = await Promise.all([current.json(), history.json()]);
        if (!controller.signal.aborted) {
          setStatus(value as Status);
          setSettings((value as Status).settings);
          setAudit(records as Audit[]);
        }
      })
      .catch(() => {
        if (!controller.signal.aborted) setError("unavailable");
      });
    return () => controller.abort();
  }, [accessToken]);
  useEffect(() => {
    if (!status?.checking) return;
    const controller = new AbortController();
    const headers = accessToken ? { Authorization: `Bearer ${accessToken}` } : undefined;
    let pending = false;
    const timer = window.setInterval(() => {
      if (pending) return;
      pending = true;
      void fetch(endpoint, { headers, signal: controller.signal })
        .then(async (response) => {
          if (!response.ok) throw new Error("unavailable");
          const value = (await response.json()) as Status;
          if (!controller.signal.aborted) setStatus(value);
        })
        .catch(() => {
          if (!controller.signal.aborted) setError("unavailable");
        })
        .finally(() => {
          pending = false;
        });
    }, 1500);
    return () => {
      controller.abort();
      window.clearInterval(timer);
    };
  }, [accessToken, status?.checking]);
  async function change(method: "PUT" | "POST", body: object) {
    setBusy(true);
    setError("");
    setNotice(false);
    try {
      const response = await fetch(endpoint + (method === "POST" ? "/check" : ""), {
        method,
        headers: { ...auth, "Content-Type": "application/json" },
        body: JSON.stringify(body),
      });
      if (!response.ok) {
        const data = (await response.json().catch(() => ({}))) as { error_code?: string };
        setError(data.error_code || "unavailable");
        const fresh = await fetch(endpoint, { headers: auth });
        if (fresh.ok) {
          const value = (await fresh.json()) as Status;
          setStatus(value);
          setSettings(value.settings);
        }
        return;
      }
      const value = (await response.json()) as Status;
      setStatus(value);
      setSettings(value.settings);
      setNotice(method === "PUT");
      request.current = "";
      const history = await fetch(endpoint + "/audit", { headers: auth });
      if (history.ok) setAudit((await history.json()) as Audit[]);
    } catch {
      setError("unavailable");
    } finally {
      setBusy(false);
    }
  }
  function save(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (settings) {
      request.current = "";
      void change("PUT", settings);
    }
  }
  function check() {
    if (!status) return;
    request.current ||= newRequestID();
    void change("POST", { revision: status.settings.revision, request_id: request.current });
  }
  const date = (value: string) =>
    !value || value.startsWith("0001-")
      ? t("updates.never")
      : new Date(value).toLocaleString(i18n.language);
  const knownError = (code: string) =>
    t(
      `updates.errors.${["conflict", "busy", "rate_limited", "invalid_release", "network"].includes(code) ? code : "unavailable"}`,
    );
  return (
    <section className="settings-card settings-form update-settings-card">
      <h3>{t("updates.title")}</h3>
      <p>{t("updates.description")}</p>
      {error && (
        <p className="asset-error" role="alert">
          {knownError(error)}
        </p>
      )}
      {!status && !error && <p role="status">{t("updates.loading")}</p>}
      {status && settings && (
        <>
          <dl>
            <dt>{t("updates.current")}</dt>
            <dd>
              <code>{status.current_version}</code> · {status.platform}/{status.architecture}
            </dd>
            <dt>{t("updates.lastAttempt")}</dt>
            <dd>{date(status.last_attempt)}</dd>
            <dt>{t("updates.lastSuccess")}</dt>
            <dd>{date(status.last_success)}</dd>
            {settings.automatic && (
              <>
                <dt>{t("updates.nextCheck")}</dt>
                <dd>
                  {status.next_check.startsWith("0001-")
                    ? t("updates.soon")
                    : date(status.next_check)}
                </dd>
              </>
            )}
          </dl>
          {!status.current_known && <p className="settings-help">{t("updates.unknownBuild")}</p>}
          {status.error && (
            <p className="asset-error" role="status">
              {knownError(status.error)}
            </p>
          )}
          <p role="status">
            {t(`updates.states.${status.result.status}`)} {status.result.version || ""}
          </p>
          <button
            type="button"
            className="button-primary"
            disabled={busy || status.checking}
            onClick={check}
          >
            {busy || status.checking ? t("updates.checking") : t("updates.check")}
          </button>
          {status.result.release_url && (
            <p>
              <a href={status.result.release_url} target="_blank" rel="noreferrer">
                {t("updates.releaseNotes")}
              </a>
            </p>
          )}
          {status.result.version && !status.result.artifact && (
            <p className="settings-help">{t("updates.artifactPending")}</p>
          )}
          {status.result.artifact && (
            <details className="update-artifact">
              <summary>{t("updates.artifact")}</summary>
              <p>
                <a href={status.result.artifact.url} rel="noreferrer">
                  {status.result.artifact.name}
                </a>
              </p>
              <p className="settings-help">
                {t("updates.checksum")}: <code>{status.result.artifact.sha256}</code>
              </p>
            </details>
          )}
          <form onSubmit={save}>
            <label className="settings-checkbox">
              <input
                type="checkbox"
                checked={settings.automatic}
                onChange={(event) => {
                  setSettings({ ...settings, automatic: event.target.checked });
                  setNotice(false);
                }}
              />
              {t("updates.automatic")}
            </label>
            <label>
              <span>{t("updates.interval")}</span>
              <input
                type="number"
                min={1}
                max={168}
                step={1}
                required
                value={settings.interval_hours}
                onChange={(event) => {
                  setSettings({ ...settings, interval_hours: Number(event.target.value) });
                  setNotice(false);
                }}
              />
            </label>
            <p className="settings-help">{t("updates.checkOnly")}</p>
            <button type="submit" className="button-primary" disabled={busy}>
              {t("updates.save")}
            </button>
            {notice && <p role="status">{t("updates.saved")}</p>}
          </form>
          <ServiceMaintenance
            onChanged={() => {
              void fetch(endpoint + "/audit", { headers: auth })
                .then(async (response) => {
                  if (response.ok) setAudit((await response.json()) as Audit[]);
                })
                .catch(() => {});
            }}
          />
          <InstallationSchedule />
          <details>
            <summary>{t("updates.audit")}</summary>
            <ul>
              {audit
                .slice(-20)
                .reverse()
                .map((row, index) => (
                  <li key={`${row.at}-${index}`}>
                    {date(row.at)} · {row.actor} · {t(`updates.actions.${row.action}`)}
                    {row.error ? ` · ${knownError(row.error)}` : ""}
                  </li>
                ))}
            </ul>
          </details>
        </>
      )}
    </section>
  );
}
