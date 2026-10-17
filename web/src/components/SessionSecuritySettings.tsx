import { useEffect, useState, type FormEvent } from "react";
import { useTranslation } from "react-i18next";
import { useAuth } from "../auth/AuthContext";

type Settings = {
  idle_minutes: number;
  max_hours: number;
  watermark: boolean;
  sharing: boolean;
  revision: number;
};
type Audit = { at: string; actor: string; before: Settings; after: Settings };

export default function SessionSecuritySettings() {
  const { t, i18n } = useTranslation();
  const { accessToken } = useAuth();
  const [settings, setSettings] = useState<Settings | null>(null);
  const [audit, setAudit] = useState<Audit[]>([]);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState(false);
  const [saved, setSaved] = useState(false);
  const headers = accessToken ? { Authorization: `Bearer ${accessToken}` } : undefined;
  useEffect(() => {
    const controller = new AbortController();
    const auth = accessToken ? { Authorization: `Bearer ${accessToken}` } : undefined;
    void Promise.all([
      fetch("/api/v1/settings/security/sessions", { headers: auth, signal: controller.signal }),
      fetch("/api/v1/settings/security/sessions/audit", {
        headers: auth,
        signal: controller.signal,
      }),
    ])
      .then(async ([policy, history]) => {
        if (!policy.ok || !history.ok) throw new Error("session security unavailable");
        const [current, records] = await Promise.all([policy.json(), history.json()]);
        if (!controller.signal.aborted) {
          setSettings(current as Settings);
          setAudit(records as Audit[]);
        }
      })
      .catch(() => {
        if (!controller.signal.aborted) setError(true);
      });
    return () => controller.abort();
  }, [accessToken]);
  async function save(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!settings) return;
    setBusy(true);
    setError(false);
    setSaved(false);
    try {
      const response = await fetch("/api/v1/settings/security/sessions", {
        method: "PUT",
        headers: { ...headers, "Content-Type": "application/json" },
        body: JSON.stringify(settings),
      });
      if (!response.ok) throw new Error("session security update failed");
      setSettings((await response.json()) as Settings);
      const history = await fetch("/api/v1/settings/security/sessions/audit", { headers });
      if (history.ok) setAudit((await history.json()) as Audit[]);
      setSaved(true);
    } catch {
      setError(true);
    } finally {
      setBusy(false);
    }
  }
  return (
    <section className="settings-card settings-form session-security-card">
      <h3>{t("sessionSecurity.title")}</h3>
      <p>{t("sessionSecurity.description")}</p>
      {error && (
        <p className="asset-error" role="alert">
          {t("sessionSecurity.error")}
        </p>
      )}
      {settings && (
        <form onSubmit={(event) => void save(event)}>
          <label>
            <span>{t("sessionSecurity.idle")}</span>
            <input
              type="number"
              required
              min={0}
              max={1440}
              step={1}
              value={settings.idle_minutes}
              onChange={(e) => {
                setSettings({ ...settings, idle_minutes: Number(e.target.value) });
                setSaved(false);
              }}
            />
          </label>
          <label>
            <span>{t("sessionSecurity.maximum")}</span>
            <input
              type="number"
              required
              min={0}
              max={168}
              step={1}
              value={settings.max_hours}
              onChange={(e) => {
                setSettings({ ...settings, max_hours: Number(e.target.value) });
                setSaved(false);
              }}
            />
          </label>
          <label className="settings-checkbox">
            <input
              type="checkbox"
              checked={settings.watermark}
              onChange={(e) => {
                setSettings({ ...settings, watermark: e.target.checked });
                setSaved(false);
              }}
            />
            <span>{t("sessionSecurity.watermark")}</span>
          </label>
          <p className="settings-help">{t("sessionSecurity.hint")}</p>
          <label className="settings-checkbox">
            <input
              type="checkbox"
              checked={settings.sharing}
              onChange={(e) => {
                setSettings({ ...settings, sharing: e.target.checked });
                setSaved(false);
              }}
            />
            <span>{t("sharing.enabled")}</span>
          </label>
          <button type="submit" className="button-primary" disabled={busy}>
            {busy ? "…" : t("sessionSecurity.save")}
          </button>
          {saved && (
            <p className="settings-notice" role="status">
              {t("sessionSecurity.saved")}
            </p>
          )}
        </form>
      )}
      <h4>{t("sessionSecurity.history")}</h4>
      {audit.length === 0 && <p>{t("sessionSecurity.empty")}</p>}
      {audit
        .slice(-10)
        .reverse()
        .map((item) => (
          <div key={item.after.revision} className="settings-help">
            <strong>{item.actor}</strong> · {new Date(item.at).toLocaleString(i18n.language)} ·{" "}
            {t("sessionSecurity.change", {
              idle: item.after.idle_minutes,
              max: item.after.max_hours,
              watermark: item.after.watermark ? t("sessionSecurity.on") : t("sessionSecurity.off"),
              sharing: item.after.sharing ? t("sessionSecurity.on") : t("sessionSecurity.off"),
            })}
          </div>
        ))}
    </section>
  );
}
