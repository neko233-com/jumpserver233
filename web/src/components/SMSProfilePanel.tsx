import { useCallback, useEffect, useState, type FormEvent } from "react";
import { useTranslation } from "react-i18next";
import { useAuth } from "../auth/AuthContext";
import SMSFactor from "./SMSFactor";
import "../i18n/locales/features/sms-mfa/register";
type Status = { available: boolean; enabled: boolean; forced: boolean; masked_phone: string };
export default function SMSProfilePanel({
  user,
}: {
  user: { source?: string; mfa_enabled: boolean };
}) {
  const { t } = useTranslation();
  const { accessToken } = useAuth();
  const [status, setStatus] = useState<Status | null>(null);
  const [pending, setPending] = useState(false);
  const [phone, setPhone] = useState("");
  const [password, setPassword] = useState("");
  const [otp, setOTP] = useState("");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const load = useCallback(
    async (signal: AbortSignal) => {
      try {
        const r = await fetch("/api/v1/users/me/sms-mfa", {
          headers: accessToken ? { Authorization: "Bearer " + accessToken } : {},
          signal,
        });
        if (!r.ok) throw Error("sms_unavailable");
        const out = await r.json();
        if (!signal.aborted) setStatus(out);
      } catch (e) {
        if (!signal.aborted) setError(e instanceof Error ? e.message : "sms_unavailable");
      }
    },
    [accessToken],
  );
  useEffect(() => {
    const c = new AbortController();
    void load(c.signal);
    return () => c.abort();
  }, [load]);
  async function enroll(remove: boolean, event?: FormEvent) {
    event?.preventDefault();
    if (busy) return;
    setBusy(true);
    setError("");
    try {
      const r = await fetch("/api/v1/users/me/sms-mfa/enroll", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "X-JMS-Browser-Session": "cookie",
          ...(accessToken ? { Authorization: "Bearer " + accessToken } : {}),
        },
        body: JSON.stringify({ phone: remove ? "" : phone, password, otp }),
        signal: AbortSignal.timeout(30000),
      });
      const out = await r.json().catch(() => ({}));
      if (r.status !== 202) throw Error(out.error_code ?? "sms_unavailable");
      setPassword("");
      setOTP("");
      setPending(true);
    } catch (e) {
      setPassword("");
      setOTP("");
      setError(e instanceof Error ? e.message : "sms_unavailable");
    } finally {
      setBusy(false);
    }
  }
  if (pending)
    return (
      <SMSFactor
        onComplete={() => window.location.assign("/login")}
        onCancel={() => setPending(false)}
        onReview={() => window.location.assign("/login")}
      />
    );
  return (
    <article className="mfa-card">
      <h2>{t("smsMFA.title")}</h2>
      <p>{t("smsMFA.profileHint")}</p>
      <p>{t(status?.available ? "smsMFA.available" : "smsMFA.unavailable")}</p>
      {status && (
        <p>
          {status.enabled ? t("smsMFA.bound", { phone: status.masked_phone }) : t("smsMFA.unbound")}
        </p>
      )}
      {status?.forced && <p>{t("smsMFA.forced")}</p>}
      {error && (
        <p role="alert">
          {t("smsMFA.errors." + error, { defaultValue: t("smsMFA.errors.sms_unavailable") })}
        </p>
      )}
      {status?.available && (
        <form onSubmit={(e) => void enroll(false, e)}>
          <p>{t("smsMFA.reauth")}</p>
          <label>
            {t("smsMFA.phone")}
            <input
              type="tel"
              autoComplete="tel"
              maxLength={16}
              required
              pattern="\+[1-9][0-9]{6,14}"
              value={phone}
              onChange={(e) => setPhone(e.target.value)}
            />
          </label>
          {!user.source && (
            <label>
              {t("smsMFA.password")}
              <input
                type="password"
                autoComplete="current-password"
                required
                maxLength={256}
                value={password}
                onChange={(e) => setPassword(e.target.value)}
              />
            </label>
          )}
          {user.mfa_enabled && (
            <label>
              {t("smsMFA.otp")}
              <input
                type="password"
                autoComplete="one-time-code"
                required
                maxLength={128}
                value={otp}
                onChange={(e) => setOTP(e.target.value)}
              />
            </label>
          )}
          <button disabled={busy}>{t("smsMFA.bind")}</button>
          {status.enabled && !status.forced && (
            <button type="button" disabled={busy} onClick={() => void enroll(true)}>
              {t("smsMFA.disable")}
            </button>
          )}
        </form>
      )}
    </article>
  );
}
