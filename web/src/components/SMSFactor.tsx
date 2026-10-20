import { useCallback, useEffect, useRef, useState, type FormEvent } from "react";
import { useTranslation } from "react-i18next";
import { loginChallengeRedirect } from "../auth/passwordRedirect";
import type { LoginReviewPending } from "./LoginReviewPanel";
import "../i18n/locales/features/sms-mfa/register";

type Status = {
  active: boolean;
  purpose: string;
  masked_phone: string;
  delivery_state: string;
  needs_phone: boolean;
  expires_at: string;
  retry_at?: string;
};
export default function SMSFactor({
  onComplete,
  onCancel,
  onReview,
}: {
  onComplete: () => void;
  onCancel: () => void;
  onReview: (pending: LoginReviewPending) => void;
}) {
  const { t, i18n } = useTranslation();
  const [status, setStatus] = useState<Status | null>(null);
  const [phone, setPhone] = useState("");
  const [code, setCode] = useState("");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const [clock, setClock] = useState(Date.now());
  const requestID = useRef<{ action: string; body: string; id: string } | null>(null);
  const life = useRef<AbortController | null>(null);
  const request = useCallback(async (path: string, data?: unknown) => {
    const response = await fetch("/api/v1/authentication/sms/" + path, {
      method: data === undefined ? "GET" : "POST",
      headers: { "Content-Type": "application/json", "X-JMS-Browser-Session": "cookie" },
      ...(data === undefined ? {} : { body: JSON.stringify(data) }),
      signal: AbortSignal.any([
        AbortSignal.timeout(30000),
        ...(life.current ? [life.current.signal] : []),
      ]),
    });
    const result = await response.json().catch(() => ({}));
    if (!response.ok) throw Error(result.error_code ?? "sms_unavailable");
    return { response, result };
  }, []);
  useEffect(() => {
    const ctl = new AbortController();
    life.current = ctl;
    void request("pending")
      .then(({ result }) => {
        if (!ctl.signal.aborted) setStatus(result);
      })
      .catch((e) => {
        if (!ctl.signal.aborted) setError(e instanceof Error ? e.message : "sms_unavailable");
      });
    const timer = window.setInterval(() => setClock(Date.now()), 1000);
    return () => {
      ctl.abort();
      window.clearInterval(timer);
    };
  }, [request]);
  async function act(action: "bind" | "resend" | "complete", event?: FormEvent) {
    event?.preventDefault();
    if (busy) return;
    setBusy(true);
    setError("");
    try {
      let data: Record<string, string> = {};
      if (action === "complete") data = { code };
      else {
        const body = action === "bind" ? phone : "";
        if (requestID.current?.action !== action || requestID.current?.body !== body)
          requestID.current = { action, body, id: crypto.randomUUID() };
        data = { request_id: requestID.current.id, ...(action === "bind" ? { phone } : {}) };
      }
      const { response, result } = await request(action, data);
      setCode("");
      if (action !== "complete") {
        setStatus(result);
        requestID.current = null;
        return;
      }
      if (loginChallengeRedirect(result)) return;
      if (result.login_review_required && result.review_id && result.expires_at) {
        onReview({ review_id: result.review_id, expires_at: result.expires_at });
        return;
      }
      if (response.status === 200 && (result.browser_session || result.binding_updated)) {
        onComplete();
        return;
      }
      throw Error("sms_rejected");
    } catch (e) {
      setCode("");
      setError(e instanceof Error ? e.message : "sms_unavailable");
    } finally {
      setBusy(false);
    }
  }
  async function cancel() {
    setBusy(true);
    setCode("");
    try {
      const response = await fetch("/api/v1/authentication/sms/cancel", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: "{}",
        signal: AbortSignal.timeout(15000),
      });
      if (!response.ok) throw Error();
      onCancel();
    } catch {
      setError("sms_unavailable");
    } finally {
      setBusy(false);
    }
  }
  const remaining = status?.retry_at
    ? Math.max(0, Math.ceil((Date.parse(status.retry_at) - clock) / 1000))
    : 0;
  return (
    <section className="oidc-login">
      <h2>{t("smsMFA.verifyTitle")}</h2>
      <p>{t("smsMFA.verifyHint")}</p>
      {status && (
        <>
          <p>
            {t("smsMFA.expires", {
              time: new Date(status.expires_at).toLocaleTimeString(i18n.language),
            })}
          </p>
          {status.masked_phone && <p>{t("smsMFA.sentTo", { phone: status.masked_phone })}</p>}
        </>
      )}
      {status?.delivery_state === "uncertain" && <p role="status">{t("smsMFA.uncertain")}</p>}
      {status?.delivery_state === "failed" && <p role="status">{t("smsMFA.deliveryFailed")}</p>}
      {error && (
        <p role="alert">
          {t("smsMFA.errors." + error, { defaultValue: t("smsMFA.errors.sms_unavailable") })}
        </p>
      )}
      {status?.needs_phone ? (
        <form onSubmit={(e) => void act("bind", e)}>
          <label>
            {t("smsMFA.phone")}
            <input
              type="tel"
              autoComplete="tel"
              value={phone}
              maxLength={16}
              required
              pattern="\+[1-9][0-9]{6,14}"
              onChange={(e) => setPhone(e.target.value)}
            />
          </label>
          <p>{t("smsMFA.firstPhone")}</p>
          <button disabled={busy}>{t("smsMFA.send")}</button>
        </form>
      ) : (
        <>
          <form onSubmit={(e) => void act("complete", e)}>
            <label>
              {t("smsMFA.code")}
              <input
                type="password"
                inputMode="numeric"
                autoComplete="one-time-code"
                value={code}
                minLength={6}
                maxLength={6}
                required
                pattern="[0-9]{6}"
                onChange={(e) => setCode(e.target.value)}
              />
            </label>
            <button
              disabled={busy || !status || !["sent", "uncertain"].includes(status.delivery_state)}
            >
              {t("smsMFA.verify")}
            </button>
          </form>
          <button
            type="button"
            disabled={busy || !status || remaining > 0 || status.delivery_state === "sending"}
            onClick={() => void act("resend")}
          >
            {remaining > 0 ? t("smsMFA.resendIn", { seconds: remaining }) : t("smsMFA.resend")}
          </button>
        </>
      )}
      <button type="button" disabled={busy} onClick={() => void cancel()}>
        {t("smsMFA.cancel")}
      </button>
    </section>
  );
}
