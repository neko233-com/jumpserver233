import { loginChallengeRedirect } from "../auth/passwordRedirect";
import { useEffect, useState, type FormEvent } from "react";
import { useTranslation } from "react-i18next";
import type { LoginReviewPending } from "./LoginReviewPanel";
import "../i18n/locales/features/radius/register";
export default function RadiusFactor({
  onComplete,
  onCancel,
  onReview,
}: {
  onComplete: () => void;
  onCancel: () => void;
  onReview: (p: LoginReviewPending) => void;
}) {
  const { t, i18n } = useTranslation(),
    [response, setResponse] = useState(""),
    [busy, setBusy] = useState(false),
    [ready, setReady] = useState(false),
    [round, setRound] = useState(0),
    [expires, setExpires] = useState(""),
    [error, setError] = useState(false);
  useEffect(() => {
    const ctl = new AbortController();
    void fetch("/api/v1/authentication/factor/pending", { signal: ctl.signal })
      .then(async (r) => {
        if (!r.ok) throw Error();
        const v = (await r.json()) as {
          active: boolean;
          status?: { round: number; expires_at: string };
        };
        if (!v.active) throw Error();
        if (!ctl.signal.aborted) {
          setReady(true);
          setRound(v.status?.round || 0);
          setExpires(v.status?.expires_at || "");
        }
      })
      .catch(() => {
        if (!ctl.signal.aborted) setError(true);
      });
    return () => ctl.abort();
  }, []);
  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setError(false);
    try {
      const r = await fetch("/api/v1/authentication/factor/complete", {
        method: "POST",
        headers: { "Content-Type": "application/json", "X-JMS-Browser-Session": "cookie" },
        body: JSON.stringify({ response }),
      });
      setResponse("");
      const v = (await r.json()) as {
        password_change_required?: boolean;
        radius_challenge_required?: boolean;
        round?: number;
        browser_session?: boolean;
        login_review_required?: boolean;
        review_id?: string;
        expires_at?: string;
      };
      if (loginChallengeRedirect(v)) return;
      if (r.status === 202 && v.radius_challenge_required) {
        setRound(v.round || 0);
        return;
      }
      if (r.status === 202 && v.login_review_required && v.review_id && v.expires_at) {
        onReview({ review_id: v.review_id, expires_at: v.expires_at });
        return;
      }
      if (!r.ok || !v.browser_session) throw Error();
      onComplete();
    } catch {
      setError(true);
    } finally {
      setBusy(false);
    }
  };
  const cancel = async () => {
    setResponse("");
    await fetch("/api/v1/authentication/factor/cancel", { method: "POST" }).catch(() => {});
    onCancel();
  };
  return (
    <section className="oidc-login">
      <h2>{t("radius.factorTitle")}</h2>
      <p>{t("radius.factorHint")}</p>
      {round > 0 && <p role="status">{t("radius.challengeRound", { count: round })}</p>}
      {expires && (
        <p>{t("radius.expires", { time: new Date(expires).toLocaleTimeString(i18n.language) })}</p>
      )}
      <form onSubmit={(e) => void submit(e)}>
        <label>
          {t("radius.response")}
          <input
            type="password"
            aria-describedby="radius-factor-response-hint"
            maxLength={128}
            autoComplete="one-time-code"
            value={response}
            onChange={(e) => setResponse(e.target.value)}
          />
        </label>
        <p id="radius-factor-response-hint">{t("radius.responseHint")}</p>
        {error && (
          <p role="alert" className="login-error">
            {t("radius.factorError")}
          </p>
        )}
        <button disabled={!ready || busy}>{t("radius.verify")}</button>
      </form>
      <button type="button" className="oidc-cancel" disabled={busy} onClick={() => void cancel()}>
        {t("radius.restart")}
      </button>
    </section>
  );
}
