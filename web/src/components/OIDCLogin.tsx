import { passwordRedirect } from "../auth/passwordRedirect";
import { useEffect, useState, type FormEvent } from "react";
import { useTranslation } from "react-i18next";
import { type LoginReviewPending } from "./LoginReviewPanel";
type Setup = {
  token: string;
  enrollment: { secret: string; provisioning_uri: string; expires_at: string };
};
export default function OIDCLogin({
  onComplete,
  onCancel,
  onReview,
  onFactor,
  source = "oidc",
}: {
  onComplete: () => void;
  onCancel: () => void;
  onReview: (pending: LoginReviewPending) => void;
  onFactor?: () => void;
  source?: "oidc" | "cas" | "saml" | "passkey" | "radius";
}) {
  const { t, i18n } = useTranslation();
  const [active, setActive] = useState(false);
  const [otpRequired, setOtpRequired] = useState(false);
  const [otp, setOTP] = useState("");
  const [setup, setSetup] = useState<Setup | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState(false);
  const [policyDenied, setPolicyDenied] = useState(false);
  useEffect(() => {
    const c = new AbortController();
    fetch(`/api/v1/authentication/${source}/pending`, { signal: c.signal })
      .then(async (r) => {
        if (!r.ok) throw new Error("pending login unavailable");
        const data = (await r.json()) as { active: boolean; mfa_required: boolean };
        if (!c.signal.aborted) {
          setActive(data.active);
          setOtpRequired(data.mfa_required);
        }
      })
      .catch(() => {
        if (!c.signal.aborted) setError(true);
      });
    return () => c.abort();
  }, [source]);
  async function submit(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(false);
    setPolicyDenied(false);
    try {
      const r = await fetch(`/api/v1/authentication/${source}/complete`, {
        method: "POST",
        headers: { "Content-Type": "application/json", "X-JMS-Browser-Session": "cookie" },
        body: JSON.stringify({ otp, ...(setup ? { setup_token: setup.token } : {}) }),
      });
      const data = (await r.json()) as {
 password_change_required?: boolean;
        radius_factor_required?: boolean;
        login_review_required?: boolean;
        review_id?: string;
        expires_at?: string;
        code?: string;
        browser_session?: boolean;
        mfa_required?: boolean;
        mfa_setup_required?: boolean;
        setup_token?: string;
        enrollment?: Setup["enrollment"];
      };
      if (passwordRedirect(data))return;
      if (r.status === 202 && data.radius_factor_required && onFactor) {
        onFactor();
        return;
      }
      if (r.status === 202 && data.login_review_required && data.review_id && data.expires_at) {
        onReview({ review_id: data.review_id, expires_at: data.expires_at });
        return;
      }
      if (data.code === "access_policy_denied") {
        setPolicyDenied(true);
        setOTP("");
        setError(true);
        return;
      }
      if (r.status === 401 && data.mfa_setup_required && data.setup_token && data.enrollment) {
        setSetup({ token: data.setup_token, enrollment: data.enrollment });
        setOTP("");
        return;
      }
      if (r.status === 401 && data.mfa_required) {
        setOtpRequired(true);
        return;
      }
      if (!r.ok || !data.browser_session) throw new Error("SSO verification failed");
      onComplete();
    } catch {
      setError(true);
    } finally {
      setBusy(false);
    }
  }
  async function cancel() {
    await fetch(`/api/v1/authentication/${source}/pending`, { method: "DELETE" }).catch(
      () => undefined,
    );
    onCancel();
  }
  return (
    <section className="oidc-login">
      <h2>{t(`${source}.finishTitle`)}</h2>
      <p>{t(`${source}.finishHint`)}</p>
      <form
        onSubmit={(e) => {
          void submit(e);
        }}
      >
        {setup && (
          <div className="login-mfa-setup">
            <p>{t("login.mfaSetupHint")}</p>
            <p>
              {t("login.mfaSecret")} <code>{setup.enrollment.secret}</code>
            </p>
            <details>
              <summary>{t("login.mfaShowURI")}</summary>
              <code>{setup.enrollment.provisioning_uri}</code>
            </details>
            <small>
              {t("login.mfaExpires", {
                time: new Date(setup.enrollment.expires_at).toLocaleTimeString(i18n.language),
              })}
            </small>
          </div>
        )}
        {(otpRequired || setup) && (
          <label>
            {t(setup ? "login.otp" : "login.otpOrRecoveryCode")}
            <input
              required
              autoComplete="one-time-code"
              minLength={6}
              maxLength={32}
              value={otp}
              onChange={(e) => setOTP(e.target.value.toUpperCase())}
            />
          </label>
        )}
        {error && (
          <p role="alert" className="login-error">
            {t(policyDenied ? "acl.loginDenied" : `${source}.loginError`)}
          </p>
        )}
        <button type="submit" disabled={!active || busy}>
          {t(setup ? "login.mfaEnableAndSignIn" : `${source}.finish`)}
        </button>
      </form>
      <button
        type="button"
        className="oidc-cancel"
        onClick={() => {
          void cancel();
        }}
      >
        {t("oidc.cancel")}
      </button>
    </section>
  );
}
