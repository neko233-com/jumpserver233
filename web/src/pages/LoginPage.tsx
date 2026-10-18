import { lazy, Suspense, useCallback, useEffect, useRef, useState, type FormEvent } from "react";
import { useTranslation } from "react-i18next";
import { useNavigate } from "react-router-dom";
import { useAuth } from "../auth/AuthContext";
import { loginReturnPath, clearLoginReturn } from "../auth/loginReturn";
import BlurText from "../components/BlurText";
import ShaderCanvas from "../components/ShaderCanvas";
import { toggleLang } from "../i18n";
import { getPasskey, passkeysSupported, type PasskeyRequestOptions } from "../auth/passkeys";
import OIDCLogin from "../components/OIDCLogin";
import LoginReviewPanel, { type LoginReviewPending } from "../components/LoginReviewPanel";
import "../i18n/locales/features/radius/register";
const RadiusPrimary = lazy(() => import("../components/RadiusPrimary"));
const RadiusFactor = lazy(() => import("../components/RadiusFactor"));

type Health = { status: string; version: string; time: string };
type AuthStatus = { bootstrap_required: boolean };
type MFAEnrollment = { secret: string; provisioning_uri: string; expires_at: string };
type LoginResult = {
  radius_factor_required?: boolean;
  login_review_required?: boolean;
  review_id?: string;
  expires_at?: string;
  code?: string;
  browser_session?: boolean;
  mfa_required?: boolean;
  mfa_setup_required?: boolean;
  setup_token?: string;
  enrollment?: MFAEnrollment;
};

function useHealth() {
  const [health, setHealth] = useState<Health | null>(null);
  const [error, setError] = useState(false);

  useEffect(() => {
    fetch("/api/health")
      .then((r) => (r.ok ? r.json() : Promise.reject(new Error(String(r.status)))))
      .then(setHealth)
      .catch(() => setError(true));
  }, []);

  return { health, error };
}

export default function LoginPage() {
  const { t, i18n } = useTranslation();
  const navigate = useNavigate();
  const [destination] = useState(loginReturnPath);
  const finishNavigation = useCallback(() => {
    clearLoginReturn();
    navigate(destination, { replace: true });
  }, [destination, navigate]);
  const { authenticated, sessionReady, setCookieSession } = useAuth();
  const { health, error: healthError } = useHealth();
  const [bootstrapRequired, setBootstrapRequired] = useState(false);
  const [statusLoaded, setStatusLoaded] = useState(false);
  const [username, setUsername] = useState("root");
  const [password, setPassword] = useState("");
  const [bootstrapToken, setBootstrapToken] = useState("");
  const [otp, setOtp] = useState("");
  const [otpRequired, setOtpRequired] = useState(false);
  const [setupChallenge, setSetupChallenge] = useState<{
    token: string;
    enrollment: MFAEnrollment;
  } | null>(null);
  const [authError, setAuthError] = useState(false);
  const [policyDenied, setPolicyDenied] = useState(false);
  const [loginReview, setLoginReview] = useState<LoginReviewPending | null>(null);
  const [submitting, setSubmitting] = useState(false);
  const [ssoEnabled, setSsoEnabled] = useState(false);
  const passkeyOperation = useRef<AbortController | null>(null);
  const [passkeyEnabled, setPasskeyEnabled] = useState(false);
  const [passkeyBusy, setPasskeyBusy] = useState(false);
  const [passkeyError, setPasskeyError] = useState(false);
  const [samlEnabled, setSamlEnabled] = useState(false);
  const [casEnabled, setCasEnabled] = useState(false);
  const [directoryEnabled, setDirectoryEnabled] = useState(false);
  const [radiusEnabled, setRadiusEnabled] = useState(false);
  const [factorPending, setFactorPending] = useState(
    () => new URLSearchParams(location.search).get("factor") === "radius",
  );
  const [authSource, setAuthSource] = useState(() =>
    new URLSearchParams(location.search).get("radius") === "challenge" ? "radius" : "local",
  );
  const [directoryPending, setDirectoryPending] = useState(false);
  const [ssoSource, setSsoSource] = useState<"oidc" | "cas" | "saml" | "passkey" | "radius" | null>(
    () => {
      const q = new URLSearchParams(window.location.search);
      if (q.get("radius") === "continue") return "radius";
      return q.get("passkey") === "continue"
        ? "passkey"
        : q.get("saml") === "continue"
          ? "saml"
          : q.get("cas") === "continue"
            ? "cas"
            : q.get("sso") === "continue"
              ? "oidc"
              : null;
    },
  );
  const ssoPending = ssoSource !== null;
  const ssoError = new URLSearchParams(window.location.search).has("sso_error");
  const samlError = new URLSearchParams(window.location.search).has("saml_error");
  const casError = new URLSearchParams(window.location.search).has("cas_error");
  const isZh = i18n.language !== "en";
  const waitForReview = useCallback((pending: LoginReviewPending) => {
    setFactorPending(false);
    setLoginReview(pending);
    setPassword("");
    setOtp("");
    setOtpRequired(false);
    setSetupChallenge(null);
    setDirectoryPending(false);
    setSsoSource(null);
    window.history.replaceState(null, "", "/login");
  }, []);
  const completeReview = useCallback(() => {
    setLoginReview(null);
    setCookieSession();
    finishNavigation();
  }, [setCookieSession, finishNavigation]);
  const cancelReview = useCallback(() => {
    setFactorPending(false);
    setAuthSource("local");
    setLoginReview(null);
    setPassword("");
    setOtp("");
    setOtpRequired(false);
    setSetupChallenge(null);
    setDirectoryPending(false);
    setSsoSource(null);
    window.history.replaceState(null, "", "/login");
  }, []);
  const waitForFactor = useCallback(() => {
    setFactorPending(true);
    setLoginReview(null);
    setSsoSource(null);
    setPassword("");
    setOtp("");
    setSetupChallenge(null);
    setDirectoryPending(false);
    window.history.replaceState(null, "", "/login?factor=radius");
  }, []);
  useEffect(() => {
    const c = new AbortController();
    void fetch("/api/v1/authentication/radius/status", { signal: c.signal })
      .then(async (r) => {
        if (r.ok) {
          const v = (await r.json()) as { enabled: boolean };
          if (!c.signal.aborted) setRadiusEnabled(v.enabled);
        }
      })
      .catch(() => {});
    return () => c.abort();
  }, []);
  useEffect(() => {
    if (!sessionReady || authenticated) return;
    const c = new AbortController();
    queueMicrotask(() => {
      if (c.signal.aborted) return;
      void fetch("/api/v1/authentication/login-review/pending", { signal: c.signal })
        .then(async (response) => {
          if (!response.ok) return;
          const data = (await response.json()) as LoginReviewPending & { active: boolean };
          if (!c.signal.aborted && data.active && data.review_id && data.expires_at)
            waitForReview(data);
        })
        .catch(() => undefined);
    });
    return () => c.abort();
  }, [sessionReady, authenticated, waitForReview]);
  useEffect(() => {
    const c = new AbortController();
    fetch("/api/v1/authentication/passkey/status", { signal: c.signal })
      .then(async (r) => {
        if (r.ok) {
          const data = (await r.json()) as { enabled: boolean };
          if (!c.signal.aborted) setPasskeyEnabled(data.enabled);
        }
      })
      .catch(() => undefined);
    fetch("/api/v1/authentication/saml/status", { signal: c.signal })
      .then(async (r) => {
        if (r.ok) {
          const data = (await r.json()) as { enabled: boolean };
          if (!c.signal.aborted) setSamlEnabled(data.enabled);
        }
      })
      .catch(() => undefined);
    fetch("/api/v1/authentication/cas/status", { signal: c.signal })
      .then(async (r) => {
        if (r.ok) {
          const data = (await r.json()) as { enabled: boolean };
          if (!c.signal.aborted) setCasEnabled(data.enabled);
        }
      })
      .catch(() => undefined);
    fetch("/api/v1/authentication/oidc/status", { signal: c.signal })
      .then(async (r) => {
        if (r.ok) {
          const data = (await r.json()) as { enabled: boolean };
          if (!c.signal.aborted) setSsoEnabled(data.enabled);
        }
      })
      .catch(() => undefined);
    fetch("/api/v1/authentication/ldap/status", { signal: c.signal })
      .then(async (r) => {
        if (r.ok) {
          const data = (await r.json()) as { enabled: boolean };
          if (!c.signal.aborted) setDirectoryEnabled(data.enabled);
        }
      })
      .catch(() => undefined);
    return () => c.abort();
  }, []);

  useEffect(() => {
    let active = true;
    fetch("/api/v1/authentication/status")
      .then((response) =>
        response.ok
          ? (response.json() as Promise<AuthStatus>)
          : Promise.reject(new Error(String(response.status))),
      )
      .then((result) => {
        if (active) setBootstrapRequired(result.bootstrap_required);
      })
      .catch(() => undefined)
      .finally(() => {
        if (active) setStatusLoaded(true);
      });
    return () => {
      active = false;
    };
  }, []);

  useEffect(() => {
    if (sessionReady && authenticated) finishNavigation();
  }, [authenticated, finishNavigation, sessionReady]);

  useEffect(() => () => passkeyOperation.current?.abort(), []);
  async function signInWithPasskey() {
    setPasskeyBusy(true);
    setPasskeyError(false);
    setPassword("");
    setOtp("");
    setOtpRequired(false);
    const c = new AbortController();
    passkeyOperation.current = c;
    try {
      const start = await fetch("/api/v1/authentication/passkey/start", {
        method: "POST",
        signal: c.signal,
      });
      if (!start.ok) throw new Error("Passkey unavailable");
      const credential = await getPasskey((await start.json()) as PasskeyRequestOptions, c.signal);
      const verified = await fetch("/api/v1/authentication/passkey/verify", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ credential }),
        signal: c.signal,
      });
      if (!verified.ok) throw new Error("Passkey rejected");
      await verified.json();
      setSsoSource("passkey");
      window.history.replaceState(null, "", "/login?passkey=continue");
    } catch {
      if (!c.signal.aborted) setPasskeyError(true);
      await fetch("/api/v1/authentication/passkey/pending", { method: "DELETE" }).catch(
        () => undefined,
      );
    } finally {
      passkeyOperation.current = null;
      setPasskeyBusy(false);
    }
  }
  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setSubmitting(true);
    setAuthError(false);
    setPolicyDenied(false);
    try {
      const headers = new Headers({
        "Content-Type": "application/json",
        "X-JMS-Browser-Session": "cookie",
      });
      if (!setupChallenge && bootstrapRequired && bootstrapToken.trim())
        headers.set("Authorization", `Bearer ${bootstrapToken.trim()}`);
      const directory = authSource === "ldap" && !bootstrapRequired;
      const endpoint = directory
        ? directoryPending
          ? "/api/v1/authentication/ldap/complete"
          : "/api/v1/authentication/ldap/login"
        : setupChallenge
          ? "/api/v1/authentication/mfa/setup/confirm"
          : bootstrapRequired
            ? "/api/v1/authentication/bootstrap"
            : "/api/v1/authentication/auth/";
      const response = await fetch(endpoint, {
        method: "POST",
        headers,
        body: JSON.stringify(
          directory && directoryPending
            ? { otp, ...(setupChallenge ? { setup_token: setupChallenge.token } : {}) }
            : setupChallenge
              ? { setup_token: setupChallenge.token, otp }
              : { username, password, ...(otpRequired ? { otp } : {}) },
        ),
      });
      const result = (await response.json()) as LoginResult;
      if (response.status === 202 && result.radius_factor_required) {
        waitForFactor();
        return;
      }
      if (
        response.status === 202 &&
        result.login_review_required &&
        result.review_id &&
        result.expires_at
      ) {
        waitForReview({ review_id: result.review_id, expires_at: result.expires_at });
        return;
      }
      if (result.code === "access_policy_denied") {
        setPolicyDenied(true);
        setPassword("");
        setOtp("");
        setAuthError(true);
        return;
      }
      if (
        directory &&
        response.status === 401 &&
        (result.mfa_required || result.mfa_setup_required)
      ) {
        setDirectoryPending(true);
        setPassword("");
      }
      if (
        !setupChallenge &&
        response.status === 401 &&
        result.mfa_setup_required &&
        result.setup_token &&
        result.enrollment
      ) {
        setSetupChallenge({ token: result.setup_token, enrollment: result.enrollment });
        setOtpRequired(false);
        setOtp("");
        return;
      }
      if (!setupChallenge && response.status === 401 && result.mfa_required) {
        setOtpRequired(true);
        setOtp("");
        return;
      }
      if (!response.ok) throw new Error("authentication failed");
      if (!result.browser_session) throw new Error("browser session cookie missing");
      setSetupChallenge(null);
      setPassword("");
      setDirectoryPending(false);
      setCookieSession();
      finishNavigation();
    } catch {
      setAuthError(true);
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <div className="login-page">
      <ShaderCanvas className="login-shader" />
      <div className="login-card">
        <h1 aria-label="JumpServer233">
          <BlurText text="JumpServer233" animateBy="letters" delay={60} />
        </h1>
        {statusLoaded && bootstrapRequired && (
          <>
            <h2>{t("login.setupTitle")}</h2>
            <p className="login-hint">{t("login.setupHint")}</p>
          </>
        )}
        {factorPending ? (
          <Suspense fallback={null}>
            <RadiusFactor
              onComplete={completeReview}
              onCancel={cancelReview}
              onReview={waitForReview}
            />
          </Suspense>
        ) : loginReview ? (
          <LoginReviewPanel
            key={loginReview.review_id}
            pending={loginReview}
            onComplete={completeReview}
            onCancel={cancelReview}
          />
        ) : ssoPending ? (
          <OIDCLogin
            onFactor={waitForFactor}
            onReview={waitForReview}
            source={ssoSource ?? "oidc"}
            key={ssoSource}
            onComplete={() => {
              setCookieSession();
              finishNavigation();
            }}
            onCancel={() => {
              setSsoSource(null);
              navigate("/login", { replace: true });
            }}
          />
        ) : authSource === "radius" ? (
          <Suspense fallback={null}>
            <RadiusPrimary
              onVerified={() => {
                setSsoSource("radius");
                window.history.replaceState(null, "", "/login?radius=continue");
              }}
              onCancel={cancelReview}
            />
          </Suspense>
        ) : (
          <>
            <form
              onSubmit={(event) => {
                void submit(event);
              }}
            >
              {(directoryEnabled || radiusEnabled) && !bootstrapRequired && (
                <label>
                  {t("ldap.source")}
                  <select
                    aria-label={t("ldap.source")}
                    value={authSource}
                    disabled={submitting || directoryPending}
                    onChange={(e) => {
                      setAuthSource(e.target.value);
                      setPassword("");
                      setOtp("");
                      setOtpRequired(false);
                      setSetupChallenge(null);
                      setAuthError(false);
                    }}
                  >
                    <option value="local">{t("ldap.local")}</option>
                    {directoryEnabled && <option value="ldap">{t("ldap.sourceOption")}</option>}
                    {radiusEnabled && <option value="radius">{t("radius.signIn")}</option>}
                  </select>
                </label>
              )}
              <label>
                {t("login.username")}
                <input
                  name="username"
                  autoComplete="username"
                  required
                  minLength={authSource === "ldap" ? 1 : 3}
                  maxLength={authSource === "ldap" ? 256 : 64}
                  disabled={directoryPending}
                  value={username}
                  onChange={(event) => {
                    setUsername(event.target.value);
                    setOtpRequired(false);
                    setSetupChallenge(null);
                    setOtp("");
                  }}
                />
              </label>
              <label>
                {t("login.password")}
                <input
                  name="password"
                  type="password"
                  autoComplete="current-password"
                  required
                  disabled={directoryPending}
                  minLength={bootstrapRequired ? 12 : undefined}
                  maxLength={authSource === "ldap" ? 4096 : 256}
                  value={password}
                  onChange={(event) => {
                    setPassword(event.target.value);
                    setOtpRequired(false);
                    setSetupChallenge(null);
                    setOtp("");
                  }}
                />
              </label>
              {setupChallenge && (
                <div className="login-mfa-setup">
                  <p>{t("login.mfaSetupHint")}</p>
                  <p>
                    {t("login.mfaSecret")} <code>{setupChallenge.enrollment.secret}</code>
                  </p>
                  <details>
                    <summary>{t("login.mfaShowURI")}</summary>
                    <code>{setupChallenge.enrollment.provisioning_uri}</code>
                  </details>
                  <small>
                    {t("login.mfaExpires", {
                      time: new Date(setupChallenge.enrollment.expires_at).toLocaleTimeString(
                        i18n.language,
                      ),
                    })}
                  </small>
                </div>
              )}
              {(otpRequired || setupChallenge) && (
                <label>
                  {t(setupChallenge ? "login.otp" : "login.otpOrRecoveryCode")}
                  <input
                    name="otp"
                    type="text"
                    inputMode="text"
                    autoComplete="one-time-code"
                    required
                    minLength={6}
                    maxLength={32}
                    value={otp}
                    onChange={(event) => setOtp(event.target.value.toUpperCase().slice(0, 32))}
                  />
                </label>
              )}
              {statusLoaded && bootstrapRequired && (
                <label>
                  {t("login.bootstrapToken")}
                  <input
                    name="bootstrap-token"
                    type="password"
                    autoComplete="off"
                    value={bootstrapToken}
                    onChange={(event) => setBootstrapToken(event.target.value)}
                  />
                </label>
              )}
              {authError && (
                <p className="login-error" role="alert">
                  {t(
                    policyDenied
                      ? "acl.loginDenied"
                      : setupChallenge
                        ? "login.mfaSetupError"
                        : bootstrapRequired
                          ? "login.bootstrapError"
                          : otpRequired
                            ? "login.otpOrRecoveryCodeError"
                            : "login.authError",
                  )}
                </p>
              )}
              <button type="submit" disabled={!statusLoaded || submitting}>
                {submitting
                  ? t("login.signingIn")
                  : t(
                      setupChallenge
                        ? "login.mfaEnableAndSignIn"
                        : bootstrapRequired
                          ? "login.bootstrap"
                          : "login.submit",
                    )}
              </button>
              {directoryPending && (
                <button
                  type="button"
                  className="oidc-cancel"
                  disabled={submitting}
                  onClick={() => {
                    void fetch("/api/v1/authentication/ldap/pending", { method: "DELETE" });
                    setDirectoryPending(false);
                    setSetupChallenge(null);
                    setOtpRequired(false);
                    setOtp("");
                    setPassword("");
                    setAuthError(false);
                  }}
                >
                  {t("ldap.cancel")}
                </button>
              )}
            </form>
            {passkeyError && (
              <p role="alert" className="login-error">
                {t("passkey.loginError")}
              </p>
            )}
            {passkeyEnabled && !bootstrapRequired && !setupChallenge && (
              <button
                type="button"
                className="oidc-sign-in"
                disabled={passkeyBusy || submitting || !passkeysSupported()}
                onClick={() => {
                  void signInWithPasskey();
                }}
              >
                {t("passkey.signIn")}
              </button>
            )}
            {passkeyBusy && (
              <button type="button" onClick={() => passkeyOperation.current?.abort()}>
                {t("passkey.cancel")}
              </button>
            )}
            {(ssoError || casError || samlError) && (
              <p role="alert" className="login-error">
                {t(samlError ? "saml.loginError" : casError ? "cas.loginError" : "oidc.loginError")}
              </p>
            )}
            {ssoEnabled && !bootstrapRequired && (
              <a className="oidc-sign-in" href="/api/v1/authentication/oidc/start">
                {t("oidc.signIn")}
              </a>
            )}
            {samlEnabled && !bootstrapRequired && (
              <a className="oidc-sign-in" href="/api/v1/authentication/saml/start">
                {t("saml.signIn")}
              </a>
            )}
            {casEnabled && !bootstrapRequired && (
              <a className="oidc-sign-in" href="/api/v1/authentication/cas/start">
                {t("cas.signIn")}
              </a>
            )}
          </>
        )}
        <p className="health-line">
          {t("login.api")}
          {healthError
            ? t("login.apiDown")
            : health
              ? t("login.apiOk", { version: health.version })
              : t("login.apiChecking")}
        </p>
        <button
          type="button"
          className="lang-switch login-lang"
          onClick={toggleLang}
          title="中文 / English"
        >
          {isZh ? "EN" : "中文"}
        </button>
      </div>
    </div>
  );
}
