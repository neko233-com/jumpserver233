import { useEffect, useState, type FormEvent } from "react";
import { useTranslation } from "react-i18next";
import "../i18n/locales/features/radius/register";
export default function RadiusPrimary({
  onVerified,
  onCancel,
}: {
  onVerified: () => void;
  onCancel: () => void;
}) {
  const { t } = useTranslation(),
    [username, setUsername] = useState(""),
    [password, setPassword] = useState(""),
    [response, setResponse] = useState(""),
    [challenge, setChallenge] = useState(
      () => new URLSearchParams(location.search).get("radius") === "challenge",
    ),
    [busy, setBusy] = useState(false),
    [error, setError] = useState(false),
    [round, setRound] = useState(0);
  useEffect(() => {
    if (!challenge) return;
    const ctl = new AbortController();
    void fetch("/api/v1/authentication/radius/challenge", { signal: ctl.signal })
      .then(async (r) => {
        if (!r.ok) throw Error();
        const v = (await r.json()) as { state: string; round: number };
        if (v.state !== "pending") throw Error();
        if (!ctl.signal.aborted) setRound(v.round);
      })
      .catch(() => {
        if (!ctl.signal.aborted) setError(true);
      });
    return () => ctl.abort();
  }, [challenge]);
  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setError(false);
    try {
      const r = await fetch(
        "/api/v1/authentication/radius/" + (challenge ? "challenge" : "login"),
        {
          method: "POST",
          headers: { "Content-Type": "application/json", "X-JMS-Browser-Session": "cookie" },
          body: JSON.stringify(challenge ? { response } : { username, password }),
        },
      );
      setPassword("");
      setResponse("");
      const v = (await r.json()) as {
        radius_challenge_required?: boolean;
        radius_primary_verified?: boolean;
        round?: number;
      };
      if (r.status === 202 && v.radius_challenge_required) {
        setChallenge(true);
        setRound(v.round || 0);
        history.replaceState(null, "", "/login?radius=challenge");
        return;
      }
      if (r.status !== 202 || !v.radius_primary_verified) throw Error();
      onVerified();
    } catch {
      setError(true);
    } finally {
      setBusy(false);
    }
  };
  const cancel = async () => {
    setPassword("");
    setResponse("");
    await fetch("/api/v1/authentication/radius/pending", { method: "DELETE" }).catch(() => {});
    onCancel();
  };
  return (
    <section className="oidc-login">
      <h2>{t("radius.signIn")}</h2>
      <p>{t(challenge ? "radius.primaryChallenge" : "radius.primaryHint")}</p>
      {challenge && <p>{t("radius.challengeRound", { count: round })}</p>}
      <form onSubmit={(e) => void submit(e)}>
        {challenge ? (
          <label>
            {t("radius.response")}
            <input
              type="password"
              autoComplete="one-time-code"
              maxLength={128}
              required
              value={response}
              onChange={(e) => setResponse(e.target.value)}
            />
          </label>
        ) : (
          <>
            <label>
              {t("login.username")}
              <input
                autoComplete="username"
                maxLength={128}
                required
                value={username}
                onChange={(e) => setUsername(e.target.value)}
              />
            </label>
            <label>
              {t("login.password")}
              <input
                type="password"
                autoComplete="current-password"
                maxLength={128}
                required
                value={password}
                onChange={(e) => setPassword(e.target.value)}
              />
            </label>
          </>
        )}
        {error && (
          <p role="alert" className="login-error">
            {t("radius.loginError")}
          </p>
        )}
        <button disabled={busy}>{t(challenge ? "radius.verify" : "login.submit")}</button>
      </form>
      <button type="button" className="oidc-cancel" disabled={busy} onClick={() => void cancel()}>
        {t("radius.restart")}
      </button>
    </section>
  );
}
