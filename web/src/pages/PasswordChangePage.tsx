import { useEffect, useState, type FormEvent } from "react";
import { passwordReturnPath } from "../auth/passwordRedirect";
import { useTranslation } from "react-i18next";
import PasswordRules, { type PasswordPolicy } from "../components/PasswordRules";
import { toggleLang } from "../i18n";
export default function PasswordChangePage() {
  const { t, i18n } = useTranslation(),
    [pending, setPending] = useState<{
      user: { username: string; role: string };
      policy: PasswordPolicy;
    } | null>(null),
    [password, setPassword] = useState(""),
    [confirm, setConfirm] = useState(""),
    [busy, setBusy] = useState(false),
    [error, setError] = useState("");
  useEffect(() => {
    const c = new AbortController();
    void fetch("/api/v1/authentication/password-change/pending", { signal: c.signal })
      .then(async (r) => {
        if (!r.ok) throw Error();
        const p = await r.json();
        if (!c.signal.aborted) setPending(p);
      })
      .catch(() => {
        if (!c.signal.aborted) setError("password_change_invalid");
      });
    return () => c.abort();
  }, []);
  async function save(e: FormEvent) {
    e.preventDefault();
    if (password !== confirm) {
      setError("mismatch");
      return;
    }
    setBusy(true);
    setError("");
    try {
      const r = await fetch("/api/v1/authentication/password-change/complete", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ new_password: password }),
      });
      const data = (await r.json()) as { error_code?: string };
      if (!r.ok) {
        setError(data.error_code || "error");
        return;
      }
      window.location.assign(passwordReturnPath("/login"));
    } catch {
      setError("error");
    } finally {
      setPassword("");
      setConfirm("");
      setBusy(false);
    }
  }
  return (
    <main className="settings-page">
      <section className="settings-card settings-form">
        <h1>{t("passwordSecurity.changeTitle")}</h1>
        <p>{t("passwordSecurity.changeHint")}</p>
        <button onClick={toggleLang}>{i18n.language === "en" ? "中文" : "EN"}</button>
        {pending && (
          <form className="settings-form" onSubmit={(e) => void save(e)}>
            <p>{pending.user.username}</p>
            <PasswordRules policy={pending.policy} admin={pending.user.role === "admin"} />
            {["password", "confirm"].map((k) => (
              <label key={k}>
                {t("passwordSecurity." + k)}
                <input
                  type="password"
                  autoComplete="new-password"
                  maxLength={256}
                  required
                  value={k === "password" ? password : confirm}
                  onChange={(e) =>
                    k === "password" ? setPassword(e.target.value) : setConfirm(e.target.value)
                  }
                />
              </label>
            ))}
            <button disabled={busy}>{t("passwordSecurity.change")}</button>
          </form>
        )}
        {error && (
          <p role="alert">{t("passwordSecurity." + (error in errorCodes ? error : "error"))}</p>
        )}
        <button
          disabled={busy}
          onClick={() => {
            void fetch("/api/v1/authentication/password-change/cancel", {
              method: "POST",
              headers: { "Content-Type": "application/json" },
              body: "{}",
            })
              .then((r) => {
                if (r.ok || r.status === 401) window.location.assign(passwordReturnPath("/login"));
                else setError("error");
              })
              .catch(() => setError("error"));
          }}
        >
          {t("passwordSecurity.back")}
        </button>
      </section>
    </main>
  );
}
const errorCodes = {
  password_policy: 1,
  password_history: 1,
  password_unchanged: 1,
  password_change_invalid: 1,
  password_rate_limit: 1,
  mismatch: 1,
};
