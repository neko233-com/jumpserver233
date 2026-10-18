import { useState, type FormEvent } from "react";
import { useTranslation } from "react-i18next";
import { useAuth } from "../auth/AuthContext";
import PasswordRules from "./PasswordRules";
export default function CredentialRecovery({
  user,
  kind,
  done,
}: {
  user: { id: string; username: string; role: string; revision: number };
  kind: "password" | "mfa";
  done: () => void;
}) {
  const { t } = useTranslation(),
    { accessToken } = useAuth(),
    [password, setPassword] = useState(""),
    [force, setForce] = useState(true),
    [busy, setBusy] = useState(false),
    [error, setError] = useState(false);
  async function reset(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(false);
    try {
      const r = await fetch(`/api/v1/users/${encodeURIComponent(user.id)}/${kind}/reset`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          ...(accessToken ? { Authorization: `Bearer ${accessToken}` } : {}),
        },
        body: JSON.stringify({
          revision: user.revision,
          ...(kind === "password" ? { new_password: password, force_change: force } : {}),
        }),
      });
      if (!r.ok) throw Error();
      done();
    } catch {
      setError(true);
    } finally {
      setPassword("");
      setBusy(false);
    }
  }
  return (
    <form className="users-editor" onSubmit={(e) => void reset(e)}>
      <h2>
        {t("passwordSecurity.reset_" + kind)}: {user.username}
      </h2>
      <p>{t("passwordSecurity.resetHint")}</p>
      {kind === "password" && (
        <>
          <PasswordRules admin={user.role === "admin"} />
          <label>
            {t("passwordSecurity.password")}
            <input
              type="password"
              autoComplete="new-password"
              required
              maxLength={256}
              value={password}
              onChange={(e) => setPassword(e.target.value)}
            />
          </label>
          <label>
            <input type="checkbox" checked={force} onChange={(e) => setForce(e.target.checked)} />
            {t("passwordSecurity.force")}
          </label>
        </>
      )}
      {error && <p role="alert">{t("passwordSecurity.resetError")}</p>}
      <button disabled={busy}>{t("passwordSecurity.apply")}</button>
      <button type="button" disabled={busy} onClick={done}>
        {t("passwordSecurity.cancel")}
      </button>
    </form>
  );
}
