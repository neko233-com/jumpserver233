import { useCallback, useEffect, useState, type FormEvent } from "react";
import { useTranslation } from "react-i18next";
import PasskeysPanel from "../components/PasskeysPanel";
import { useAuth } from "../auth/AuthContext";
import "../i18n/locales/features/radius/register";

type Profile = {
  id: string;
  username: string;
  role: string;
  mfa_enabled: boolean;
  source?: string;
};
type MFAEnrollment = { secret: string; provisioning_uri: string; expires_at: string };
type MFARecoveryCodes = { codes: string[]; generated_at: string };
type AccessKeyMetadata = { access_key_id: string; created_at: string };
type AccessKeyCredentials = AccessKeyMetadata & { access_key_secret: string };
type PermanentTokenMetadata = { id: string; created_at: string };
type PermanentTokenCredentials = PermanentTokenMetadata & { token: string };

export default function ProfilePage() {
  const { t } = useTranslation();
  const { accessToken } = useAuth();
  const [profile, setProfile] = useState<Profile | null>(null);
  const [enrollment, setEnrollment] = useState<MFAEnrollment | null>(null);
  const [otp, setOtp] = useState("");
  const [password, setPassword] = useState("");
  const [recoveryOtp, setRecoveryOtp] = useState("");
  const [recoveryPassword, setRecoveryPassword] = useState("");
  const [recoveryCodes, setRecoveryCodes] = useState<string[]>([]);
  const [changeCurrentPassword, setChangeCurrentPassword] = useState("");
  const [newPassword, setNewPassword] = useState("");
  const [confirmNewPassword, setConfirmNewPassword] = useState("");
  const [busy, setBusy] = useState(false);
  const [loading, setLoading] = useState(true);
  const [errorKey, setErrorKey] = useState("");
  const [success, setSuccess] = useState(false);
  const [passwordErrorKey, setPasswordErrorKey] = useState("");
  const [passwordSuccess, setPasswordSuccess] = useState(false);
  const [accessKeys, setAccessKeys] = useState<AccessKeyMetadata[]>([]);
  const [createdAccessKey, setCreatedAccessKey] = useState<AccessKeyCredentials | null>(null);
  const [accessKeyBusy, setAccessKeyBusy] = useState(false);
  const [accessKeyErrorKey, setAccessKeyErrorKey] = useState("");
  const [permanentTokens, setPermanentTokens] = useState<PermanentTokenMetadata[]>([]);
  const [createdPermanentToken, setCreatedPermanentToken] =
    useState<PermanentTokenCredentials | null>(null);
  const [permanentTokenBusy, setPermanentTokenBusy] = useState(false);
  const [permanentTokenErrorKey, setPermanentTokenErrorKey] = useState("");
  const externalAccount =
    profile?.source === "oidc" ||
    profile?.source === "ldap" ||
    profile?.source === "cas" ||
    profile?.source === "saml" ||
    profile?.source === "radius";
  const externalNamespace =
    profile?.source === "radius"
      ? "radius"
      : profile?.source === "saml"
        ? "saml"
        : profile?.source === "ldap"
          ? "ldap"
          : profile?.source === "cas"
            ? "cas"
            : "oidc";
  const newPasswordBytes = new TextEncoder().encode(newPassword).length;

  const request = useCallback(
    async <T,>(path: string, init: RequestInit = {}): Promise<T> => {
      const headers = new Headers(init.headers);
      if (accessToken) headers.set("Authorization", `Bearer ${accessToken}`);
      if (init.body) headers.set("Content-Type", "application/json");
      const response = await fetch(path, { ...init, headers });
      if (!response.ok) throw new Error(String(response.status));
      if (response.status === 204) return undefined as T;
      return response.json() as Promise<T>;
    },
    [accessToken],
  );

  useEffect(() => {
    let active = true;
    void request<Profile>("/api/v1/users/me")
      .then((user) => {
        if (active) setProfile(user);
      })
      .catch(() => {
        if (active) setErrorKey("profile.errorGeneric");
      })
      .finally(() => {
        if (active) setLoading(false);
      });
    void request<AccessKeyMetadata[]>("/api/v1/users/me/access-keys")
      .then((keys) => {
        if (active) setAccessKeys(keys);
      })
      .catch(() => {
        if (active) setAccessKeyErrorKey("profile.accessKeyLoadError");
      });
    void request<PermanentTokenMetadata[]>("/api/v1/users/me/tokens")
      .then((tokens) => {
        if (active) setPermanentTokens(tokens);
      })
      .catch(() => {
        if (active) setPermanentTokenErrorKey("profile.tokenLoadError");
      });
    return () => {
      active = false;
    };
  }, [request]);

  function reportError(error: unknown) {
    const status = error instanceof Error ? error.message : "";
    const key =
      status === "403" && externalAccount
        ? `${externalNamespace}.reauthRequired`
        : status === "401"
          ? "profile.errorAuth"
          : status === "400"
            ? "profile.errorInvalidOTP"
            : status === "409"
              ? "profile.errorConflict"
              : status === "410"
                ? "profile.errorExpired"
                : status === "503"
                  ? "profile.errorUnavailable"
                  : "profile.errorGeneric";
    setErrorKey(key);
  }

  function reportPasswordError(error: unknown) {
    const status = error instanceof Error ? error.message : "";
    const key =
      status === "401"
        ? "profile.errorAuth"
        : status === "403"
          ? "profile.passwordCurrentInvalid"
          : status === "400"
            ? "profile.passwordInvalid"
            : status === "409"
              ? "profile.passwordConflict"
              : "profile.errorGeneric";
    setPasswordErrorKey(key);
  }

  async function changePassword(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setPasswordErrorKey("");
    setPasswordSuccess(false);
    if (newPassword !== confirmNewPassword) {
      setPasswordErrorKey("profile.passwordMismatch");
      return;
    }
    if (newPasswordBytes < 12 || newPasswordBytes > 256) {
      setPasswordErrorKey("profile.passwordInvalid");
      return;
    }
    setBusy(true);
    try {
      await request<void>("/api/v1/users/me/password/change", {
        method: "POST",
        body: JSON.stringify({
          current_password: changeCurrentPassword,
          new_password: newPassword,
        }),
      });
      setChangeCurrentPassword("");
      setNewPassword("");
      setConfirmNewPassword("");
      setPasswordSuccess(true);
    } catch (error) {
      reportPasswordError(error);
    } finally {
      setBusy(false);
    }
  }

  function reportAccessKeyError(error: unknown) {
    const status = error instanceof Error ? error.message : "";
    const key =
      status === "409"
        ? "profile.accessKeyLimit"
        : status === "503"
          ? "profile.accessKeyUnavailable"
          : "profile.accessKeyError";
    setAccessKeyErrorKey(key);
  }

  async function createAccessKey() {
    setAccessKeyBusy(true);
    setAccessKeyErrorKey("");
    setCreatedAccessKey(null);
    try {
      const credentials = await request<AccessKeyCredentials>("/api/v1/users/me/access-keys", {
        method: "POST",
        body: "{}",
      });
      setCreatedAccessKey(credentials);
      setAccessKeys((current) => [
        ...current,
        { access_key_id: credentials.access_key_id, created_at: credentials.created_at },
      ]);
    } catch (error) {
      reportAccessKeyError(error);
    } finally {
      setAccessKeyBusy(false);
    }
  }

  async function deleteAccessKey(key: AccessKeyMetadata) {
    if (!window.confirm(t("profile.accessKeyRevokeConfirm"))) return;
    setAccessKeyBusy(true);
    setAccessKeyErrorKey("");
    try {
      await request<void>(`/api/v1/users/me/access-keys/${encodeURIComponent(key.access_key_id)}`, {
        method: "DELETE",
      });
      setAccessKeys((current) =>
        current.filter((item) => item.access_key_id !== key.access_key_id),
      );
      if (createdAccessKey?.access_key_id === key.access_key_id) setCreatedAccessKey(null);
    } catch (error) {
      reportAccessKeyError(error);
    } finally {
      setAccessKeyBusy(false);
    }
  }

  async function createPermanentToken() {
    setPermanentTokenBusy(true);
    setPermanentTokenErrorKey("");
    setCreatedPermanentToken(null);
    try {
      const credentials = await request<PermanentTokenCredentials>("/api/v1/users/me/tokens", {
        method: "POST",
        body: "{}",
      });
      setCreatedPermanentToken(credentials);
      setPermanentTokens((current) => [
        ...current,
        { id: credentials.id, created_at: credentials.created_at },
      ]);
    } catch (error) {
      const status = error instanceof Error ? error.message : "";
      setPermanentTokenErrorKey(status === "409" ? "profile.tokenLimit" : "profile.tokenError");
    } finally {
      setPermanentTokenBusy(false);
    }
  }

  async function deletePermanentToken(token: PermanentTokenMetadata) {
    if (!window.confirm(t("profile.tokenRevokeConfirm"))) return;
    setPermanentTokenBusy(true);
    setPermanentTokenErrorKey("");
    try {
      await request<void>(`/api/v1/users/me/tokens/${encodeURIComponent(token.id)}`, {
        method: "DELETE",
      });
      setPermanentTokens((current) => current.filter((item) => item.id !== token.id));
      if (createdPermanentToken?.id === token.id) setCreatedPermanentToken(null);
    } catch {
      setPermanentTokenErrorKey("profile.tokenError");
    } finally {
      setPermanentTokenBusy(false);
    }
  }

  async function startEnrollment() {
    setBusy(true);
    setErrorKey("");
    setSuccess(false);
    try {
      const result = await request<MFAEnrollment>("/api/v1/users/me/mfa/enrollment", {
        method: "POST",
        body: "{}",
      });
      setEnrollment(result);
      setOtp("");
    } catch (error) {
      reportError(error);
    } finally {
      setBusy(false);
    }
  }

  async function confirmEnrollment(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setBusy(true);
    setErrorKey("");
    setSuccess(false);
    try {
      const updated = await request<Profile>("/api/v1/users/me/mfa/confirm", {
        method: "POST",
        body: JSON.stringify({ otp }),
      });
      setProfile(updated);
      setEnrollment(null);
      setOtp("");
      setSuccess(true);
    } catch (error) {
      reportError(error);
    } finally {
      setBusy(false);
    }
  }

  async function disableMFA(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setBusy(true);
    setErrorKey("");
    setSuccess(false);
    try {
      const updated = await request<Profile>("/api/v1/users/me/mfa/disable", {
        method: "POST",
        body: JSON.stringify({ password, otp }),
      });
      setProfile(updated);
      setPassword("");
      setOtp("");
      setRecoveryCodes([]);
      setSuccess(true);
    } catch (error) {
      reportError(error);
    } finally {
      setBusy(false);
    }
  }

  async function regenerateRecoveryCodes(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setBusy(true);
    setErrorKey("");
    setSuccess(false);
    try {
      const result = await request<MFARecoveryCodes>("/api/v1/users/me/mfa/recovery-codes", {
        method: "POST",
        body: JSON.stringify({ password: recoveryPassword, otp: recoveryOtp }),
      });
      setRecoveryCodes(result.codes);
      setRecoveryPassword("");
      setRecoveryOtp("");
      setSuccess(true);
    } catch (error) {
      reportError(error);
    } finally {
      setBusy(false);
    }
  }

  const codeField = (label: string) => (
    <label className="mfa-field">
      <span>{label}</span>
      <input
        inputMode="numeric"
        autoComplete="one-time-code"
        required
        minLength={6}
        maxLength={6}
        pattern="[0-9]{6}"
        value={otp}
        onChange={(event) => setOtp(event.target.value.replace(/\D/g, "").slice(0, 6))}
      />
    </label>
  );

  const recoveryCodeField = () => (
    <label className="mfa-field">
      <span>{t("profile.mfaCode")}</span>
      <input
        inputMode="numeric"
        autoComplete="one-time-code"
        required
        minLength={6}
        maxLength={6}
        pattern="[0-9]{6}"
        value={recoveryOtp}
        onChange={(event) => setRecoveryOtp(event.target.value.replace(/\D/g, "").slice(0, 6))}
      />
    </label>
  );

  return (
    <section className="profile-security">
      <header className="profile-security-heading">
        <div>
          <h2>{t("profile.title")}</h2>
          <p>{t("profile.subtitle")}</p>
        </div>
        {profile && <span className="profile-identity">{profile.username}</span>}
      </header>

      {!loading && externalAccount && (
        <p className="settings-notice">{t(`${externalNamespace}.passwordManaged`)}</p>
      )}
      {!loading && profile && !externalAccount && (
        <article className="mfa-card password-card">
          <div className="mfa-card-heading">
            <div>
              <h3>{t("profile.passwordTitle")}</h3>
              <p>{t("profile.passwordDescription")}</p>
            </div>
          </div>
          <form className="mfa-form" onSubmit={(event) => void changePassword(event)}>
            <label className="mfa-field">
              <span>{t("profile.password")}</span>
              <input
                type="password"
                autoComplete="current-password"
                required
                value={changeCurrentPassword}
                onChange={(event) => setChangeCurrentPassword(event.target.value)}
              />
            </label>
            <label className="mfa-field">
              <span>{t("profile.passwordNew")}</span>
              <input
                type="password"
                autoComplete="new-password"
                required
                maxLength={256}
                value={newPassword}
                onChange={(event) => setNewPassword(event.target.value)}
              />
            </label>
            <label className="mfa-field">
              <span>{t("profile.passwordConfirm")}</span>
              <input
                type="password"
                autoComplete="new-password"
                required
                maxLength={256}
                value={confirmNewPassword}
                onChange={(event) => setConfirmNewPassword(event.target.value)}
              />
            </label>
            {confirmNewPassword && newPassword !== confirmNewPassword && (
              <p className="mfa-feedback error">{t("profile.passwordMismatch")}</p>
            )}
            <button
              type="submit"
              disabled={
                busy ||
                newPasswordBytes < 12 ||
                newPasswordBytes > 256 ||
                newPassword !== confirmNewPassword
              }
            >
              {busy ? t("profile.working") : t("profile.passwordChange")}
            </button>
          </form>
          {passwordErrorKey && (
            <p className="mfa-feedback error" role="alert">
              {t(passwordErrorKey)}
            </p>
          )}
          {passwordSuccess && (
            <p className="mfa-feedback success" role="status">
              {t("profile.passwordChanged")}
            </p>
          )}
        </article>
      )}

      {!loading && profile && (
        <article className="mfa-card access-key-card">
          <div className="mfa-card-heading">
            <div>
              <h3>{t("profile.accessKeyTitle")}</h3>
              <p>{t("profile.accessKeyDescription")}</p>
            </div>
          </div>
          <button
            type="button"
            className="button-secondary"
            disabled={accessKeyBusy}
            onClick={() => void createAccessKey()}
          >
            {accessKeyBusy ? t("profile.working") : t("profile.accessKeyCreate")}
          </button>
          {createdAccessKey && (
            <div className="mfa-recovery-codes access-key-created" role="status">
              <p>{t("profile.accessKeySaveNow")}</p>
              <div>
                <span>{t("profile.accessKeyID")}</span>
                <code>{createdAccessKey.access_key_id}</code>
              </div>
              <div>
                <span>{t("profile.accessKeySecret")}</span>
                <code>{createdAccessKey.access_key_secret}</code>
              </div>
              <button
                type="button"
                className="button-secondary"
                onClick={() => setCreatedAccessKey(null)}
              >
                {t("profile.accessKeyHide")}
              </button>
            </div>
          )}
          {accessKeyErrorKey && (
            <p className="mfa-feedback error" role="alert">
              {t(accessKeyErrorKey)}
            </p>
          )}
          <div className="access-key-list">
            {accessKeys.length === 0 ? (
              <p>{t("profile.accessKeyEmpty")}</p>
            ) : (
              accessKeys.map((key) => (
                <div className="access-key-row" key={key.access_key_id}>
                  <div>
                    <code>{key.access_key_id}</code>
                    <small>{new Date(key.created_at).toLocaleString()}</small>
                  </div>
                  <button
                    type="button"
                    className="button-text danger"
                    disabled={accessKeyBusy}
                    onClick={() => void deleteAccessKey(key)}
                  >
                    {t("profile.accessKeyRevoke")}
                  </button>
                </div>
              ))
            )}
          </div>
        </article>
      )}

      {!loading && profile && (
        <article className="mfa-card access-key-card">
          <div className="mfa-card-heading">
            <div>
              <h3>{t("profile.tokenTitle")}</h3>
              <p>{t("profile.tokenDescription")}</p>
            </div>
          </div>
          <button
            type="button"
            className="button-secondary"
            disabled={permanentTokenBusy}
            onClick={() => void createPermanentToken()}
          >
            {permanentTokenBusy ? t("profile.working") : t("profile.tokenCreate")}
          </button>
          {createdPermanentToken && (
            <div className="mfa-recovery-codes access-key-created" role="status">
              <p>{t("profile.tokenSaveNow")}</p>
              <div>
                <span>{t("profile.tokenID")}</span>
                <code>{createdPermanentToken.id}</code>
              </div>
              <div>
                <span>{t("profile.tokenValue")}</span>
                <code>{createdPermanentToken.token}</code>
              </div>
              <button
                type="button"
                className="button-secondary"
                onClick={() => setCreatedPermanentToken(null)}
              >
                {t("profile.accessKeyHide")}
              </button>
            </div>
          )}
          {permanentTokenErrorKey && (
            <p className="mfa-feedback error" role="alert">
              {t(permanentTokenErrorKey)}
            </p>
          )}
          <div className="access-key-list">
            {permanentTokens.length === 0 ? (
              <p>{t("profile.tokenEmpty")}</p>
            ) : (
              permanentTokens.map((token) => (
                <div className="access-key-row" key={token.id}>
                  <div>
                    <code>{token.id}</code>
                    <small>{new Date(token.created_at).toLocaleString()}</small>
                  </div>
                  <button
                    type="button"
                    className="button-text danger"
                    disabled={permanentTokenBusy}
                    onClick={() => void deletePermanentToken(token)}
                  >
                    {t("profile.tokenRevoke")}
                  </button>
                </div>
              ))
            )}
          </div>
        </article>
      )}

      <article className="mfa-card">
        <div className="mfa-card-heading">
          <div>
            <h3>{t("profile.mfaTitle")}</h3>
            <p>{t("profile.mfaDescription")}</p>
          </div>
          <span className={`mfa-badge ${profile?.mfa_enabled ? "enabled" : ""}`}>
            {loading
              ? t("profile.loading")
              : !profile
                ? t("profile.mfaUnknown")
                : profile.mfa_enabled
                  ? t("profile.mfaEnabled")
                  : t("profile.mfaDisabled")}
          </span>
        </div>

        {!loading && profile && !profile.mfa_enabled && !enrollment && (
          <div className="mfa-actions">
            <button type="button" disabled={busy} onClick={() => void startEnrollment()}>
              {busy ? t("profile.working") : t("profile.mfaStart")}
            </button>
            <span>
              {t(externalAccount ? `${externalNamespace}.mfaStartHint` : "profile.mfaStartHint")}
            </span>
          </div>
        )}

        {enrollment && !profile?.mfa_enabled && (
          <form className="mfa-form" onSubmit={(event) => void confirmEnrollment(event)}>
            <p>{t("profile.mfaSetupHint")}</p>
            <div className="mfa-secret-block">
              <span>{t("profile.mfaSecret")}</span>
              <code>{enrollment.secret}</code>
            </div>
            <details className="mfa-uri-details">
              <summary>{t("profile.mfaShowURI")}</summary>
              <code>{enrollment.provisioning_uri}</code>
            </details>
            <p className="mfa-expiry">
              {t("profile.mfaExpires", {
                time: new Date(enrollment.expires_at).toLocaleTimeString(),
              })}
            </p>
            {codeField(t("profile.mfaCode"))}
            <div className="mfa-actions">
              <button type="submit" disabled={busy || otp.length !== 6}>
                {busy ? t("profile.working") : t("profile.mfaEnable")}
              </button>
              <button
                type="button"
                className="button-secondary"
                disabled={busy}
                onClick={() => {
                  setEnrollment(null);
                  setOtp("");
                }}
              >
                {t("profile.cancel")}
              </button>
            </div>
          </form>
        )}

        {!loading && profile?.mfa_enabled && (
          <>
            <form className="mfa-form" onSubmit={(event) => void disableMFA(event)}>
              {!externalAccount && <p>{t("profile.mfaDisableHint")}</p>}
              {externalAccount ? (
                <p>{t(`${externalNamespace}.reauthHint`)}</p>
              ) : (
                <label className="mfa-field">
                  <span>{t("profile.password")}</span>
                  <input
                    type="password"
                    autoComplete="current-password"
                    required
                    value={password}
                    onChange={(event) => setPassword(event.target.value)}
                  />
                </label>
              )}
              {codeField(t("profile.mfaCode"))}
              <button
                type="submit"
                className="button-secondary"
                disabled={busy || otp.length !== 6 || (!externalAccount && password.length === 0)}
              >
                {busy ? t("profile.working") : t("profile.mfaDisable")}
              </button>
            </form>

            <section className="mfa-recovery-section" aria-labelledby="mfa-recovery-title">
              <div>
                <h4 id="mfa-recovery-title">{t("profile.recoveryTitle")}</h4>
                <p>{t("profile.recoveryDescription")}</p>
              </div>
              <form className="mfa-form" onSubmit={(event) => void regenerateRecoveryCodes(event)}>
                {externalAccount ? (
                  <p>{t(`${externalNamespace}.reauthHint`)}</p>
                ) : (
                  <label className="mfa-field">
                    <span>{t("profile.password")}</span>
                    <input
                      type="password"
                      autoComplete="current-password"
                      required
                      value={recoveryPassword}
                      onChange={(event) => setRecoveryPassword(event.target.value)}
                    />
                  </label>
                )}
                {recoveryCodeField()}
                <button
                  type="submit"
                  className="button-secondary"
                  disabled={
                    busy ||
                    recoveryOtp.length !== 6 ||
                    (!externalAccount && recoveryPassword.length === 0)
                  }
                >
                  {busy ? t("profile.working") : t("profile.recoveryGenerate")}
                </button>
              </form>
              {recoveryCodes.length > 0 && (
                <div className="mfa-recovery-codes" role="status">
                  <p>{t("profile.recoverySaveNow")}</p>
                  <ol>
                    {recoveryCodes.map((code) => (
                      <li key={code}>
                        <code>{code}</code>
                      </li>
                    ))}
                  </ol>
                  <button
                    type="button"
                    className="button-secondary"
                    onClick={() => setRecoveryCodes([])}
                  >
                    {t("profile.recoveryHide")}
                  </button>
                </div>
              )}
            </section>
          </>
        )}

        {errorKey && (
          <p className="mfa-feedback error" role="alert">
            {t(errorKey)}
          </p>
        )}
        {success && (
          <p className="mfa-feedback success" role="status">
            {t("profile.mfaSaved")}
          </p>
        )}
      </article>
      {!loading && profile && <PasskeysPanel user={profile} />}
    </section>
  );
}
