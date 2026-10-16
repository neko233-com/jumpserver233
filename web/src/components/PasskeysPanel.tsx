import { useCallback, useEffect, useRef, useState, type FormEvent } from "react";
import { useNavigate } from "react-router-dom";
import { useTranslation } from "react-i18next";
import { useAuth } from "../auth/AuthContext";
import { createPasskey, passkeysSupported, type PasskeyCreationOptions } from "../auth/passkeys";
type Key = {
  id: string;
  name: string;
  created_at: string;
  last_used_at?: string;
  rp_id: string;
  backed_up: boolean;
  disabled: boolean;
};
type Settings = { enabled: boolean; available: boolean; rp_id: string };
export default function PasskeysPanel({
  user,
}: {
  user: { source?: string; mfa_enabled: boolean };
}) {
  const { t, i18n } = useTranslation();
  const { accessToken, setAccessToken } = useAuth();
  const navigate = useNavigate();
  const [keys, setKeys] = useState<Key[]>([]);
  const [settings, setSettings] = useState<Settings | null>(null);
  const [name, setName] = useState("");
  const [password, setPassword] = useState("");
  const [otp, setOtp] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState(false);
  const [message, setMessage] = useState("");
  const [editing, setEditing] = useState("");
  const [editName, setEditName] = useState("");
  const operation = useRef<AbortController | null>(null);
  const request = useCallback(
    (path: string, init?: RequestInit) => {
      const headers = new Headers(init?.headers);
      if (accessToken) headers.set("Authorization", `Bearer ${accessToken}`);
      if (init?.body) headers.set("Content-Type", "application/json");
      return fetch("/api/v1/users/me/passkeys" + path, { ...init, headers });
    },
    [accessToken],
  );
  const load = useCallback(
    async (signal?: AbortSignal) => {
      try {
        const r = await request("", { signal });
        if (r.status === 401) {
          await r.text();
          setAccessToken("");
          navigate("/login", { replace: true });
          return;
        }
        if (!r.ok) throw new Error("Passkeys unavailable");
        const data = (await r.json()) as { settings: Settings; credentials: Key[] };
        if (!signal?.aborted) {
          setKeys(data.credentials);
          setSettings(data.settings);
          setError(false);
        }
      } catch {
        if (!signal?.aborted) setError(true);
      }
    },
    [request, navigate, setAccessToken],
  );
  useEffect(() => {
    const c = new AbortController();
    queueMicrotask(() => {
      if (!c.signal.aborted) void load(c.signal);
    });
    return () => {
      c.abort();
      operation.current?.abort();
    };
  }, [load]);
  async function register(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(false);
    setMessage("");
    const controller = new AbortController();
    operation.current = controller;
    try {
      const r = await request("/registration/start", {
        method: "POST",
        body: JSON.stringify({ name, password, otp }),
        signal: controller.signal,
      });
      setPassword("");
      setOtp("");
      if (!r.ok) throw new Error("Registration rejected");
      const credential = await createPasskey(
        (await r.json()) as PasskeyCreationOptions,
        controller.signal,
      );
      const done = await request("/registration/finish", {
        method: "POST",
        body: JSON.stringify({ credential }),
        signal: controller.signal,
      });
      if (!done.ok) throw new Error("Registration rejected");
      await done.json();
      setName("");
      await load();
      setMessage("registered");
    } catch {
      if (!controller.signal.aborted) setError(true);
      await request("/registration", { method: "DELETE" }).catch(() => undefined);
    } finally {
      setPassword("");
      setOtp("");
      operation.current = null;
      setBusy(false);
    }
  }
  async function remove(key: Key) {
    if (!window.confirm(t("passkey.removeConfirm", { name: key.name }))) return;
    setBusy(true);
    setMessage("");
    try {
      const r = await request("/" + encodeURIComponent(key.id), {
        method: "DELETE",
        body: JSON.stringify({ password, otp }),
      });
      if (!r.ok) throw new Error("Removal rejected");
      await load();
      setMessage("removed");
    } catch {
      setError(true);
    } finally {
      setPassword("");
      setOtp("");
      setBusy(false);
    }
  }
  async function rename(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    try {
      const r = await request("/" + encodeURIComponent(editing), {
        method: "PATCH",
        body: JSON.stringify({ name: editName }),
      });
      if (!r.ok) throw new Error("Rename rejected");
      await r.json();
      setEditing("");
      await load();
      setMessage("renamed");
    } catch {
      setError(true);
    } finally {
      setBusy(false);
    }
  }
  const supported = passkeysSupported();
  return (
    <section className="profile-section passkeys-panel">
      <h2>{t("passkey.keysTitle")}</h2>
      <p>{t("passkey.keysHint")}</p>
      {error && (
        <p role="alert" className="login-error">
          {t("passkey.manageError")}
        </p>
      )}
      {message && <p role="status">{t(`passkey.${message}`)}</p>}
      {!supported && <p>{t("passkey.unsupported")}</p>}
      {settings && !settings.available && <p>{t("passkey.unavailable")}</p>}
      <div className="jobs-table-scroll">
        <table className="jobs-table">
          <thead>
            <tr>
              <th>{t("passkey.name")}</th>
              <th>{t("passkey.lastUsed")}</th>
              <th>{t("passkey.state")}</th>
              <th>{t("passkey.actions")}</th>
            </tr>
          </thead>
          <tbody>
            {keys.map((key) => (
              <tr key={key.id}>
                <td>
                  {key.name}
                  <small>{key.rp_id}</small>
                </td>
                <td>
                  {key.last_used_at
                    ? new Date(key.last_used_at).toLocaleString(i18n.language)
                    : t("passkey.never")}
                </td>
                <td>
                  {t(
                    key.disabled
                      ? "passkey.keyDisabled"
                      : key.backed_up
                        ? "passkey.backedUp"
                        : "passkey.active",
                  )}
                </td>
                <td>
                  <button
                    type="button"
                    disabled={busy}
                    onClick={() => {
                      setEditing(key.id);
                      setEditName(key.name);
                    }}
                  >
                    {t("passkey.rename")}
                  </button>
                  <button
                    type="button"
                    disabled={busy}
                    onClick={() => {
                      void remove(key);
                    }}
                  >
                    {t("passkey.remove")}
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      {keys.length === 0 && <p>{t("passkey.empty")}</p>}
      {editing && (
        <form
          className="rbac-form"
          onSubmit={(e) => {
            void rename(e);
          }}
        >
          <label>
            {t("passkey.newName")}
            <input
              required
              maxLength={120}
              value={editName}
              onChange={(e) => setEditName(e.target.value)}
            />
          </label>
          <button disabled={busy}>{t("passkey.saveName")}</button>
          <button type="button" onClick={() => setEditing("")}>
            {t("passkey.cancel")}
          </button>
        </form>
      )}
      <form
        className="rbac-form"
        onSubmit={(e) => {
          void register(e);
        }}
      >
        <h3>{t("passkey.manageProof")}</h3>
        <p>{t(user.source ? "passkey.externalProof" : "passkey.localProof")}</p>
        {!user.source && (
          <label>
            {t("passkey.password")}
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
            {t("passkey.otp")}
            <input
              autoComplete="one-time-code"
              maxLength={128}
              value={otp}
              onChange={(e) => setOtp(e.target.value)}
            />
          </label>
        )}
        <p>{t("passkey.removeProofHint")}</p>
        <label>
          {t("passkey.name")}
          <input required maxLength={120} value={name} onChange={(e) => setName(e.target.value)} />
        </label>
        <button disabled={busy || !supported || !settings?.available}>
          {t("passkey.register")}
        </button>
        {busy && (
          <button type="button" onClick={() => operation.current?.abort()}>
            {t("passkey.cancel")}
          </button>
        )}
      </form>
    </section>
  );
}
