import { useCallback, useEffect, useState, type FormEvent } from "react";
import { useTranslation } from "react-i18next";
import { usePermissions } from "../auth/usePermissions";
import { selectedOrganization } from "../auth/organization";
import SessionShareActivity from "./SessionShareActivity";

type Invite = { id: string; mode: string; expires_at: string; allowed_users: string[] };
type Member = { id: string; actor: { id: string; name: string }; mode: string };
type State = {
  enabled: boolean;
  shares: Invite[];
  members: Member[];
  controller: string;
  usernames?: Record<string, string>;
};
type Props = { sessionID: string; accessToken: string; onClose: () => void };
export default function SessionSharePanel({ sessionID, accessToken, onClose }: Props) {
  const { t, i18n } = useTranslation();
  const { allows } = usePermissions();
  const [state, setState] = useState<State | null>(null),
    [users, setUsers] = useState(""),
    [minutes, setMinutes] = useState(10),
    [mode, setMode] = useState("read_only"),
    [error, setError] = useState(false),
    [busy, setBusy] = useState(false);
  const [created, setCreated] = useState<{ url: string; code: string } | null>(null);
  const call = useCallback(
    async (path: string, method = "GET", body?: unknown) => {
      const response = await fetch(path, {
        method,
        headers: {
          ...(accessToken ? { Authorization: `Bearer ${accessToken}` } : {}),
          ...(body ? { "Content-Type": "application/json" } : {}),
        },
        ...(body ? { body: JSON.stringify(body) } : {}),
      });
      if (!response.ok) throw Error("share request failed");
      return response;
    },
    [accessToken],
  );
  const refresh = useCallback(async () => {
    setState(
      (await (
        await call(`/api/v1/sessions/${encodeURIComponent(sessionID)}/shares`)
      ).json()) as State,
    );
  }, [call, sessionID]);
  useEffect(() => {
    let active = true;
    const load = async () => {
      try {
        const result = (await (
          await call(`/api/v1/sessions/${encodeURIComponent(sessionID)}/shares`)
        ).json()) as State;
        if (active) setState(result);
      } catch {
        if (active) setError(true);
      }
    };
    void load();
    const timer = window.setInterval(() => void load(), 2000);
    return () => {
      active = false;
      clearInterval(timer);
    };
  }, [call, sessionID]);
  async function action(path: string, method: string, body?: unknown) {
    setError(false);
    setBusy(true);
    try {
      await call(path, method, body);
      await refresh();
    } catch {
      setError(true);
    } finally {
      setBusy(false);
    }
  }
  async function create(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(false);
    setCreated(null);
    try {
      const result = (await (
        await call(`/api/v1/sessions/${encodeURIComponent(sessionID)}/shares`, "POST", {
          mode,
          minutes,
          users: users
            .split(",")
            .map((v) => v.trim())
            .filter(Boolean),
        })
      ).json()) as { id: string; code: string };
      setCreated({
        url: `${window.location.origin}/share/${encodeURIComponent(result.id)}?org=${encodeURIComponent(selectedOrganization())}`,
        code: result.code,
      });
      await refresh();
    } catch {
      setError(true);
    } finally {
      setBusy(false);
    }
  }
  return (
    <aside
      className="session-share-panel"
      aria-label={t("sharing.manage")}
      onKeyDown={(e) => {
        if (e.key === "Escape") {
          e.stopPropagation();
          onClose();
        }
      }}
    >
      <header>
        <h3>{t("sharing.manage")}</h3>
        <button type="button" className="button-secondary" onClick={onClose}>
          {t("sharing.hide")}
        </button>
      </header>
      <p className="settings-help">{t("sharing.hint")}</p>
      {error && (
        <p role="alert" className="asset-error">
          {t("sharing.error")}
        </p>
      )}
      {state && !state.enabled && <p>{t("sharing.disabled")}</p>}
      {state?.enabled && !allows("sessions.share") && <p>{t("sharing.noPermission")}</p>}
      {state?.enabled && allows("sessions.share") && (
        <form onSubmit={(e) => void create(e)} className="session-share-form">
          <label>
            {t("sharing.users")}
            <input
              required
              value={users}
              maxLength={2600}
              onChange={(e) => setUsers(e.target.value)}
            />
          </label>
          <label>
            {t("sharing.mode")}
            <select
              aria-label={t("sharing.mode")}
              value={mode}
              onChange={(e) => setMode(e.target.value)}
            >
              <option value="read_only">{t("sharing.readOnly")}</option>
              <option value="read_write">{t("sharing.readWrite")}</option>
            </select>
          </label>
          <label>
            {t("sharing.minutes")}
            <input
              type="number"
              required
              min={1}
              max={1440}
              value={minutes}
              onChange={(e) => setMinutes(Number(e.target.value))}
            />
          </label>
          <button className="button-primary" disabled={busy}>
            {t("sharing.create")}
          </button>
        </form>
      )}
      {created && (
        <div className="settings-notice" role="status">
          <p>{t("sharing.created")}</p>
          <label>
            {t("sharing.link")}
            <input readOnly value={created.url} />
          </label>
          <label>
            {t("sharing.code")}
            <input readOnly value={created.code} autoComplete="off" />
          </label>
          <button type="button" className="button-secondary" onClick={() => setCreated(null)}>
            {t("sharing.hideCode")}
          </button>
        </div>
      )}
      {state && (
        <>
          <p>
            {t("sharing.controller", {
              name:
                state.members.find((m) => m.id === state.controller)?.actor.name ||
                (state.controller ? t("sharing.departed") : t("sharing.owner")),
            })}
          </p>
          <button
            type="button"
            className="button-secondary"
            disabled={busy}
            onClick={() =>
              void action(
                `/api/v1/sessions/${encodeURIComponent(sessionID)}/share-control`,
                "POST",
                { member_id: "" },
              )
            }
          >
            {t("sharing.reclaim")}
          </button>
          {state.members.map((m) => (
            <div className="session-share-row" key={m.id}>
              <span>
                {m.actor.name} ·{" "}
                {t(m.mode === "read_write" ? "sharing.readWrite" : "sharing.readOnly")}
              </span>
              <button
                type="button"
                className="button-secondary"
                disabled={busy}
                onClick={() =>
                  void action(`/api/v1/session-share-members/${encodeURIComponent(m.id)}`, "DELETE")
                }
              >
                {t("sharing.kick")}
              </button>
            </div>
          ))}
          {state.shares.map((s) => (
            <div className="session-share-row" key={s.id}>
              <span>
                {s.allowed_users.map((id) => state.usernames?.[id] || id).join(", ")} ·{" "}
                {t(s.mode === "read_write" ? "sharing.readWrite" : "sharing.readOnly")} ·{" "}
                {new Date(s.expires_at).toLocaleString(i18n.language)}
              </span>
              <button
                type="button"
                className="button-secondary"
                disabled={busy}
                onClick={() =>
                  void action(`/api/v1/session-shares/${encodeURIComponent(s.id)}`, "DELETE")
                }
              >
                {t("sharing.revoke")}
              </button>
            </div>
          ))}
        </>
      )}
      <SessionShareActivity sessionID={sessionID} accessToken={accessToken} />
    </aside>
  );
}
