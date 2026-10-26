import { requestID as newRequestID } from "../utils/requestID";
import { useCallback, useEffect, useId, useRef, useState, type FormEvent } from "react";
import { useTranslation } from "react-i18next";
import { useAuth } from "../auth/AuthContext";

type Policy = {
  revision: number;
  mode: string;
  interval_hours: number;
  hour_utc: number;
  minute_utc: number;
  window_minutes: number;
  drain_timeout_seconds: number;
};
type State = {
  policy: Policy;
  phase: string;
  error?: string;
  last_attempt: string;
  last_success: string;
  next_attempt: string;
  candidate?: { version: string; archive_sha256: string };
  events: { at: string; action: string; actor: string; code?: string; version?: string }[];
};
const path = "/api/v1/settings/security/updates/installation/automatic";
const phases = new Set([
  "idle",
  "checking",
  "downloading",
  "staging",
  "ready",
  "failed",
  "no_update",
  "attempted",
]);
const failures = new Set([
  "network",
  "invalid_release",
  "integrity",
  "rate_limited",
  "interrupted",
  "canceled",
  "authorization",
  "attempt_limit",
]);
export default function AutomaticUpdates() {
  const { accessToken } = useAuth();
  const { t, i18n } = useTranslation();
  const id = useId();
  const [state, setState] = useState<State | null>(null);
  const [form, setForm] = useState<Policy | null>(null);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const editing = useRef(false);
  const pending = useRef<{ request_id: string; policy: Policy } | null>(null);
  const accept = useCallback((value: State) => {
    setState((old) => (old && old.policy.revision > value.policy.revision ? old : value));
    if (!editing.current) setForm(value.policy);
  }, []);
  const read = useCallback(
    async (signal?: AbortSignal) => {
      const r = await fetch(path, {
        signal,
        headers: accessToken ? { Authorization: `Bearer ${accessToken}` } : undefined,
      });
      if (!r.ok) throw new Error();
      const v = (await r.json()) as State;
      if (!signal?.aborted) {
        accept(v);
        setError((old) => (old === "unavailable" ? "" : old));
      }
    },
    [accessToken, accept],
  );
  const poll = !!state && state.policy.mode !== "off";
  useEffect(() => {
    const c = new AbortController();
    let loading = false;
    const refresh = async () => {
      if (loading) return;
      loading = true;
      try {
        await read(c.signal);
      } catch {
        if (!c.signal.aborted) setError("unavailable");
      } finally {
        loading = false;
      }
    };
    void refresh();
    const timer = poll ? window.setInterval(() => void refresh(), 5000) : undefined;
    return () => {
      c.abort();
      window.clearInterval(timer);
    };
  }, [read, poll]);
  const date = (v: string) =>
    !v || v.startsWith("0001-") ? t("updates.never") : new Date(v).toLocaleString(i18n.language);
  function edit(patch: Partial<Policy>) {
    if (!form) return;
    editing.current = true;
    pending.current = null;
    setForm({ ...form, ...patch });
  }
  async function save(e: FormEvent) {
    e.preventDefault();
    if (!form || !state) return;
    pending.current ||= {
      request_id: newRequestID(),
      policy: { ...form, revision: state.policy.revision },
    };
    setBusy(true);
    setError("");
    try {
      const r = await fetch(path, {
        method: "PUT",
        headers: {
          ...(accessToken ? { Authorization: `Bearer ${accessToken}` } : {}),
          "Content-Type": "application/json",
        },
        body: JSON.stringify(pending.current),
      });
      if (!r.ok) {
        if (r.status === 409 || r.status === 400) pending.current = null;
        setError(r.status === 409 ? "conflict" : "unavailable");
        await read();
        return;
      }
      editing.current = false;
      pending.current = null;
      accept((await r.json()) as State);
    } catch {
      setError("unavailable");
    } finally {
      setBusy(false);
    }
  }
  return (
    <div className="automatic-updates">
      <h5>{t("updates.automaticInstall.title")}</h5>
      <p className="settings-help">{t("updates.automaticInstall.description")}</p>
      {error && (
        <p role="alert" className="asset-error">
          {t(`updates.errors.${error}`)}
        </p>
      )}
      {!state && !error && <p role="status">{t("updates.loading")}</p>}
      {state && form && (
        <>
          <p role="status">
            {t(
              `updates.automaticInstall.${state.policy.mode === "off" ? "disabled" : "phases." + (phases.has(state.phase) ? state.phase : "failed")}`,
            )}
          </p>
          {state.error && (
            <p className="asset-error">
              {t(
                `updates.automaticInstall.failures.${failures.has(state.error) ? state.error : "unavailable"}`,
              )}
            </p>
          )}
          {state.candidate && (
            <p>
              {t("updates.automaticInstall.prepared", { version: state.candidate.version })}
              <br />
              <code>{state.candidate.archive_sha256}</code>
            </p>
          )}
          <dl>
            <dt>{t("updates.automaticInstall.lastAttempt")}</dt>
            <dd>{date(state.last_attempt)}</dd>
            <dt>{t("updates.automaticInstall.nextAttempt")}</dt>
            <dd>{state.policy.mode === "off" ? t("updates.never") : date(state.next_attempt)}</dd>
          </dl>
          <details>
            <summary>{t("updates.automaticInstall.configure")}</summary>
            <form onSubmit={(e) => void save(e)}>
              <label htmlFor={id + "-mode"}>{t("updates.automaticInstall.mode")}</label>
              <select
                id={id + "-mode"}
                value={form.mode}
                disabled={busy}
                onChange={(e) => edit({ mode: e.target.value })}
              >
                {["off", "prepare", "install"].map((mode) => (
                  <option key={mode} value={mode}>
                    {t(`updates.automaticInstall.modes.${mode}`)}
                  </option>
                ))}
              </select>
              <label htmlFor={id + "-interval"}>{t("updates.automaticInstall.interval")}</label>
              <input
                id={id + "-interval"}
                type="number"
                min={1}
                max={168}
                required
                value={form.interval_hours}
                disabled={busy}
                onChange={(e) => edit({ interval_hours: e.target.valueAsNumber })}
              />
              {form.mode === "install" && (
                <>
                  <label htmlFor={id + "-time"}>{t("updates.automaticInstall.window")}</label>
                  <input
                    id={id + "-time"}
                    type="time"
                    required
                    value={`${String(form.hour_utc).padStart(2, "0")}:${String(form.minute_utc).padStart(2, "0")}`}
                    disabled={busy}
                    onChange={(e) => {
                      const [hour, minute] = e.target.value.split(":").map(Number);
                      edit({ hour_utc: hour, minute_utc: minute });
                    }}
                  />
                  <label htmlFor={id + "-width"}>{t("updates.automaticInstall.width")}</label>
                  <input
                    id={id + "-width"}
                    type="number"
                    min={5}
                    max={180}
                    required
                    value={form.window_minutes}
                    disabled={busy}
                    onChange={(e) => edit({ window_minutes: e.target.valueAsNumber })}
                  />
                  <label htmlFor={id + "-drain"}>{t("updates.installation.timeout")}</label>
                  <input
                    id={id + "-drain"}
                    type="number"
                    min={5}
                    max={86400}
                    required
                    value={form.drain_timeout_seconds}
                    disabled={busy}
                    onChange={(e) => edit({ drain_timeout_seconds: e.target.valueAsNumber })}
                  />
                  <p className="settings-help">{t("updates.automaticInstall.windowHelp")}</p>
                </>
              )}
              <button type="submit" className="button-primary" disabled={busy}>
                {t("updates.automaticInstall.save")}
              </button>
            </form>
          </details>
          <button
            type="button"
            disabled={busy}
            onClick={() => void read().catch(() => setError("unavailable"))}
          >
            {t("updates.automaticInstall.refresh")}
          </button>
          {!!state.events.length && (
            <details>
              <summary>{t("updates.installation.history")}</summary>
              <ul>
                {state.events
                  .slice(-5)
                  .reverse()
                  .map((e, n) => (
                    <li key={`${e.at}-${n}`}>
                      {date(e.at)} ·{" "}
                      {t(
                        `updates.automaticInstall.events.${["policy", "check", "ready", "failed", "no_update", "attempted"].includes(e.action) ? e.action : "check"}`,
                      )}{" "}
                      · {e.actor}
                      {e.version ? ` · ${e.version}` : ""}
                    </li>
                  ))}
              </ul>
            </details>
          )}
        </>
      )}
    </div>
  );
}
