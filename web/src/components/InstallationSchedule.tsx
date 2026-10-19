import { useCallback, useEffect, useRef, useState, type FormEvent } from "react";
import { useTranslation } from "react-i18next";
import { useAuth } from "../auth/AuthContext";

type Selection = { version: string; archive_sha256: string; commit: string };
type Plan = {
  id: string;
  phase: string;
  error?: string;
  target: Selection;
  input: { not_before: string };
  actor: string;
};
type Status = {
  configured: boolean;
  revision: number;
  installation_revision: number;
  supervisor_seen_at: string;
  plan?: Plan | null;
  events?: { at: string; phase: string; actor: string }[];
};
const endpoint = "/api/v1/settings/security/updates/installation";
const active = new Set(["scheduled", "draining", "stopping", "installing", "awaiting_start"]);
const phases = new Set([...active, "succeeded", "failed", "cancelled"]);
const codes = new Set([
  "checkpoint_passphrase_unavailable",
  "installation_changed",
  "candidate_changed",
  "maintenance_unavailable",
  "drain_start_failed",
  "maintenance_changed",
  "drain_timeout",
  "reopen_failed",
  "service_exited",
  "stop_unconfirmed",
  "service_stop_failed",
  "service_stop_timeout",
  "installation_failed",
  "supervisor_interrupted",
  "activation_rolled_back",
  "activation_failed",
  "activation_committed",
]);
export default function InstallationSchedule() {
  const { t, i18n } = useTranslation();
  const { accessToken } = useAuth();
  const [status, setStatus] = useState<Status | null>(null);
  const [candidates, setCandidates] = useState<Selection[]>([]);
  const [sha, setSHA] = useState("");
  const [when, setWhen] = useState(() => {
    const d = new Date(Date.now() + 300_000);
    return new Date(d.getTime() - d.getTimezoneOffset() * 60_000).toISOString().slice(0, 16);
  });
  const [timeout, setTimeoutSeconds] = useState(60);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const pending = useRef<{ cancel: boolean; body: object } | null>(null);
  const read = useCallback(
    async (signal?: AbortSignal) => {
      const r = await fetch(endpoint, {
        signal,
        headers: accessToken ? { Authorization: `Bearer ${accessToken}` } : undefined,
      });
      if (!r.ok) throw new Error("unavailable");
      const value = (await r.json()) as Status;
      if (!signal?.aborted)
        setStatus((old) => (old && old.revision > value.revision ? old : value));
    },
    [accessToken],
  );
  const running = !!status?.plan && active.has(status.plan.phase);
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
    const timer = running ? window.setInterval(() => void refresh(), 3000) : undefined;
    return () => {
      c.abort();
      window.clearInterval(timer);
    };
  }, [read, running]);
  const date = (value: string) =>
    !value || value.startsWith("0001-")
      ? t("updates.never")
      : new Date(value).toLocaleString(i18n.language);
  async function change(cancel: boolean) {
    if (!status) return;
    if (!pending.current || pending.current.cancel !== cancel)
      pending.current = {
        cancel,
        body: cancel
          ? { revision: status.revision, request_id: crypto.randomUUID(), plan_id: status.plan?.id }
          : {
              revision: status.revision,
              request_id: crypto.randomUUID(),
              installation_revision: status.installation_revision,
              archive_sha256: sha,
              not_before: new Date(when).toISOString(),
              drain_timeout_seconds: timeout,
            },
      };
    setBusy(true);
    setError("");
    try {
      const response = await fetch(endpoint + (cancel ? "/cancel" : ""), {
        method: "POST",
        headers: {
          ...(accessToken ? { Authorization: `Bearer ${accessToken}` } : {}),
          "Content-Type": "application/json",
        },
        body: JSON.stringify(pending.current.body),
      });
      if (!response.ok) {
        if (response.status === 409 || response.status === 400) pending.current = null;
        setError(response.status === 409 ? "conflict" : "unavailable");
        await read();
        return;
      }
      setStatus((await response.json()) as Status);
      pending.current = null;
    } catch {
      setError("unavailable");
    } finally {
      setBusy(false);
    }
  }
  async function refreshCandidates() {
    setBusy(true);
    setError("");
    try {
      const r = await fetch(endpoint + "/candidates", {
        headers: accessToken ? { Authorization: `Bearer ${accessToken}` } : undefined,
      });
      if (!r.ok) throw new Error();
      const values = (await r.json()) as Selection[];
      setCandidates(values);
      setSHA(values[0]?.archive_sha256 || "");
      await read();
    } catch {
      setError("unavailable");
    } finally {
      setBusy(false);
    }
  }
  function submit(e: FormEvent) {
    e.preventDefault();
    void change(false);
  }
  const phase = status?.plan?.phase || "";
  return (
    <div className="installation-schedule">
      <h4>{t("updates.installation.title")}</h4>
      <p className="settings-help">{t("updates.installation.description")}</p>
      {error && (
        <p role="alert" className="asset-error">
          {t(`updates.errors.${error}`)}
        </p>
      )}
      {!status && !error && <p role="status">{t("updates.loading")}</p>}
      {status && !status.configured && (
        <p role="status">{t("updates.installation.unconfigured")}</p>
      )}
      {status?.configured && (
        <>
          <p className="settings-help">
            {t("updates.installation.supervisor", { at: date(status.supervisor_seen_at) })}
          </p>
          {status.plan && (
            <div role="status">
              <strong>
                {t(`updates.installation.phases.${phases.has(phase) ? phase : "failed"}`)}
              </strong>
              <p>
                {status.plan.target.version} · {date(status.plan.input.not_before)}
              </p>
              <code>{status.plan.target.archive_sha256}</code>
              {status.plan.error && (
                <p className="asset-error">
                  {t(
                    `updates.installation.failures.${codes.has(status.plan.error) ? status.plan.error : "unknown"}`,
                  )}
                </p>
              )}
            </div>
          )}
          <div className="maintenance-actions">
            {(phase === "scheduled" || phase === "draining") && (
              <button type="button" disabled={busy} onClick={() => void change(true)}>
                {t("updates.installation.cancel")}
              </button>
            )}
            <button
              type="button"
              disabled={busy}
              onClick={() =>
                void read()
                  .then(() => setError(""))
                  .catch(() => setError("unavailable"))
              }
            >
              {t("updates.installation.refresh")}
            </button>
          </div>
          {!running && (
            <details>
              <summary>{t("updates.installation.prepare")}</summary>
              <p className="settings-help">{t("updates.installation.staging")}</p>
              <button type="button" disabled={busy} onClick={() => void refreshCandidates()}>
                {t("updates.installation.candidates")}
              </button>
              <form onSubmit={submit}>
                <label>
                  {t("updates.installation.target")}
                  <select
                    required
                    value={sha}
                    disabled={busy}
                    onChange={(e) => {
                      setSHA(e.target.value);
                      pending.current = null;
                    }}
                  >
                    <option value="">{t("updates.installation.choose")}</option>
                    {candidates.map((c) => (
                      <option key={c.archive_sha256} value={c.archive_sha256}>
                        {c.version} · {c.archive_sha256.slice(0, 12)}
                      </option>
                    ))}
                  </select>
                </label>
                <label>
                  {t("updates.installation.at")}
                  <input
                    type="datetime-local"
                    required
                    value={when}
                    disabled={busy}
                    onChange={(e) => {
                      setWhen(e.target.value);
                      pending.current = null;
                    }}
                  />
                </label>
                <label>
                  {t("updates.installation.timeout")}
                  <input
                    type="number"
                    min={5}
                    max={86400}
                    required
                    value={timeout}
                    disabled={busy}
                    onChange={(e) => {
                      setTimeoutSeconds(e.target.valueAsNumber);
                      pending.current = null;
                    }}
                  />
                </label>
                <button type="submit" className="button-primary" disabled={busy || !sha}>
                  {t("updates.installation.schedule")}
                </button>
              </form>
            </details>
          )}
          {!!status.events?.length && (
            <details>
              <summary>{t("updates.installation.history")}</summary>
              <ul>
                {status.events
                  .slice(-5)
                  .reverse()
                  .map((e, i) => (
                    <li key={`${e.at}-${i}`}>
                      {date(e.at)} ·{" "}
                      {t(`updates.installation.phases.${phases.has(e.phase) ? e.phase : "failed"}`)}{" "}
                      · {e.actor}
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
