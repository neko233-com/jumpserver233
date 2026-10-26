import { requestID as newRequestID } from "../utils/requestID";
import { useCallback, useEffect, useRef, useState } from "react";
import { useTranslation } from "react-i18next";
import { useAuth } from "../auth/AuthContext";

type Status = {
  supported: boolean;
  instance: string;
  pid: number;
  revision: number;
  draining: boolean;
  ready: boolean;
  stopping: boolean;
  activity: Record<string, number>;
};
type Input = { instance: string; revision: number; request_id: string; draining: boolean };
const endpoint = "/api/v1/settings/security/maintenance";
const kinds = new Set([
  "ssh_routes",
  "http_requests",
  "asset_cycles",
  "credential_operations",
  "ssh_jobs",
  "replay_archive",
  "assistant",
  "probes",
  "plan_dispatch",
  "terminal_sessions",
  "desktop_sessions",
  "running_jobs",
  "database_queries",
]);
async function readStatus(accessToken: string | null, signal?: AbortSignal): Promise<Status> {
  const response = await fetch(endpoint, {
    signal,
    headers: accessToken ? { Authorization: `Bearer ${accessToken}` } : undefined,
  });
  if (!response.ok) throw new Error("unavailable");
  return response.json() as Promise<Status>;
}

export default function ServiceMaintenance({ onChanged }: { onChanged?: () => void }) {
  const { t } = useTranslation();
  const { accessToken } = useAuth();
  const [status, setStatus] = useState<Status | null>(null);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const pending = useRef<Input | null>(null);
  const accept = useCallback((value: Status) => {
    setStatus((current) =>
      current?.instance === value.instance && current.revision > value.revision ? current : value,
    );
  }, []);
  useEffect(() => {
    const controller = new AbortController();
    let loading = false;
    async function refresh() {
      if (loading) return;
      loading = true;
      try {
        const value = await readStatus(accessToken, controller.signal);
        if (!controller.signal.aborted) accept(value);
      } catch {
        if (!controller.signal.aborted) setError("unavailable");
      } finally {
        loading = false;
      }
    }
    void refresh();
    const timer = status?.draining ? window.setInterval(() => void refresh(), 1500) : undefined;
    return () => {
      controller.abort();
      window.clearInterval(timer);
    };
  }, [accessToken, status?.draining, accept]);
  async function change(draining: boolean) {
    if (!status) return;
    setBusy(true);
    setError("");
    if (!pending.current || pending.current.draining !== draining)
      pending.current = {
        instance: status.instance,
        revision: status.revision,
        request_id: newRequestID(),
        draining,
      };
    try {
      const response = await fetch(endpoint, {
        method: "PUT",
        headers: {
          ...(accessToken ? { Authorization: `Bearer ${accessToken}` } : {}),
          "Content-Type": "application/json",
        },
        body: JSON.stringify(pending.current),
      });
      if (!response.ok) {
        const result = (await response.json().catch(() => ({}))) as { error_code?: string };
        if (response.status === 409 || response.status === 400) pending.current = null;
        const fresh = await readStatus(accessToken);
        accept(fresh);
        setError(result.error_code === "conflict" ? "conflict" : "unavailable");
      } else {
        accept((await response.json()) as Status);
        pending.current = null;
        onChanged?.();
      }
    } catch {
      setError("unavailable");
    } finally {
      setBusy(false);
    }
  }
  return (
    <div className="service-maintenance">
      <h4>{t("updates.maintenance.title")}</h4>
      <p className="settings-help">{t("updates.maintenance.description")}</p>
      {error && (
        <p className="asset-error" role="alert">
          {t(`updates.maintenance.${error}`)}
        </p>
      )}
      {!status && !error && <p role="status">{t("updates.loading")}</p>}
      {status && (
        <>
          <p role="status">
            {t(
              `updates.maintenance.${!status.supported ? "unsupported" : status.stopping ? "stopping" : status.ready ? "ready" : status.draining ? "draining" : "open"}`,
            )}
          </p>
          {status.draining && (
            <ul>
              {Object.entries(status.activity).map(([kind, count]) => (
                <li key={kind}>
                  {t(`updates.maintenance.activity.${kinds.has(kind) ? kind : "other"}`)}: {count}
                </li>
              ))}
            </ul>
          )}
          <div className="maintenance-actions">
            <button
              type="button"
              className="button-primary"
              disabled={busy || !status.supported || status.stopping}
              onClick={() => void change(!status.draining)}
            >
              {t(`updates.maintenance.${status.draining ? "cancel" : "start"}`)}
            </button>
            <button
              type="button"
              disabled={busy}
              onClick={() => {
                void readStatus(accessToken)
                  .then((value) => {
                    accept(value);
                    setError("");
                  })
                  .catch(() => setError("unavailable"));
              }}
            >
              {t("updates.maintenance.refresh")}
            </button>
          </div>
          <details>
            <summary>{t("updates.maintenance.instance")}</summary>
            <code>{status.instance}</code>
            <p>
              {t("updates.maintenance.revision", { revision: status.revision, pid: status.pid })}
            </p>
          </details>
        </>
      )}
    </div>
  );
}
