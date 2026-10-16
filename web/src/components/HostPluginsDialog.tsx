import { useCallback, useEffect, useRef, useState } from "react";
import { useTranslation } from "react-i18next";
import { usePermissions } from "../auth/usePermissions";
import "./host-plugins.css";
import AgentEvents from "./AgentEvents";

type Definition = {
  id: string;
  version: string;
  source: string;
  name_key: string;
  description_key: string;
  actions: string[];
};
type Job = {
  id: string;
  state: string;
  stdout: string;
  error_code?: string;
  command: string;
  plugin?: { plugin: string; action: string };
};
type Result = {
  version?: string;
  latest_version?: string;
  upgrade_available?: boolean;
  transition_pending?: boolean;
  protection_mode?: string;
  recovery_state?: string;
  systemd_state?: string;
  supervisor?: string;
  recovery_version?: string;
  active_bans?: number;
  protection?: Protection;
  state: string;
  installed: boolean;
  running: boolean;
  platform?: string;
  managed_path?: string;
  existing_path?: string;
  output?: string;
  detail?: string;
  dry_run: boolean;
  autostart: boolean;
  autostart_state?: string;
};
type Protection = {
  mode: "audit" | "enforce";
  ignore_ips: string[];
  ssh_ports: number[];
  max_attempts: number;
  find_seconds: number;
  ban_seconds: number;
  success_grace_seconds: number;
  interval_seconds: number;
};
const active = (j: Job | null) => j && ["running", "pending_review"].includes(j.state);
const inspect = new Set([
  "systemd_status",
  "events",
  "detect",
  "status",
  "doctor",
  "scan",
  "keepalive_preview",
  "metrics",
  "protection_status",
]);
const defaultProtection: Protection = {
  mode: "audit",
  ignore_ips: [],
  ssh_ports: [],
  max_attempts: 5,
  find_seconds: 600,
  ban_seconds: 3600,
  success_grace_seconds: 600,
  interval_seconds: 10,
};

export default function HostPluginsDialog({
  assetId,
  assetName,
  accessToken,
  onClose,
}: {
  assetId: string;
  assetName: string;
  accessToken: string;
  onClose: () => void;
}) {
  const { t } = useTranslation();
  const { allows } = usePermissions();
  const [catalog, setCatalog] = useState<Definition[]>([]);
  const [job, setJob] = useState<Job | null>(null);
  const [results, setResults] = useState<Record<string, Result>>({});
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const [review, setReview] = useState("");
  const [mode, setMode] = useState<"audit" | "enforce">("audit");
  const [ignoreIPs, setIgnoreIPs] = useState("");
  const [ports, setPorts] = useState("");
  const [attempts, setAttempts] = useState(5);
  const [policyBase, setPolicyBase] = useState<Protection>(defaultProtection);
  const pending = useRef<{
    plugin: string;
    action: string;
    request_id: string;
    protection?: Protection;
  } | null>(null);
  const controller = useRef<HTMLDivElement>(null);
  const alive = useRef(true);
  const request = useCallback(
    (url: string, init?: RequestInit) => {
      const headers = new Headers(init?.headers);
      if (accessToken) headers.set("Authorization", `Bearer ${accessToken}`);
      return fetch(url, { ...init, headers });
    },
    [accessToken],
  );
  const accept = useCallback((j: Job) => {
    setJob(j);
    if (j.stdout && j.plugin) {
      try {
        const value = JSON.parse(j.stdout) as Result;
        setResults((old) => ({ ...old, [j.plugin!.plugin]: value }));
        if (
          j.plugin.plugin === "banhack233" &&
          value.installed &&
          ["audit", "enforce"].includes(value.protection_mode || "")
        ) {
          const policy = value.protection ?? defaultProtection;
          setPolicyBase(policy);
          setMode(policy.mode);
          setIgnoreIPs(policy.ignore_ips.join(", "));
          setPorts(policy.ssh_ports.join(", "));
          setAttempts(policy.max_attempts);
        }
      } catch {
        setError("hostPlugins.failed");
      }
    }
  }, []);
  useEffect(() => {
    alive.current = true;
    const abort = new AbortController();
    const previous = document.activeElement as HTMLElement | null;
    controller.current?.focus();
    void request("/api/v1/host-plugins", { signal: abort.signal })
      .then(async (r) => {
        if (!r.ok) throw new Error();
        const data = (await r.json()) as Definition[];
        if (alive.current) setCatalog(data);
      })
      .catch(() => {
        if (!abort.signal.aborted) setError("hostPlugins.failed");
      });
    return () => {
      alive.current = false;
      abort.abort();
      previous?.focus();
    };
  }, [request]);
  const pendingJobID = active(job) ? job!.id : "";
  useEffect(() => {
    if (!pendingJobID) return;
    const abort = new AbortController();
    let timer: ReturnType<typeof setTimeout>;
    const poll = async () => {
      try {
        const r = await request(`/api/v1/ops/jobs/${pendingJobID}`, { signal: abort.signal });
        if (!r.ok) throw new Error();
        const next = (await r.json()) as Job;
        if (!abort.signal.aborted) accept(next);
      } catch {
        if (!abort.signal.aborted) setError("hostPlugins.pollFailed");
      }
      if (!abort.signal.aborted)
        timer = setTimeout(() => {
          void poll();
        }, 1000);
    };
    timer = setTimeout(() => {
      void poll();
    }, 500);
    return () => {
      abort.abort();
      clearTimeout(timer);
    };
  }, [pendingJobID, request, accept]);
  async function submit(plugin: string, action: string, resume = false, protection?: Protection) {
    const plan =
      resume && pending.current
        ? pending.current
        : {
            plugin,
            action,
            request_id: crypto.randomUUID(),
            ...(protection ? { protection } : {}),
          };
    pending.current = plan;
    setBusy(true);
    setError("");
    try {
      const r = await request(`/api/v1/assets/${assetId}/host-plugins/${plan.plugin}/jobs`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          action: plan.action,
          request_id: plan.request_id,
          timeout_seconds: 180,
          ...(plan.protection ? { protection: plan.protection } : {}),
          ...(resume ? { review_id: review } : {}),
        }),
      });
      const data = await r.json();
      if (!alive.current) return;
      if (r.status === 202) {
        setReview(data.review_id as string);
        return;
      }
      if (!r.ok) {
        setError(r.status >= 500 ? "hostPlugins.uncertain" : "hostPlugins.failed");
        return;
      }
      setReview("");
      accept(data as Job);
    } catch {
      if (alive.current) setError("hostPlugins.uncertain");
    } finally {
      if (alive.current) setBusy(false);
    }
  }
  async function cancel() {
    if (!job) return;
    try {
      const r = await request(`/api/v1/ops/jobs/${job.id}`, { method: "DELETE" });
      if (!r.ok) throw new Error();
    } catch {
      setError("hostPlugins.failed");
    }
  }
  return (
    <div className="asset-modal-backdrop">
      <div
        className="asset-modal host-plugins-dialog"
        role="dialog"
        aria-modal="true"
        aria-labelledby="host-plugins-title"
        ref={controller}
        tabIndex={-1}
        onKeyDown={(event) => {
          if (event.key === "Escape") onClose();
          if (event.key === "Tab") {
            const items = Array.from(
              controller.current?.querySelectorAll<HTMLElement>(
                "button:not(:disabled),a[href],summary,input:not(:disabled),select:not(:disabled),textarea:not(:disabled)",
              ) ?? [],
            ).filter((element) => {
              if (!element.getClientRects().length) return false;
              for (let parent = element.parentElement; parent; parent = parent.parentElement) {
                if (
                  parent.tagName === "DETAILS" &&
                  !parent.hasAttribute("open") &&
                  !(element.tagName === "SUMMARY" && element.parentElement === parent)
                )
                  return false;
              }
              return true;
            });
            if (!items?.length) return;
            const first = items[0],
              last = items[items.length - 1];
            if (
              event.shiftKey &&
              (document.activeElement === first || document.activeElement === controller.current)
            ) {
              event.preventDefault();
              last.focus();
            } else if (!event.shiftKey && document.activeElement === last) {
              event.preventDefault();
              first.focus();
            }
          }
        }}
      >
        <header>
          <div>
            <h2 id="host-plugins-title">{t("hostPlugins.title")}</h2>
            <p>{assetName}</p>
          </div>
          <button type="button" className="button-text" onClick={onClose}>
            {t("hostPlugins.close")}
          </button>
        </header>
        <p className="host-plugins-hint">{t("hostPlugins.hint")}</p>
        {error && <p role="alert">{t(error)}</p>}
        {review && (
          <div role="status">
            <p>{t("hostPlugins.review", { id: review })}</p>
            <button
              type="button"
              className="button-secondary"
              disabled={busy}
              onClick={() => {
                if (pending.current)
                  void submit(pending.current.plugin, pending.current.action, true);
              }}
            >
              {t("hostPlugins.resume")}
            </button>
          </div>
        )}
        <div className="host-plugin-cards">
          {catalog.map((d) => {
            const result = results[d.id];
            return (
              <section key={d.id} className="host-plugin-card" aria-label={t(d.name_key)}>
                <header>
                  <h3>{t(d.name_key)}</h3>
                  <a href={d.source} target="_blank" rel="noreferrer">
                    v{d.version}
                  </a>
                </header>
                <p>{t(d.description_key)}</p>
                {result && (
                  <div className="host-plugin-state" aria-live="polite">
                    <strong>
                      {t(`hostPlugins.states.${result.state}`, { defaultValue: result.state })}
                    </strong>
                    {result.platform && <span>{result.platform}</span>}
                    {result.version && (
                      <span>{t("hostPlugins.installedVersion", { version: result.version })}</span>
                    )}
                    {result.upgrade_available && (
                      <span>
                        {t("hostPlugins.upgradeAvailable", { version: result.latest_version })}
                      </span>
                    )}
                    {result.protection_mode && (
                      <span>{t(`hostPlugins.protectionModes.${result.protection_mode}`)}</span>
                    )}
                    {result.dry_run && <span>{t("hostPlugins.dryRun")}</span>}
                    {result.autostart_state && (
                      <span>{t(`hostPlugins.autostart.${result.autostart_state}`)}</span>
                    )}
                    {result.systemd_state && (
                      <span>{t(`hostPlugins.systemd.${result.systemd_state}`)}</span>
                    )}
                    {result.recovery_state && (
                      <span>{t(`hostPlugins.recovery.${result.recovery_state}`)}</span>
                    )}
                    {["ready", "required", "restored"].includes(result.recovery_state || "") && (
                      <span>{t("hostPlugins.activeBans", { count: result.active_bans ?? 0 })}</span>
                    )}
                    {result.detail && (
                      <p role="alert">
                        {t(`hostPlugins.errors.${result.detail}`, {
                          defaultValue: t("hostPlugins.failed"),
                        })}
                      </p>
                    )}
                  </div>
                )}
                <div className="host-plugin-actions">
                  {d.actions
                    .filter((a) => ["detect", "install", "status", "start", "stop"].includes(a))
                    .map((action) => (
                      <button
                        key={action}
                        type="button"
                        className={
                          action === "install"
                            ? "button-primary button-small"
                            : "button-secondary button-small"
                        }
                        disabled={
                          busy ||
                          Boolean(active(job)) ||
                          Boolean(review) ||
                          (!inspect.has(action) && !allows("plugins.manage"))
                        }
                        onClick={() => {
                          void submit(d.id, action);
                        }}
                      >
                        {t(`hostPlugins.actions.${action}`)}
                      </button>
                    ))}
                </div>
                <details>
                  <summary>{t("hostPlugins.advanced")}</summary>
                  <p>{t("hostPlugins.lifecycle")}</p>
                  {result?.managed_path && <code>{result.managed_path}</code>}
                  {result?.existing_path && (
                    <p>{t("hostPlugins.existing", { path: result.existing_path })}</p>
                  )}
                  <div className="host-plugin-actions">
                    {d.actions
                      .filter(
                        (a) =>
                          ![
                            "detect",
                            "install",
                            "status",
                            "start",
                            "stop",
                            "protection_apply",
                            "events_collect",
                            "systemd_status",
                            "systemd_enable",
                            "systemd_disable",
                          ].includes(a),
                      )
                      .map((action) => (
                        <button
                          key={action}
                          type="button"
                          className="button-secondary button-small"
                          disabled={
                            busy ||
                            Boolean(active(job)) ||
                            Boolean(review) ||
                            (action === "protection_rollback"
                              ? !allows("plugins.protect")
                              : !inspect.has(action) && !allows("plugins.manage"))
                          }
                          onClick={() => {
                            void submit(d.id, action);
                          }}
                        >
                          {t(`hostPlugins.actions.${action}`)}
                        </button>
                      ))}
                  </div>
                  <details>
                    <summary>{t("hostPlugins.systemdTitle")}</summary>
                    <p>{t("hostPlugins.systemdHint")}</p>
                    <div className="host-plugin-actions">
                      {["systemd_status", "systemd_enable", "systemd_disable"].map((action) => (
                        <button
                          key={action}
                          type="button"
                          className="button-secondary button-small"
                          disabled={
                            busy ||
                            Boolean(active(job)) ||
                            Boolean(review) ||
                            (action !== "systemd_status" && !allows("plugins.manage"))
                          }
                          onClick={() => void submit(d.id, action)}
                        >
                          {t(`hostPlugins.actions.${action}`)}
                        </button>
                      ))}
                    </div>
                  </details>
                  {d.id === "banhack233" &&
                    result?.installed &&
                    ["audit", "enforce"].includes(result.protection_mode || "") &&
                    allows("plugins.protect") && (
                      <form
                        className="host-protection-form"
                        onSubmit={(event) => {
                          event.preventDefault();
                          const parsedPorts = ports
                            .split(/[\s,]+/)
                            .filter(Boolean)
                            .map(Number);
                          if (
                            parsedPorts.some((p) => !Number.isInteger(p) || p < 1 || p > 65535) ||
                            !Number.isInteger(attempts) ||
                            attempts < 1 ||
                            attempts > 10000
                          ) {
                            setError("hostPlugins.invalidPolicy");
                            return;
                          }
                          void submit(d.id, "protection_apply", false, {
                            ...policyBase,
                            mode,
                            ignore_ips: ignoreIPs.split(/[\s,]+/).filter(Boolean),
                            ssh_ports: parsedPorts,
                            max_attempts: attempts,
                          });
                        }}
                      >
                        <h4>{t("hostPlugins.protectionTitle")}</h4>
                        <p>{t("hostPlugins.protectionHint")}</p>
                        <p>
                          {t("hostPlugins.policyTiming", {
                            find: policyBase.find_seconds,
                            ban: policyBase.ban_seconds,
                            grace: policyBase.success_grace_seconds,
                            interval: policyBase.interval_seconds,
                          })}
                        </p>
                        <label>
                          {t("hostPlugins.policyMode")}
                          <select
                            aria-label={t("hostPlugins.policyMode")}
                            value={mode}
                            onChange={(e) => setMode(e.target.value as "audit" | "enforce")}
                          >
                            <option value="audit">{t("hostPlugins.protectionModes.audit")}</option>
                            <option value="enforce">
                              {t("hostPlugins.protectionModes.enforce")}
                            </option>
                          </select>
                        </label>
                        <label>
                          {t("hostPlugins.ignoreIPs")}
                          <textarea
                            aria-label={t("hostPlugins.ignoreIPs")}
                            value={ignoreIPs}
                            onChange={(e) => setIgnoreIPs(e.target.value)}
                            rows={2}
                          />
                        </label>
                        <label>
                          {t("hostPlugins.sshPorts")}
                          <input
                            aria-label={t("hostPlugins.sshPorts")}
                            value={ports}
                            onChange={(e) => setPorts(e.target.value)}
                          />
                        </label>
                        <label>
                          {t("hostPlugins.maxAttempts")}
                          <input
                            aria-label={t("hostPlugins.maxAttempts")}
                            type="number"
                            min={1}
                            max={10000}
                            value={attempts}
                            onChange={(e) => setAttempts(e.target.valueAsNumber)}
                          />
                        </label>
                        <button
                          className="button-secondary button-small"
                          type="submit"
                          disabled={busy || Boolean(active(job)) || Boolean(review)}
                        >
                          {t("hostPlugins.actions.protection_apply")}
                        </button>
                      </form>
                    )}
                  {d.id === "banhack233" && <p>{t("hostPlugins.keepaliveHint")}</p>}
                  {result?.output && (
                    <pre className="host-plugin-output" aria-label={t("hostPlugins.output")}>
                      {result.output}
                    </pre>
                  )}
                </details>
              </section>
            );
          })}
        </div>
        <details>
          <summary>{t("agentEvents.title")}</summary>
          <AgentEvents
            accessToken={accessToken}
            assetId={assetId}
            revision={job && !active(job) ? job.id : ""}
          />
        </details>
        {job && (
          <section className="host-plugin-job" aria-live="polite">
            <h3>{t("hostPlugins.job")}</h3>
            <p>
              <code>{job.id}</code> ·{" "}
              {t(`operations.states.${job.state}`, { defaultValue: job.state })}
            </p>
            {job.error_code && (
              <p role="alert">{t("hostPlugins.jobFailed", { code: job.error_code })}</p>
            )}
            {active(job) && (
              <button
                type="button"
                className="button-secondary"
                onClick={() => {
                  void cancel();
                }}
              >
                {t("hostPlugins.cancel")}
              </button>
            )}
            <p>{t("hostPlugins.auditHint")}</p>
          </section>
        )}
      </div>
    </div>
  );
}
