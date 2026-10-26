import { requestID as newRequestID } from "../utils/requestID";
import { useCallback, useEffect, useRef, useState, type FormEvent } from "react";
import { useTranslation } from "react-i18next";
import "../i18n/locales/features/operations/register";
import { usePermissions } from "../auth/usePermissions";
import type { DiscoveryPlan, DiscoveryReceiptPage } from "./accountCollectionTypes";

export default function AccountDiscoverySchedule({
  assetId,
  accessToken,
  canConnect,
  onCollected,
}: {
  assetId: string;
  accessToken: string;
  canConnect: boolean;
  onCollected: () => void;
}) {
  const { t, i18n } = useTranslation();
  const { allows, userID } = usePermissions();
  const [open, setOpen] = useState(false),
    [plans, setPlans] = useState<DiscoveryPlan[]>([]);
  const [history, setHistory] = useState<DiscoveryReceiptPage>({ results: [], next_before: 0 });
  const [before, setBefore] = useState(0),
    [previous, setPrevious] = useState<number[]>([]);
  const [editing, setEditing] = useState<DiscoveryPlan | null>(null),
    [minutes, setMinutes] = useState("60");
  const [formOpen, setFormOpen] = useState(false),
    [busy, setBusy] = useState(false),
    [error, setError] = useState("");
  const [reload, setReload] = useState(0),
    [loadedKey, setLoadedKey] = useState("");
  const requestID = useRef("");
  const latestIndex = useRef<number | null>(null);
  const base = `/api/v1/assets/${encodeURIComponent(assetId)}/account-discovery`;
  const canSchedule = allows("accounts.schedule") && allows("accounts.discover") && canConnect;
  const requestKey = JSON.stringify([base, before, reload]);
  const request = useCallback(
    (url: string, init?: RequestInit) => {
      const headers = new Headers(init?.headers);
      if (accessToken) headers.set("Authorization", `Bearer ${accessToken}`);
      return fetch(url, {
        ...init,
        headers,
        signal: init?.signal
          ? AbortSignal.any([init.signal, AbortSignal.timeout(15_000)])
          : AbortSignal.timeout(15_000),
      });
    },
    [accessToken],
  );
  useEffect(() => {
    if (!open) return;
    const controller = new AbortController();
    let timer: ReturnType<typeof setTimeout> | undefined;
    async function load() {
      try {
        const responses = await Promise.all([
          request(`${base}/plans`, { signal: controller.signal }),
          request(`${base}/collections?before=${before}&limit=10`, { signal: controller.signal }),
        ]);
        if (!responses[0].ok) throw Error();
        const nextPlans = (await responses[0].json()) as DiscoveryPlan[];
        if (controller.signal.aborted) return;
        if (!Array.isArray(nextPlans)) throw Error();
        setPlans(nextPlans);
        if (!responses[1].ok) throw Error();
        const records = (await responses[1].json()) as DiscoveryReceiptPage;
        if (controller.signal.aborted) return;
        if (!Array.isArray(records.results)) throw Error();
        setHistory(records);
        setLoadedKey(requestKey);
        setError((current) => (current === "failed" ? "" : current));
        if (before === 0) {
          const index = records.results[0]?.index || 0;
          if (latestIndex.current !== null && index !== latestIndex.current) onCollected();
          latestIndex.current = index;
        }
      } catch {
        if (!controller.signal.aborted) {
          setError("failed");
          setLoadedKey(requestKey);
        }
      } finally {
        if (!controller.signal.aborted) timer = setTimeout(() => void load(), 5000);
      }
    }
    void load();
    return () => {
      controller.abort();
      if (timer) clearTimeout(timer);
    };
  }, [open, base, before, request, onCollected, requestKey]);
  const fail = async (response: Response) => {
    if (!response.ok)
      throw Error(
        response.status === 409 ? "conflict" : response.status === 403 ? "denied" : "failed",
      );
  };
  const startEdit = (plan: DiscoveryPlan | null) => {
    setEditing(plan);
    setMinutes(String((plan?.interval_seconds || 3600) / 60));
    setFormOpen(true);
    setError("");
    requestID.current = "";
  };
  async function save(e: FormEvent) {
    e.preventDefault();
    const interval = Number(minutes) * 60;
    if (!Number.isInteger(interval) || interval < 60 || interval > 86400) return;
    setBusy(true);
    setError("");
    if (!requestID.current) requestID.current = newRequestID();
    try {
      const response = await request(
        editing
          ? `/api/v1/assets/${encodeURIComponent(editing.asset_ids[0])}/account-discovery/plans/${encodeURIComponent(editing.id)}`
          : `${base}/plans`,
        {
          method: editing ? "PUT" : "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(
            editing
              ? {
                  enabled: editing.enabled,
                  interval_seconds: interval,
                  revision: editing.config_revision,
                }
              : {
                  name: t("accountSchedule.title"),
                  interval_seconds: interval,
                  request_id: requestID.current,
                },
          ),
        },
      );
      await fail(response);
      setFormOpen(false);
      setEditing(null);
      requestID.current = "";
      setReload((v) => v + 1);
    } catch (e) {
      setError(
        e instanceof Error && ["conflict", "denied"].includes(e.message) ? e.message : "failed",
      );
    } finally {
      setBusy(false);
    }
  }
  async function toggle(plan: DiscoveryPlan) {
    setBusy(true);
    setError("");
    try {
      const response = await request(
        `/api/v1/assets/${encodeURIComponent(plan.asset_ids[0])}/account-discovery/plans/${encodeURIComponent(plan.id)}`,
        {
          method: "PUT",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ enabled: !plan.enabled, revision: plan.config_revision }),
        },
      );
      await fail(response);
      setReload((v) => v + 1);
    } catch (e) {
      setError(
        e instanceof Error && ["conflict", "denied"].includes(e.message) ? e.message : "failed",
      );
    } finally {
      setBusy(false);
    }
  }
  const time = (v?: string) => (v ? new Date(v).toLocaleString(i18n.language) : "—");
  const summary = (raw?: string) => {
    try {
      const v = JSON.parse(raw || "{}");
      if ([v.observed, v.new, v.missing].every(Number.isSafeInteger))
        return t("accountDiscovery.summary", { count: v.observed, new: v.new, missing: v.missing });
    } catch {
      /* A failed run can have no inventory summary. */
    }
    return "—";
  };
  return (
    <details className="account-discovery-schedule" onToggle={(e) => setOpen(e.currentTarget.open)}>
      <summary>{t("accountSchedule.title")}</summary>
      {open && (
        <>
          <p className="settings-help">{t("accountSchedule.hint")}</p>
          <div className="account-discovery-actions">
            {canSchedule && (
              <button
                type="button"
                className="button-secondary"
                disabled={busy || plans.some((p) => p.owner_id === userID && p.enabled)}
                onClick={() => startEdit(null)}
              >
                {t("accountSchedule.create")}
              </button>
            )}
            <button
              type="button"
              className="button-secondary"
              disabled={busy}
              onClick={() => {
                setError("");
                setReload((v) => v + 1);
              }}
            >
              {t("audit.refresh")}
            </button>
          </div>
          {error && (
            <p role="alert" className="asset-error">
              {t(`accountSchedule.errors.${error}`)}
            </p>
          )}
          {loadedKey !== requestKey && <p role="status">{t("managedAccounts.loading")}</p>}
          <div className="account-discovery-table">
            <table>
              <thead>
                <tr>
                  <th>{t("accountSchedule.account")}</th>
                  <th>{t("accountSchedule.interval")}</th>
                  <th>{t("operations.nextRun")}</th>
                  <th>{t("accountSchedule.latest")}</th>
                  <th>{t("jobs.status")}</th>
                  <th>{t("assets.actions")}</th>
                </tr>
              </thead>
              <tbody>
                {plans.map((plan) => (
                  <tr key={plan.id}>
                    <td>
                      {plan.collection_account}
                      <small>{plan.owner}</small>
                    </td>
                    <td>{plan.interval_seconds / 60}</td>
                    <td>{time(plan.enabled ? plan.next_run : undefined)}</td>
                    <td>
                      {plan.last_run ? t(`operations.states.${plan.last_run.state}`) : "—"}
                      {plan.last_run?.items.map((item, index) => (
                        <small key={index}>
                          {item.state === "waiting_review" && item.review_id
                            ? t("accountDiscovery.loginReview", { id: item.review_id })
                            : item.state === "pending_review"
                              ? t("accountSchedule.commandReview", { id: item.job_id })
                              : ""}
                        </small>
                      ))}
                    </td>
                    <td>
                      {t(plan.enabled ? "operations.enabled" : "accountSchedule.paused")}
                      {plan.error_code && (
                        <small>
                          {t(
                            plan.error_code === "access_denied"
                              ? "accountSchedule.autoPaused"
                              : "operations.errors." + plan.error_code,
                          )}
                        </small>
                      )}
                    </td>
                    <td>
                      {(plan.owner_id === userID || allows("plans.manage_all")) && (
                        <div className="account-discovery-actions">
                          <button
                            type="button"
                            className="button-text"
                            disabled={busy || (!plan.enabled && !canSchedule)}
                            onClick={() => void toggle(plan)}
                          >
                            {t(plan.enabled ? "operations.pause" : "operations.resume")}
                          </button>
                          {canSchedule && (
                            <button
                              type="button"
                              className="button-text"
                              disabled={busy}
                              onClick={() => startEdit(plan)}
                            >
                              {t("accountSchedule.edit")}
                            </button>
                          )}
                        </div>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          {plans.length === 0 && <p>{t("accountSchedule.empty")}</p>}
          {formOpen && (
            <form onSubmit={(e) => void save(e)} className="account-discovery-review">
              <label>
                {t("accountSchedule.interval")}
                <input
                  aria-label={t("accountSchedule.interval")}
                  type="number"
                  min="1"
                  max="1440"
                  step="any"
                  required
                  value={minutes}
                  onChange={(e) => {
                    setMinutes(e.target.value);
                    requestID.current = "";
                  }}
                />
              </label>
              <div className="account-discovery-actions">
                <button
                  type="submit"
                  className="button-primary"
                  disabled={busy || !Number.isInteger(Number(minutes) * 60)}
                >
                  {t("assets.save")}
                </button>
                <button
                  type="button"
                  className="button-secondary"
                  disabled={busy}
                  onClick={() => {
                    setFormOpen(false);
                    setEditing(null);
                  }}
                >
                  {t("assets.cancel")}
                </button>
              </div>
            </form>
          )}
          <h3>{t("accountSchedule.history")}</h3>
          <div className="account-discovery-table">
            <table>
              <thead>
                <tr>
                  <th>{t("audit.started")}</th>
                  <th>{t("accountSchedule.account")}</th>
                  <th>{t("jobs.status")}</th>
                  <th>{t("accountSchedule.run")}</th>
                  <th>{t("accountSchedule.changes")}</th>
                </tr>
              </thead>
              <tbody>
                {history.results.map((row) => (
                  <tr key={row.index}>
                    <td>{time(row.observed_at)}</td>
                    <td>
                      {row.source.account}
                      <small>{row.collector.name || row.collector.id}</small>
                    </td>
                    <td>
                      {t(`operations.states.${row.receipt.state}`)}
                      <small>
                        {(row.receipt.job?.error_code || row.receipt.run.items[0]?.error_code) &&
                          t(
                            `jobs.errors.${row.receipt.job?.error_code || row.receipt.run.items[0]?.error_code}`,
                            { defaultValue: t("accountDiscovery.jobFailed") },
                          )}
                      </small>
                    </td>
                    <td>
                      {row.receipt.sequence}
                      <small>{row.receipt.run_id}</small>
                    </td>
                    <td>{summary(row.receipt.job?.stdout)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          {history.results.length === 0 && <p>{t("accountSchedule.noHistory")}</p>}
          <div className="account-discovery-actions">
            <button
              type="button"
              className="button-secondary"
              disabled={!previous.length}
              onClick={() => {
                setBefore(previous.at(-1) || 0);
                setPrevious((v) => v.slice(0, -1));
              }}
            >
              {t("audit.previous")}
            </button>
            <button
              type="button"
              className="button-secondary"
              disabled={!history.next_before}
              onClick={() => {
                setPrevious((v) => [...v, before]);
                setBefore(history.next_before);
              }}
            >
              {t("audit.next")}
            </button>
          </div>
        </>
      )}
    </details>
  );
}
