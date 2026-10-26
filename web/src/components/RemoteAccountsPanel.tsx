import { requestID as newRequestID } from "../utils/requestID";
import { useCallback, useEffect, useRef, useState } from "react";
import { useTranslation } from "react-i18next";
import { usePermissions } from "../auth/usePermissions";
import type { ManagedAccount } from "./managedAccounts";

type Task = {
  operation: {
    task: { id: string; action: string; username: string };
    mode: string;
    attempt: number;
  };
  revision: number;
  state: string;
  job_id?: string;
  review_id?: string;
  error_code?: string;
  result?: { state: string; error_code?: string; uid: number; stage?: string };
};
type Job = { state: string; error_code?: string };
class RemoteError extends Error {
  constructor(readonly code: string) {
    super(code);
  }
}
const knownErrors = new Set([
  "invalid",
  "not_found",
  "pending",
  "referenced",
  "conflict",
  "capacity",
  "denied",
  "unavailable",
  "uid",
  "confirm",
]);
const terminal = (t: Task) => t.state === "succeeded" || t.state === "cancelled";

export default function RemoteAccountsPanel({
  assetId,
  collectorId,
  accessToken,
  onChanged,
}: {
  assetId: string;
  collectorId: string;
  accessToken: string;
  onChanged: () => void;
}) {
  const { t } = useTranslation();
  const { allows } = usePermissions();
  const [requestedAction, setAction] = useState("create"),
    [username, setUsername] = useState(""),
    [uid, setUID] = useState(""),
    [confirm, setConfirm] = useState(""),
    [shell, setShell] = useState("/bin/bash");
  const [page, setPage] = useState<{ results: Task[]; total: number }>({ results: [], total: 0 });
  const [jobs, setJobs] = useState<Record<string, Job>>({}),
    [collector, setCollector] = useState<ManagedAccount | null>(null);
  const [error, setError] = useState(""),
    [pollError, setPollError] = useState(false),
    [busy, setBusy] = useState(false),
    [offset, setOffset] = useState(0),
    [reload, setReload] = useState(0);
  const intent = useRef({ key: "", id: "" });
  const availableActions = ["create", "disable", "enable", "delete"].filter((v) =>
    allows(`accounts.remote.${v}`),
  );
  const action = availableActions.includes(requestedAction)
    ? requestedAction
    : availableActions[0] || "create";
  const base = `/api/v1/assets/${encodeURIComponent(collectorId)}/remote-account-tasks`;
  const accounts = `/api/v1/assets/${encodeURIComponent(assetId)}/accounts`;
  const request = useCallback(
    async (path: string, init?: RequestInit) => {
      const headers = new Headers(init?.headers);
      if (accessToken) headers.set("Authorization", `Bearer ${accessToken}`);
      const response = await fetch(path, {
        ...init,
        headers,
        signal: init?.signal || AbortSignal.timeout(15_000),
      });
      if (!response.ok) {
        let code = "unavailable";
        try {
          code = (await response.json()).error_code || code;
        } catch {
          /* An empty response is unavailable. */
        }
        throw new RemoteError(knownErrors.has(code) ? code : "unavailable");
      }
      return response;
    },
    [accessToken],
  );
  const fail = useCallback(
    (e: unknown) => setError(e instanceof RemoteError ? e.code : "unavailable"),
    [],
  );
  useEffect(() => {
    const controller = new AbortController();
    let timer: ReturnType<typeof setTimeout>;
    const load = async () => {
      try {
        const signal = AbortSignal.any([controller.signal, AbortSignal.timeout(15_000)]);
        const [tasks, account] = await Promise.all([
          request(`${base}?offset=${offset}&limit=20`, { signal }).then((r) => r.json()),
          request(`${accounts}/${encodeURIComponent(collectorId)}`, { signal }).then((r) =>
            r.json(),
          ),
        ]);
        if (!Array.isArray(tasks.results) || !Number.isSafeInteger(tasks.total)) throw Error();
        const states: Record<string, Job> = {};
        for (const task of tasks.results as Task[]) {
          if (task.job_id && !terminal(task)) {
            try {
              const response = await request(
                `/api/v1/ops/jobs/${encodeURIComponent(task.job_id)}`,
                { signal },
              );
              states[task.job_id] = await response.json();
            } catch {
              states[task.job_id] = { state: "unavailable" };
            }
          }
        }
        if (!controller.signal.aborted) {
          setPage(tasks);
          setCollector(account);
          setJobs(states);
          setPollError(false);
        }
      } catch {
        if (!controller.signal.aborted) setPollError(true);
      }
      if (!controller.signal.aborted) timer = setTimeout(() => void load(), 5000);
    };
    void load();
    return () => {
      controller.abort();
      clearTimeout(timer);
    };
  }, [base, accounts, collectorId, offset, reload, request, fail]);
  const changed = () => {
    setReload((v) => v + 1);
    onChanged();
  };
  const post = async (path: string, body?: unknown) =>
    request(path, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      ...(body ? { body: JSON.stringify(body) } : {}),
    });
  async function create(e: React.SubmitEvent<HTMLFormElement>) {
    e.preventDefault();
    setBusy(true);
    setError("");
    try {
      if (action === "delete" && confirm !== username) throw new RemoteError("confirm");
      const current = await (
        await request(`${accounts}?username=${encodeURIComponent(username)}&limit=2`)
      ).json();
      const target: ManagedAccount | undefined =
        current.total === 1 ? current.results[0] : undefined;
      const resolvedUID = uid ? Number(uid) : target?.remote_account?.uid;
      if (
        action !== "create" &&
        (!target ||
          target.default ||
          !Number.isSafeInteger(resolvedUID) ||
          resolvedUID! < 1000 ||
          resolvedUID! > 60000)
      )
        throw new RemoteError("uid");
      const key = JSON.stringify([assetId, collectorId, action, username, resolvedUID, shell]);
      if (intent.current.key !== key) intent.current = { key, id: newRequestID() };
      await post(base, {
        action,
        username,
        version: action === "create" ? current.version : target!.version,
        request_id: intent.current.id,
        ...(action === "create" ? { shell } : { uid: resolvedUID, account_id: target!.id }),
      });
      intent.current = { key: "", id: "" };
      setUsername("");
      setUID("");
      setConfirm("");
      setOffset(0);
      changed();
    } catch (e) {
      fail(e);
    } finally {
      setBusy(false);
    }
  }
  async function mutate(task: Task, mode: string) {
    setBusy(true);
    setError("");
    try {
      const path = `${base}/${encodeURIComponent(task.operation.task.id)}`;
      if (mode === "stop") {
        await request(`/api/v1/ops/jobs/${encodeURIComponent(task.job_id!)}`, { method: "DELETE" });
      } else if (mode === "submit") await post(`${path}/submit`);
      else await post(`${path}/attempts`, { revision: task.revision, mode });
      changed();
    } catch (e) {
      fail(e);
    } finally {
      setBusy(false);
    }
  }
  return (
    <section className="remote-accounts-panel" aria-labelledby="remote-accounts-title">
      <h3 id="remote-accounts-title">{t("remoteAccounts.title")}</h3>
      <p>{t("remoteAccounts.collector", { username: collector?.username || "…" })}</p>
      <details>
        <summary>{t("remoteAccounts.details")}</summary>
        <p className="settings-help">{t("remoteAccounts.hint")}</p>
        <p className="settings-help">{t("remoteAccounts.recoveryHint")}</p>
      </details>
      {(error || pollError) && (
        <p role="alert" className="asset-error">
          {t(`remoteAccounts.errors.${error || "unavailable"}`)}
        </p>
      )}
      {allows("accounts.manage") && (
        <details open>
          <summary>{t("remoteAccounts.newTask")}</summary>
          <form onSubmit={(e) => void create(e)}>
            <div className="managed-accounts-fields">
              <label>
                {t("remoteAccounts.action")}
                <select
                  aria-label={t("remoteAccounts.action")}
                  value={action}
                  onChange={(e) => {
                    setAction(e.target.value);
                    setConfirm("");
                  }}
                >
                  {availableActions.map((v) => (
                    <option key={v} value={v}>
                      {t(`remoteAccounts.actions.${v}`)}
                    </option>
                  ))}
                </select>
              </label>
              <label>
                {t("remoteAccounts.username")}
                <input
                  required
                  pattern="[a-z_][a-z0-9_-]{1,31}"
                  maxLength={32}
                  value={username}
                  onChange={(e) => setUsername(e.target.value)}
                />
              </label>
              {action === "create" ? (
                <label>
                  {t("remoteAccounts.shell")}
                  <select value={shell} onChange={(e) => setShell(e.target.value)}>
                    <option>/bin/bash</option>
                    <option>/bin/sh</option>
                  </select>
                </label>
              ) : (
                <label>
                  {t("remoteAccounts.uid")}
                  <input
                    type="number"
                    min={1000}
                    max={60000}
                    value={uid}
                    onChange={(e) => setUID(e.target.value)}
                    placeholder={t("remoteAccounts.uidHint")}
                  />
                </label>
              )}
              {action === "delete" && (
                <label>
                  {t("remoteAccounts.confirm")}
                  <input required value={confirm} onChange={(e) => setConfirm(e.target.value)} />
                </label>
              )}
            </div>
            {action === "delete" && (
              <p className="settings-help">{t("remoteAccounts.deleteHint")}</p>
            )}
            <button
              type="submit"
              className="button-primary"
              disabled={busy || !collector?.active || !allows(`accounts.remote.${action}`)}
            >
              {t("remoteAccounts.submit")}
            </button>
          </form>
        </details>
      )}
      <div className="managed-accounts-actions">
        <h4>{t("remoteAccounts.tasks", { total: page.total })}</h4>
        <button
          type="button"
          className="button-secondary"
          disabled={busy}
          onClick={() => {
            setError("");
            changed();
          }}
        >
          {t("audit.refresh")}
        </button>
      </div>
      <ul className="remote-accounts-tasks">
        {page.results.map((task) => {
          const job = task.job_id ? jobs[task.job_id] : undefined;
          const running = job?.state === "running" || job?.state === "pending_review";
          const allowed =
            allows("accounts.manage") && allows(`accounts.remote.${task.operation.task.action}`);
          const state = terminal(task)
            ? task.state
            : task.review_id && !task.job_id
              ? "review"
              : running
                ? "running"
                : task.job_id && job
                  ? "needs_reconcile"
                  : task.state;
          return (
            <li key={task.operation.task.id} data-remote-task={task.operation.task.id}>
              <strong>
                {task.operation.task.username} ·{" "}
                {t(`remoteAccounts.actions.${task.operation.task.action}`)}
              </strong>
              <span>{t(`remoteAccounts.states.${state}`)}</span>
              <small>
                {t("remoteAccounts.attempt", { count: task.operation.attempt })} ·{" "}
                {task.operation.mode}
              </small>
              <code>{task.operation.task.id}</code>
              {task.review_id && (
                <small>{t("remoteAccounts.review", { id: task.review_id })}</small>
              )}
              {task.job_id && <small>{t("remoteAccounts.job", { id: task.job_id })}</small>}
              {task.result && (
                <small>
                  {t("remoteAccounts.result", {
                    state: task.result.state,
                    uid: task.result.uid,
                    stage: task.result.stage || "—",
                  })}
                </small>
              )}
              {(task.error_code || task.result?.error_code || job?.error_code) && (
                <p className="asset-error">
                  {t("remoteAccounts.operationFailed", {
                    code: task.error_code || task.result?.error_code || job?.error_code,
                  })}
                </p>
              )}
              {allowed && !terminal(task) && (
                <div className="managed-accounts-actions">
                  {running ? (
                    <button type="button" disabled={busy} onClick={() => void mutate(task, "stop")}>
                      {t("remoteAccounts.stop")}
                    </button>
                  ) : (
                    <>
                      {!task.job_id && (
                        <button
                          type="button"
                          disabled={busy}
                          onClick={() => void mutate(task, "submit")}
                        >
                          {t("remoteAccounts.resumeSubmission")}
                        </button>
                      )}
                      {["inspect", "apply", "cancel"].map((mode) => (
                        <button
                          type="button"
                          key={mode}
                          disabled={busy}
                          onClick={() => void mutate(task, mode)}
                        >
                          {t(`remoteAccounts.${mode}`)}
                        </button>
                      ))}
                    </>
                  )}
                </div>
              )}
            </li>
          );
        })}
      </ul>
      <div className="managed-accounts-actions">
        <button
          type="button"
          disabled={busy || offset === 0}
          onClick={() => setOffset(Math.max(0, offset - 20))}
        >
          {t("managedAccounts.previous")}
        </button>
        <button
          type="button"
          disabled={busy || offset + 20 >= page.total}
          onClick={() => setOffset(offset + 20)}
        >
          {t("managedAccounts.next")}
        </button>
      </div>
    </section>
  );
}
