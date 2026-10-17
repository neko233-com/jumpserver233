import { useCallback, useEffect, useRef, useState, type FormEvent } from "react";
import { useTranslation } from "react-i18next";
import { useLocation } from "react-router-dom";
import { useAuth } from "../auth/AuthContext";
import OperationsPanel from "../components/OperationsPanel";
import { usePermissions } from "../auth/usePermissions";
import type { AccountChoice } from "../components/managedAccounts";

type Asset = {
  protocol?: string;
  id: string;
  name: string;
  username: string;
  permissions: string[];
  accounts?: AccountChoice[];
};
type Job = {
  id: string;
  asset_name: string;
  operator: string;
  operator_id: string;
  command: string;
  state: string;
  rule_name?: string;
  reviewed_by?: string;
  created_at: string;
  stdout?: string;
  stderr?: string;
  exit_code: number;
  truncated: boolean;
  error_code?: string;
};
const pageSize = 50;
const active = (job: Job) => job.state === "running" || job.state === "pending_review";

export default function WorkbenchPage() {
  const { search: notificationSearch } = useLocation();
  const { t, i18n } = useTranslation();
  const { accessToken } = useAuth();
  const [assets, setAssets] = useState<Asset[]>([]);
  const [jobs, setJobs] = useState<Job[]>([]);
  const [total, setTotal] = useState(0);
  const [offset, setOffset] = useState(0);
  const { allows, userID } = usePermissions();
  const [assetID, setAssetID] = useState("");
  const [command, setCommand] = useState("");
  const [timeout, setTimeoutSeconds] = useState(60);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState(false);
  const [reviewPending, setReviewPending] = useState(false);
  const [selected, setSelected] = useState<Job | null>(null);
  const requestID = useRef("");
  const request = useCallback(
    (url: string, init?: RequestInit) => {
      const headers = new Headers(init?.headers);
      if (accessToken) headers.set("Authorization", `Bearer ${accessToken}`);
      if (init?.body) headers.set("Content-Type", "application/json");
      return fetch(url, { ...init, headers });
    },
    [accessToken],
  );
  useEffect(() => {
    const id = new URLSearchParams(notificationSearch).get("job");
    if (!id || !/^[A-Za-z0-9_-]{1,128}$/.test(id)) return;
    const controller = new AbortController();
    void request(`/api/v1/ops/jobs/${encodeURIComponent(id)}`, { signal: controller.signal })
      .then((r) => {
        if (!r.ok) throw new Error();
        return r.json();
      })
      .then((v) => {
        if (!controller.signal.aborted) setSelected(v);
      })
      .catch(() => {
        if (!controller.signal.aborted) setError(true);
      });
    return () => controller.abort();
  }, [notificationSearch, request]);
  const load = useCallback(
    async (signal?: AbortSignal) => {
      try {
        const responses = await Promise.all([
          request("/api/v1/assets", { signal }),
          request(`/api/v1/ops/jobs?limit=${pageSize}&offset=${offset}`, { signal }),
        ]);
        if (responses.some((response) => !response.ok)) throw new Error("job data unavailable");
        const [inventory, page] = (await Promise.all(
          responses.map((response) => response.json()),
        )) as [Asset[], { results: Job[]; total: number }];
        if (signal?.aborted) return;
        setAssets(
          inventory
            .flatMap((asset) =>
              asset.accounts?.length
                ? asset.accounts
                    .filter((a) => a.active && a.permissions.includes("connect"))
                    .map((a) => ({
                      ...asset,
                      id: a.id,
                      username: a.username,
                      permissions: a.permissions,
                    }))
                : [asset],
            )
            .filter(
              (asset) =>
                (asset.protocol ?? "ssh") === "ssh" && asset.permissions.includes("connect"),
            ),
        );
        setJobs(page.results);
        setTotal(page.total);
        setError(false);
      } catch {
        if (!signal?.aborted) setError(true);
      }
    },
    [offset, request],
  );
  useEffect(() => {
    const controller = new AbortController();
    queueMicrotask(() => {
      if (!controller.signal.aborted) void load(controller.signal);
    });
    return () => controller.abort();
  }, [load]);
  const hasActive = jobs.some(active);
  useEffect(() => {
    if (!hasActive) return;
    const timer = window.setInterval(() => {
      void load();
    }, 3000);
    return () => window.clearInterval(timer);
  }, [hasActive, load]);
  useEffect(() => {
    if (!selected || !active(selected)) return;
    const controller = new AbortController();
    const timer = window.setInterval(() => {
      void request(`/api/v1/ops/jobs/${encodeURIComponent(selected.id)}`, {
        signal: controller.signal,
      })
        .then(async (response) => {
          if (response.ok) {
            const result = (await response.json()) as Job;
            if (!controller.signal.aborted) setSelected(result);
          }
        })
        .catch(() => {
          if (!controller.signal.aborted) setError(true);
        });
    }, 2000);
    return () => {
      controller.abort();
      window.clearInterval(timer);
    };
  }, [request, selected]);
  async function submit(event: FormEvent) {
    event.preventDefault();
    setBusy(true);
    setError(false);
    setReviewPending(false);
    if (!requestID.current) requestID.current = crypto.randomUUID();
    try {
      const response = await request("/api/v1/ops/jobs", {
        method: "POST",
        body: JSON.stringify({
          asset_id: assetID,
          command,
          timeout_seconds: timeout,
          request_id: requestID.current,
        }),
      });
      if (response.status === 202) {
        setReviewPending(true);
        return;
      }
      if (!response.ok) throw new Error("job submission failed");
      setSelected((await response.json()) as Job);
      requestID.current = "";
      await load();
    } catch {
      setError(true);
    } finally {
      setBusy(false);
    }
  }
  async function action(job: Job, approve?: boolean) {
    setBusy(true);
    try {
      const response = await request(
        `/api/v1/ops/jobs/${encodeURIComponent(job.id)}${approve === undefined ? "" : "/review"}`,
        {
          method: approve === undefined ? "DELETE" : "POST",
          ...(approve === undefined ? {} : { body: JSON.stringify({ approve }) }),
        },
      );
      if (!response.ok) throw new Error("job action failed");
      await load();
      const detail = await request(`/api/v1/ops/jobs/${encodeURIComponent(job.id)}`);
      if (detail.ok) setSelected((await detail.json()) as Job);
    } catch {
      setError(true);
    } finally {
      setBusy(false);
    }
  }
  async function inspect(job: Pick<Job, "id">) {
    try {
      const response = await request(`/api/v1/ops/jobs/${encodeURIComponent(job.id)}`);
      if (!response.ok) throw new Error("job unavailable");
      setSelected((await response.json()) as Job);
    } catch {
      setError(true);
    }
  }
  return (
    <section className="jobs-page">
      <header className="jobs-heading">
        <div>
          <h1>{t("jobs.title")}</h1>
          <p>{t("jobs.subtitle")}</p>
        </div>
        <button
          type="button"
          onClick={() => {
            void load();
          }}
        >
          {t("jobs.refresh")}
        </button>
      </header>
      <OperationsPanel
        assets={assets}
        request={request}
        onJob={(id) => {
          void inspect({ id });
        }}
      />
      {error && (
        <p role="alert" className="login-error">
          {t("jobs.error")}
        </p>
      )}
      <form
        className="jobs-form"
        onSubmit={(event) => {
          void submit(event);
        }}
      >
        <label>
          {t("jobs.asset")}
          <select
            required
            value={assetID}
            onChange={(event) => {
              setAssetID(event.target.value);
              requestID.current = "";
              setReviewPending(false);
            }}
          >
            <option value="">{t("jobs.chooseAsset")}</option>
            {assets.map((asset) => (
              <option key={asset.id} value={asset.id}>
                {asset.name} ({asset.username})
              </option>
            ))}
          </select>
        </label>
        <label className="jobs-command">
          {t("jobs.command")}
          <input
            required
            maxLength={8192}
            value={command}
            onChange={(event) => {
              setCommand(event.target.value);
              requestID.current = "";
              setReviewPending(false);
            }}
            autoComplete="off"
            spellCheck={false}
          />
        </label>
        <label>
          {t("jobs.timeout")}
          <input
            type="number"
            min={1}
            max={300}
            required
            value={timeout}
            onChange={(event) => {
              setTimeoutSeconds(Number(event.target.value));
              requestID.current = "";
            }}
          />
        </label>
        <button type="submit" disabled={busy || !assetID || !command.trim()}>
          {t("jobs.run")}
        </button>
      </form>
      {assets.length === 0 && <p>{t("jobs.noAssets")}</p>}
      {reviewPending && <p role="status">{t("jobs.loginReview")}</p>}
      <div className="jobs-table-scroll">
        <table className="jobs-table">
          <thead>
            <tr>
              <th>{t("jobs.created")}</th>
              <th>{t("jobs.asset")}</th>
              <th>{t("jobs.operator")}</th>
              <th>{t("jobs.command")}</th>
              <th>{t("jobs.status")}</th>
              <th>{t("jobs.actions")}</th>
            </tr>
          </thead>
          <tbody>
            {jobs.map((job) => (
              <tr key={job.id}>
                <td>{new Date(job.created_at).toLocaleString(i18n.language)}</td>
                <td>{job.asset_name}</td>
                <td>{job.operator}</td>
                <td>
                  <code>{job.command}</code>
                </td>
                <td>{t(`jobs.states.${job.state}`)}</td>
                <td>
                  <button
                    type="button"
                    onClick={() => {
                      void inspect(job);
                    }}
                  >
                    {t("jobs.details")}
                  </button>
                  {active(job) && (job.operator_id === userID || allows("jobs.cancel_all")) && (
                    <button
                      type="button"
                      disabled={busy}
                      onClick={() => {
                        void action(job);
                      }}
                    >
                      {t("jobs.cancel")}
                    </button>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      {jobs.length === 0 && <p>{t("jobs.empty")}</p>}
      <div className="jobs-pagination">
        <button
          type="button"
          disabled={offset === 0}
          onClick={() => setOffset(Math.max(0, offset - pageSize))}
        >
          {t("jobs.previous")}
        </button>
        <span>{t("jobs.count", { count: total })}</span>
        <button
          type="button"
          disabled={offset + pageSize >= total}
          onClick={() => setOffset(offset + pageSize)}
        >
          {t("jobs.next")}
        </button>
      </div>
      {selected && (
        <section className="jobs-detail" aria-label={t("jobs.result")}>
          <header>
            <h2>
              {t("jobs.result")} · {selected.id}
            </h2>
            <button type="button" onClick={() => setSelected(null)}>
              {t("jobs.close")}
            </button>
          </header>
          <p>
            {t(`jobs.states.${selected.state}`)}
            {selected.rule_name ? ` · ${selected.rule_name}` : ""}
            {selected.reviewed_by
              ? ` · ${t("jobs.reviewedBy", { name: selected.reviewed_by })}`
              : ""}
          </p>
          <code>{selected.command}</code>
          {selected.error_code && <p role="status">{t(`jobs.errors.${selected.error_code}`)}</p>}
          {allows("jobs.review") && selected.state === "pending_review" && (
            <div>
              <button
                type="button"
                disabled={busy}
                onClick={() => {
                  void action(selected, true);
                }}
              >
                {t("jobs.approve")}
              </button>
              <button
                type="button"
                disabled={busy}
                onClick={() => {
                  void action(selected, false);
                }}
              >
                {t("jobs.deny")}
              </button>
            </div>
          )}
          {selected.exit_code >= 0 && <p>{t("jobs.exitCode", { code: selected.exit_code })}</p>}
          <h3>{t("jobs.stdout")}</h3>
          <pre>{selected.stdout || "—"}</pre>
          <h3>{t("jobs.stderr")}</h3>
          <pre>{selected.stderr || "—"}</pre>
          {selected.truncated && <p>{t("jobs.truncated")}</p>}
        </section>
      )}
    </section>
  );
}
