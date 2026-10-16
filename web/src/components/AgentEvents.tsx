import { useCallback, useEffect, useState } from "react";
import { useTranslation } from "react-i18next";
import { usePermissions } from "../auth/usePermissions";
import "./agent-events.css";

type Row = {
  index: number;
  kind: string;
  observed_at: string;
  source: { asset_id: string; asset_name: string; account: string };
  collector: { id: string; name: string; job_id: string };
  stream?: string;
  from?: number;
  to?: number;
  event?: {
    sequence: number;
    kind: string;
    at: string;
    trigger: string;
    active_bans: number;
    attempt: string;
    config_sha: string;
    hash: string;
    error_code?: string;
  };
  receipt?: { state: string; run_id: string; job_id?: string; plan_id: string };
};
type Plan = {
  id: string;
  enabled: boolean;
  interval_seconds: number;
  error_code?: string;
  last_run_id?: string;
};
export default function AgentEvents({
  accessToken,
  assetId,
  revision = "",
}: {
  accessToken: string;
  assetId?: string;
  revision?: string;
}) {
  const { t } = useTranslation();
  const { allows } = usePermissions();
  const [kind, setKind] = useState("host");
  const [rows, setRows] = useState<Row[]>([]);
  const [before, setBefore] = useState(0);
  const [next, setNext] = useState(0);
  const [plans, setPlans] = useState<Plan[]>([]);
  const [interval, setInterval] = useState(300);
  const [failed, setFailed] = useState(false);
  const [busy, setBusy] = useState(false);
  const [reload, setReload] = useState(0);
  const request = useCallback(
    (url: string, init?: RequestInit) => {
      const headers = new Headers(init?.headers);
      if (accessToken) headers.set("Authorization", `Bearer ${accessToken}`);
      return fetch(url, { ...init, headers });
    },
    [accessToken],
  );
  useEffect(() => {
    const abort = new AbortController();
    const base = assetId ? `/api/v1/assets/${assetId}/agent-events` : "/api/v1/audit/agent-events";
    void Promise.all([
      request(`${base}?before=${before}&limit=30&kind=${kind}`, { signal: abort.signal }),
      ...(assetId ? [request(`${base}/collection`, { signal: abort.signal })] : []),
    ])
      .then(async (responses) => {
        if (responses.some((r) => !r.ok)) throw new Error();
        const data = await responses[0].json();
        const collection = responses[1] ? await responses[1].json() : [];
        if (!abort.signal.aborted) {
          setRows(data.results);
          setNext(data.next_before);
          setPlans(collection);
          const active = collection.find((p: Plan) => p.enabled);
          if (active) setInterval(active.interval_seconds);
          setFailed(false);
        }
      })
      .catch(() => {
        if (!abort.signal.aborted) setFailed(true);
      });
    return () => abort.abort();
  }, [request, assetId, before, revision, reload, kind]);
  async function toggle(enabled: boolean) {
    setBusy(true);
    try {
      const r = await request(`/api/v1/assets/${assetId}/agent-events/collection`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          enabled,
          interval_seconds: interval,
          request_id: crypto.randomUUID(),
        }),
      });
      if (!r.ok) throw new Error();
      setBefore(0);
      setReload((v) => v + 1);
    } catch {
      setFailed(true);
    } finally {
      setBusy(false);
    }
  }
  const enabled = plans.some((p) => p.enabled);
  return (
    <section className="agent-events" aria-label={t("agentEvents.title")}>
      <h2>{t("agentEvents.title")}</h2>
      <p>{t("agentEvents.hint")}</p>
      {failed && <p role="alert">{t("agentEvents.failed")}</p>}
      <div className="agent-events-controls">
        <label>
          {t("agentEvents.show")}
          <select
            aria-label={t("agentEvents.show")}
            value={kind}
            onChange={(e) => {
              setKind(e.target.value);
              setBefore(0);
            }}
          >
            <option value="host">{t("agentEvents.hostRecords")}</option>
            <option value="collection">{t("agentEvents.collectionRecords")}</option>
            <option value="all">{t("agentEvents.allRecords")}</option>
          </select>
        </label>
        <button
          type="button"
          className="button-secondary button-small"
          onClick={() => {
            setBefore(0);
            setReload((v) => v + 1);
          }}
        >
          {t("agentEvents.refresh")}
        </button>
        {assetId && allows("plugins.manage") && (
          <>
            <label>
              {t("agentEvents.interval")}
              <select
                aria-label={t("agentEvents.interval")}
                value={interval}
                disabled={enabled || busy}
                onChange={(e) => setInterval(Number(e.target.value))}
              >
                {[60, 300, 900, 3600].map((v) => (
                  <option key={v} value={v}>
                    {t("agentEvents.seconds", { count: v })}
                  </option>
                ))}
              </select>
            </label>
            <button
              type="button"
              className="button-secondary button-small"
              disabled={busy}
              onClick={() => void toggle(!enabled)}
            >
              {t(enabled ? "agentEvents.disable" : "agentEvents.enable")}
            </button>
            <span role="status">{t(enabled ? "agentEvents.enabled" : "agentEvents.disabled")}</span>
          </>
        )}
      </div>
      {assetId && <p>{t("agentEvents.collectionHint")}</p>}
      {plans
        .filter((p) => p.enabled && p.last_run_id)
        .map((p) => (
          <p key={p.id}>
            {t("agentEvents.lastRun")} <code>{p.last_run_id}</code>
            {p.error_code &&
              ` · ${t(`operations.errors.${p.error_code}`, { defaultValue: p.error_code })}`}
          </p>
        ))}
      {!rows.length ? (
        <p>{t("agentEvents.empty")}</p>
      ) : (
        <ol className="agent-event-list">
          {rows.map((row) => (
            <li key={row.index}>
              <div className="agent-event-head">
                <strong>{t(`agentEvents.kinds.${row.event?.kind ?? row.kind}`)}</strong>
                <span>
                  {row.source.asset_name} · {row.source.account}
                </span>
                <time dateTime={row.observed_at}>{new Date(row.observed_at).toLocaleString()}</time>
              </div>
              {row.event ? (
                <p>
                  {t("agentEvents.hostTime")}:{" "}
                  <time dateTime={row.event.at}>{new Date(row.event.at).toLocaleString()}</time> ·{" "}
                  {t(`agentEvents.triggers.${row.event.trigger}`)} ·{" "}
                  {t("agentEvents.bans", { count: row.event.active_bans })}
                </p>
              ) : row.receipt ? (
                <p>
                  {t(`operations.states.${row.receipt.state}`, { defaultValue: row.receipt.state })}{" "}
                  · <code>{row.receipt.run_id}</code>
                </p>
              ) : (
                <p>{t("agentEvents.range", { from: row.from ?? 0, to: row.to ?? 0 })}</p>
              )}
              <small>
                {t("agentEvents.receivedBy")}: {row.collector.name || row.collector.id}{" "}
                {row.collector.job_id && <code>{row.collector.job_id}</code>}
              </small>
              {row.event && (
                <details>
                  <summary>{t("agentEvents.evidence")}</summary>
                  <dl>
                    <dt>{t("agentEvents.stream")}</dt>
                    <dd>
                      <code>
                        {row.stream} / {row.event.sequence}
                      </code>
                    </dd>
                    <dt>{t("agentEvents.attempt")}</dt>
                    <dd>
                      <code>{row.event.attempt}</code>
                    </dd>
                    <dt>{t("agentEvents.config")}</dt>
                    <dd>
                      <code>{row.event.config_sha}</code>
                    </dd>
                    <dt>{t("agentEvents.hash")}</dt>
                    <dd>
                      <code>{row.event.hash}</code>
                    </dd>
                    {row.event.error_code && (
                      <>
                        <dt>{t("agentEvents.error")}</dt>
                        <dd>{row.event.error_code}</dd>
                      </>
                    )}
                  </dl>
                </details>
              )}
            </li>
          ))}
        </ol>
      )}
      {next > 0 && (
        <button type="button" className="button-secondary" onClick={() => setBefore(next)}>
          {t("agentEvents.older")}
        </button>
      )}
    </section>
  );
}
