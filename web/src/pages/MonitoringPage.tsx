import { useCallback, useEffect, useRef, useState, type FormEvent } from "react";
import { useSearchParams } from "react-router-dom";
import { useTranslation } from "react-i18next";
import { useAuth } from "../auth/AuthContext";
import { usePermissions } from "../auth/usePermissions";
import "../i18n/locales/features/monitoring/register";
import "./rotation-plans.css";
import "./monitoring.css";

type Actor = { id: string; name: string };
type Rule = {
  id: string;
  revision: number;
  definition: number;
  name: string;
  enabled: boolean;
  metric: string;
  scope: { all: boolean; asset_ids: string[]; node_ids: string[] };
  threshold: number;
  recovery_threshold: number;
  for_samples: number;
  for_seconds: number;
  recovery_samples: number;
  recovery_seconds: number;
  max_age_seconds: number;
  repeat_seconds: number;
  muted_until?: string;
  mute_reason?: string;
  last_error?: string;
  owner: Actor;
};
type Alert = {
  id: string;
  revision: number;
  rule_id: string;
  rule_name: string;
  asset_id: string;
  asset_name: string;
  metric: string;
  state: string;
  reason?: string;
  value?: number;
  threshold: number;
  recovery_threshold: number;
  started_at: string;
  last_observed_at: string;
  ended_at?: string;
  acknowledged_at?: string;
  acknowledged_by?: Actor;
  comment?: string;
};
type Audit = {
  id: string;
  at: string;
  actor: Actor;
  action: string;
  target: string;
  reason?: string;
};
type Asset = { id: string; name: string; protocol?: string };
type Node = { id: string; name: string };
type Requester = (
  path: string,
  method?: string,
  body?: unknown,
  signal?: AbortSignal,
) => Promise<Response>;
class MonitorError extends Error {
  constructor(public code: string) {
    super(code);
  }
}
const metrics = [
  "cpu_percent",
  "memory_percent",
  "disk_percent",
  "latency_ms",
  "network_rx_bps",
  "network_tx_bps",
  "offline",
  "no_data",
];
const initialRule = (): Rule => ({
  id: "",
  revision: 0,
  definition: 0,
  name: "",
  enabled: true,
  metric: "cpu_percent",
  scope: { all: true, asset_ids: [], node_ids: [] },
  threshold: 90,
  recovery_threshold: 80,
  for_samples: 3,
  for_seconds: 0,
  recovery_samples: 2,
  recovery_seconds: 0,
  max_age_seconds: 180,
  repeat_seconds: 0,
  owner: { id: "", name: "" },
});
export default function MonitoringPage() {
  const { t, i18n } = useTranslation(),
    { accessToken } = useAuth(),
    { allows } = usePermissions(),
    [params, setParams] = useSearchParams();
  const canView = allows("monitoring.view"),
    manage = allows("monitoring.manage"),
    ack = allows("monitoring.ack");
  const [tab, setTab] = useState<"alerts" | "rules" | "audit">("alerts"),
    [alerts, setAlerts] = useState<Alert[]>([]),
    [rules, setRules] = useState<Rule[]>([]),
    [audit, setAudit] = useState<Audit[]>([]),
    [total, setTotal] = useState(0),
    [offset, setOffset] = useState(0),
    [state, setState] = useState("firing"),
    [query, setQuery] = useState(""),
    [filter, setFilter] = useState(""),
    [editor, setEditor] = useState<Rule | null>(null),
    [error, setError] = useState(""),
    [notice, setNotice] = useState(""),
    [now, setNow] = useState(() => Date.now()),
    [busy, setBusy] = useState(false);
  const life = useRef<AbortController | null>(null),
    reader = useRef<AbortController | null>(null),
    generation = useRef(0),
    editing = useRef(false);
  useEffect(() => {
    editing.current = editor !== null || busy;
  }, [editor, busy]);
  useEffect(() => {
    life.current = new AbortController();
    return () => life.current?.abort();
  }, []);
  const request: Requester = useCallback(
    async (path, method = "GET", body, signal) => {
      const headers = new Headers();
      if (accessToken) headers.set("Authorization", `Bearer ${accessToken}`);
      if (body !== undefined) headers.set("Content-Type", "application/json");
      const signals = [AbortSignal.timeout(30_000)];
      if (life.current) signals.push(life.current.signal);
      if (signal) signals.push(signal);
      const r = await fetch("/api/v1/monitoring/" + path, {
        method,
        headers,
        signal: AbortSignal.any(signals),
        ...(body === undefined ? {} : { body: JSON.stringify(body) }),
      });
      if (!r.ok) {
        const codes: Record<number, string> = {
          400: "invalid",
          403: "denied",
          404: "not_found",
          409: "conflict",
          429: "capacity",
        };
        throw new MonitorError(codes[r.status] || "unavailable");
      }
      return r;
    },
    [accessToken],
  );
  const load = useCallback(
    async (signal?: AbortSignal) => {
      setNow(Date.now());
      const seq = ++generation.current;
      reader.current?.abort();
      const controller = new AbortController();
      reader.current = controller;
      const combined = signal ? AbortSignal.any([signal, controller.signal]) : controller.signal;
      try {
        if (tab === "alerts") {
          if (!canView) {
            setAlerts([]);
            setTotal(0);
            return;
          }
          const v = (await (
            await request(
              `alerts?offset=${offset}&limit=20&state=${state}&q=${encodeURIComponent(filter)}`,
              "GET",
              undefined,
              combined,
            )
          ).json()) as { results: Alert[]; total: number };
          if (!combined.aborted && seq === generation.current) {
            setAlerts(v.results);
            setTotal(v.total);
          }
        } else if (tab === "rules") {
          const v = (await (await request("rules", "GET", undefined, combined)).json()) as Rule[];
          if (!combined.aborted && seq === generation.current) {
            setRules(v);
            setTotal(v.length);
          }
        } else {
          const v = (await (
            await request(`audit?offset=${offset}&limit=20`, "GET", undefined, combined)
          ).json()) as { results: Audit[]; total: number };
          if (!combined.aborted && seq === generation.current) {
            setAudit(v.results);
            setTotal(v.total);
          }
        }
        if (!combined.aborted && seq === generation.current) setError("");
      } catch (e) {
        if (!combined.aborted && !life.current?.signal.aborted && seq === generation.current) {
          if (e instanceof MonitorError && (e.code === "denied" || e.code === "not_found")) {
            setAlerts([]);
            setRules([]);
            setAudit([]);
            setTotal(0);
          }
          setError(e instanceof MonitorError ? e.code : "unavailable");
        }
      } finally {
        if (reader.current === controller) reader.current = null;
      }
    },
    [tab, canView, offset, state, filter, request],
  );
  useEffect(() => {
    const controller = new AbortController();
    queueMicrotask(() => {
      if (!controller.signal.aborted) void load(controller.signal);
    });
    const timer = setInterval(() => {
      if (!editing.current && !reader.current && document.visibilityState !== "hidden")
        void load(controller.signal);
    }, 5000);
    return () => {
      controller.abort();
      clearInterval(timer);
    };
  }, [load]);
  const act = async (fn: () => Promise<unknown>) => {
    if (busy) return;
    setBusy(true);
    setError("");
    generation.current++;
    reader.current?.abort();
    reader.current = null;
    try {
      await fn();
      if (life.current?.signal.aborted) return;
      setNotice("monitoring.saved");
      await load();
      window.dispatchEvent(new Event("jms233-notifications"));
    } catch (e) {
      if (!life.current?.signal.aborted)
        setError(e instanceof MonitorError ? e.code : "unavailable");
    } finally {
      if (!life.current?.signal.aborted) setBusy(false);
    }
  };
  const saveRule = async (rule: Rule) => {
    const id = rule.id;
    const input = {
      revision: rule.revision,
      name: rule.name,
      enabled: rule.enabled,
      metric: rule.metric,
      scope: rule.scope,
      threshold: rule.threshold,
      recovery_threshold: rule.recovery_threshold,
      for_samples: rule.for_samples,
      for_seconds: rule.for_seconds,
      recovery_samples: rule.recovery_samples,
      recovery_seconds: rule.recovery_seconds,
      max_age_seconds: rule.max_age_seconds,
      repeat_seconds: rule.repeat_seconds,
    };
    await act(async () => {
      await request(id ? "rules/" + encodeURIComponent(id) : "rules", id ? "PUT" : "POST", input);
      setEditor(null);
    });
  };
  const date = (value: string) => new Date(value).toLocaleString(i18n.language);
  const changeTab = (value: typeof tab) => {
    setTab(value);
    setOffset(0);
    setNotice("");
  };
  const alertID = params.get("alert") || "";
  return (
    <section className="rotation-page monitoring-page" aria-busy={busy}>
      <header>
        <div>
          <h1>{t("monitoring.title")}</h1>
          <p>{t("monitoring.hint")}</p>
        </div>
        <button type="button" onClick={() => void load()} disabled={busy}>
          {t("monitoring.refresh")}
        </button>
      </header>
      <nav className="rotation-actions" aria-label={t("monitoring.views")}>
        {canView && (
          <button
            type="button"
            aria-current={tab === "alerts" ? "page" : undefined}
            onClick={() => changeTab("alerts")}
          >
            {t("monitoring.alerts")}
          </button>
        )}
        {manage && (
          <>
            <button
              type="button"
              aria-current={tab === "rules" ? "page" : undefined}
              onClick={() => changeTab("rules")}
            >
              {t("monitoring.rules")}
            </button>
            <button
              type="button"
              aria-current={tab === "audit" ? "page" : undefined}
              onClick={() => changeTab("audit")}
            >
              {t("monitoring.audit")}
            </button>
          </>
        )}
      </nav>
      {error && <p role="alert">{t(`monitoring.errors.${error}`)}</p>}
      <p role="status">{notice && t(notice)}</p>
      {tab === "alerts" && (
        <>
          <form
            className="rotation-actions"
            onSubmit={(e) => {
              e.preventDefault();
              setFilter(query);
              setOffset(0);
            }}
          >
            <label>
              {t("monitoring.state")}
              <select
                value={state}
                onChange={(e) => {
                  setState(e.target.value);
                  setOffset(0);
                }}
              >
                {["firing", "resolved", "retired", ""].map((v) => (
                  <option key={v} value={v}>
                    {t(v ? `monitoring.states.${v}` : "monitoring.all")}
                  </option>
                ))}
              </select>
            </label>
            <label>
              {t("monitoring.search")}
              <input value={query} onChange={(e) => setQuery(e.target.value)} maxLength={200} />
            </label>
            <button type="submit">{t("monitoring.apply")}</button>
          </form>
          <div className="rotation-table">
            <table>
              <thead>
                <tr>
                  {["host", "rule", "metric", "value", "state", "started", "actions"].map((v) => (
                    <th key={v} scope="col">
                      {t(`monitoring.${v}`)}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {alerts.map((a) => (
                  <tr key={a.id}>
                    <td>
                      {a.asset_name}
                      <small>{a.asset_id}</small>
                    </td>
                    <td>{a.rule_name}</td>
                    <td>{t(`monitoring.metrics.${a.metric}`)}</td>
                    <td>
                      {a.value === undefined
                        ? t("monitoring.noValue")
                        : a.value.toLocaleString(i18n.language, { maximumFractionDigits: 2 })}
                    </td>
                    <td>
                      {t(`monitoring.states.${a.state}`)}
                      {a.acknowledged_at && <small>{t("monitoring.acknowledged")}</small>}
                    </td>
                    <td>{date(a.started_at)}</td>
                    <td>
                      <button type="button" onClick={() => setParams({ alert: a.id })}>
                        {t("monitoring.details")}
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          {alerts.length === 0 && <p>{t("monitoring.empty")}</p>}
        </>
      )}
      {tab === "rules" && manage && (
        <>
          <div className="rotation-actions">
            <button type="button" onClick={() => setEditor(initialRule())}>
              {t("monitoring.create")}
            </button>
          </div>
          <p>{t("monitoring.ruleHint")}</p>
          <div className="rotation-table">
            <table>
              <thead>
                <tr>
                  {["rule", "metric", "threshold", "recovery", "state", "actions"].map((v) => (
                    <th scope="col" key={v}>
                      {t(`monitoring.${v}`)}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {rules.map((r) => (
                  <tr key={r.id}>
                    <td>
                      {r.name}
                      <small>{r.id}</small>
                    </td>
                    <td>{t(`monitoring.metrics.${r.metric}`)}</td>
                    <td>
                      {r.threshold} · {t("monitoring.samples", { count: r.for_samples })}
                    </td>
                    <td>
                      {r.recovery_threshold} ·{" "}
                      {t("monitoring.samples", { count: r.recovery_samples })}
                    </td>
                    <td>
                      {t(r.enabled ? "monitoring.enabled" : "monitoring.disabled")}
                      {r.muted_until && new Date(r.muted_until).getTime() > now && (
                        <small>{t("monitoring.mutedUntil", { date: date(r.muted_until) })}</small>
                      )}
                      {r.last_error && <small>{t(`monitoring.reasons.${r.last_error}`)}</small>}
                    </td>
                    <td>
                      <div className="rotation-actions">
                        <button type="button" disabled={busy} onClick={() => setEditor(r)}>
                          {t("monitoring.edit")}
                        </button>
                        <button
                          type="button"
                          disabled={busy}
                          onClick={() =>
                            void act(() =>
                              request("rules/" + encodeURIComponent(r.id) + "/mute", "POST", {
                                revision: r.revision,
                                until: new Date(Date.now() + 30 * 60_000).toISOString(),
                                reason: "",
                              }),
                            )
                          }
                        >
                          {t("monitoring.mute30")}
                        </button>
                        {r.muted_until && new Date(r.muted_until).getTime() > now && (
                          <button
                            type="button"
                            disabled={busy}
                            onClick={() =>
                              void act(() =>
                                request("rules/" + encodeURIComponent(r.id) + "/mute", "POST", {
                                  revision: r.revision,
                                  until: "0001-01-01T00:00:00Z",
                                  reason: "",
                                }),
                              )
                            }
                          >
                            {t("monitoring.unmute")}
                          </button>
                        )}
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          {rules.length === 0 && <p>{t("monitoring.noRules")}</p>}
        </>
      )}
      {tab === "audit" && manage && (
        <div className="rotation-table">
          <table>
            <thead>
              <tr>
                {["time", "actor", "action", "target", "comment"].map((v) => (
                  <th key={v} scope="col">
                    {t(`monitoring.${v}`)}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {audit.map((a) => (
                <tr key={a.id}>
                  <td>{date(a.at)}</td>
                  <td>{a.actor.name}</td>
                  <td>{t(`monitoring.auditActions.${a.action}`)}</td>
                  <td>{a.target}</td>
                  <td>{a.reason}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      {tab !== "rules" && (
        <nav className="rotation-actions" aria-label={t("monitoring.pagination")}>
          <button
            type="button"
            disabled={offset === 0}
            onClick={() => setOffset(Math.max(0, offset - 20))}
          >
            {t("monitoring.previous")}
          </button>
          <span>{t("monitoring.total", { count: total })}</span>
          <button
            type="button"
            disabled={offset + 20 >= total}
            onClick={() => setOffset(offset + 20)}
          >
            {t("monitoring.next")}
          </button>
        </nav>
      )}
      {editor && (
        <RuleEditor
          key={editor.id || "new"}
          initial={editor}
          request={request}
          busy={busy}
          error={error}
          onSave={saveRule}
          onClose={() => setEditor(null)}
        />
      )}
      {alertID && (
        <AlertDetail
          key={alertID}
          id={alertID}
          request={request}
          canAck={ack}
          onClose={() => {
            setParams({});
            void load();
          }}
          onChanged={() => {
            void load();
            window.dispatchEvent(new Event("jms233-notifications"));
          }}
        />
      )}
    </section>
  );
}
function RuleEditor({
  initial,
  request,
  busy,
  error,
  onSave,
  onClose,
}: {
  initial: Rule;
  request: Requester;
  busy: boolean;
  error: string;
  onSave: (rule: Rule) => Promise<void>;
  onClose: () => void;
}) {
  const { t } = useTranslation(),
    [draft, setDraft] = useState({
      ...initial,
      scope: {
        ...initial.scope,
        asset_ids: initial.scope.asset_ids ?? [],
        node_ids: initial.scope.node_ids ?? [],
      },
    }),
    [assets, setAssets] = useState<Asset[]>([]),
    [nodes, setNodes] = useState<Node[]>([]),
    [targetError, setTargetError] = useState(false),
    [q, setQ] = useState("");
  const dialog = useRef<HTMLDialogElement | null>(null),
    name = useRef<HTMLInputElement | null>(null);
  const [scope, setScope] = useState(
    initial.scope.all ? "all" : initial.scope.asset_ids?.length ? "assets" : "nodes",
  );
  useEffect(() => {
    const current = dialog.current;
    const focus = document.activeElement;
    current?.showModal();
    name.current?.focus();
    const controller = new AbortController();
    void Promise.all([
      request("../assets", "GET", undefined, controller.signal).then((r) => r.json()),
      request("../assets/nodes", "GET", undefined, controller.signal).then((r) => r.json()),
    ])
      .then((results) => {
        if (controller.signal.aborted) return;
        setAssets((results[0] as Asset[]).filter((a) => !a.protocol || a.protocol === "ssh"));
        setNodes(results[1] as Node[]);
      })
      .catch(() => {
        if (!controller.signal.aborted) setTargetError(true);
      });
    return () => {
      controller.abort();
      current?.close();
      if (focus instanceof HTMLElement) focus.focus();
    };
  }, [request]);
  const number = (key: keyof Rule, min: number, max: number) => (
    <label>
      {t(`monitoring.fields.${key}`)}
      <input
        type="number"
        min={min}
        max={max}
        step={key.includes("threshold") ? "any" : 1}
        required
        value={draft[key] as number}
        onChange={(e) => setDraft((d) => ({ ...d, [key]: Number(e.target.value) }))}
      />
    </label>
  );
  const binary = draft.metric === "offline" || draft.metric === "no_data",
    noData = draft.metric === "no_data";
  const changeMetric = (metric: string) =>
    setDraft((d) => ({
      ...d,
      metric,
      ...(metric === "offline" || metric === "no_data"
        ? { threshold: 1, recovery_threshold: 0 }
        : {}),
      ...(metric === "no_data" ? { for_samples: 1, recovery_samples: 1 } : {}),
    }));
  const submit = (e: FormEvent) => {
    e.preventDefault();
    void onSave({
      ...draft,
      scope: {
        all: scope === "all",
        asset_ids: scope === "assets" ? draft.scope.asset_ids : [],
        node_ids: scope === "nodes" ? draft.scope.node_ids : [],
      },
    });
  };
  return (
    <dialog
      ref={dialog}
      className="rotation-dialog monitoring-dialog"
      onCancel={(e) => {
        e.preventDefault();
        if (!busy) onClose();
      }}
      aria-labelledby="monitor-rule-title"
    >
      <form onSubmit={submit}>
        <h2 id="monitor-rule-title">
          {t(initial.id ? "monitoring.editRule" : "monitoring.create")}
        </h2>
        {error && <p role="alert">{t(`monitoring.errors.${error}`)}</p>}
        <label>
          {t("monitoring.name")}
          <input
            ref={name}
            value={draft.name}
            required
            maxLength={120}
            onChange={(e) => setDraft((d) => ({ ...d, name: e.target.value }))}
          />
        </label>
        <label className="monitor-check">
          <input
            type="checkbox"
            checked={draft.enabled}
            onChange={(e) => setDraft((d) => ({ ...d, enabled: e.target.checked }))}
          />
          {t("monitoring.enabled")}
        </label>
        <label>
          {t("monitoring.metric")}
          <select value={draft.metric} onChange={(e) => changeMetric(e.target.value)}>
            {metrics.map((m) => (
              <option key={m} value={m}>
                {t(`monitoring.metrics.${m}`)}
              </option>
            ))}
          </select>
        </label>
        <label>
          {t("monitoring.scope")}
          <select value={scope} onChange={(e) => setScope(e.target.value)}>
            {["all", "assets", "nodes"].map((v) => (
              <option value={v} key={v}>
                {t(`monitoring.scopes.${v}`)}
              </option>
            ))}
          </select>
        </label>
        {scope !== "all" && (
          <fieldset>
            <legend>{t("monitoring.targets")}</legend>
            {targetError && <p role="alert">{t("monitoring.targetError")}</p>}
            <label>
              {t("monitoring.searchTargets")}
              <input value={q} onChange={(e) => setQ(e.target.value)} />
            </label>
            <div className="monitor-targets">
              {(scope === "assets" ? assets : nodes)
                .filter((a) => a.name.toLowerCase().includes(q.toLowerCase()))
                .slice(0, 100)
                .map((a) => {
                  const key = scope === "assets" ? "asset_ids" : "node_ids";
                  return (
                    <label key={a.id} className="monitor-check">
                      <input
                        type="checkbox"
                        checked={draft.scope[key].includes(a.id)}
                        onChange={(e) =>
                          setDraft((d) => ({
                            ...d,
                            scope: {
                              ...d.scope,
                              [key]: e.target.checked
                                ? [...d.scope[key], a.id]
                                : d.scope[key].filter((id) => id !== a.id),
                            },
                          }))
                        }
                      />
                      {a.name}
                    </label>
                  );
                })}
            </div>
            <p>
              {t("monitoring.selected", {
                count: draft.scope.asset_ids.length + draft.scope.node_ids.length,
              })}
            </p>
          </fieldset>
        )}
        <div className="monitor-grid">
          {!binary && (
            <>
              {number("threshold", 0, 1e12)}
              {number("recovery_threshold", 0, 1e12)}
            </>
          )}
          {!noData && (
            <>
              {number("for_samples", 1, 30)}
              {number("recovery_samples", 1, 30)}
            </>
          )}
          {number("for_seconds", 0, 3600)}
          {number("recovery_seconds", 0, 3600)}
          {number("max_age_seconds", 30, 3600)}
          {number("repeat_seconds", 0, 86400)}
        </div>
        <p>{t("monitoring.conditionHint")}</p>
        <div className="rotation-actions">
          <button type="submit" disabled={busy || (scope !== "all" && targetError)}>
            {t("monitoring.save")}
          </button>
          <button type="button" disabled={busy} onClick={onClose}>
            {t("monitoring.cancel")}
          </button>
        </div>
      </form>
    </dialog>
  );
}
function AlertDetail({
  id,
  request,
  canAck,
  onClose,
  onChanged,
}: {
  id: string;
  request: Requester;
  canAck: boolean;
  onClose: () => void;
  onChanged: () => void;
}) {
  const { t, i18n } = useTranslation(),
    [detail, setDetail] = useState<Alert | null>(null),
    [error, setError] = useState(""),
    [comment, setComment] = useState(""),
    [busy, setBusy] = useState(false),
    dialog = useRef<HTMLDialogElement | null>(null),
    reader = useRef<AbortController | null>(null),
    writer = useRef<AbortController | null>(null),
    serial = useRef(0),
    working = useRef(false);
  const cancelRequests = useCallback(() => {
    serial.current++;
    reader.current?.abort();
    writer.current?.abort();
  }, []);
  const load = useCallback(async () => {
    reader.current?.abort();
    const controller = new AbortController();
    reader.current = controller;
    const generation = ++serial.current;
    try {
      const v = (await (
        await request("alerts/" + encodeURIComponent(id), "GET", undefined, controller.signal)
      ).json()) as Alert;
      if (!controller.signal.aborted && generation === serial.current) {
        setDetail(v);
        setError("");
      }
    } catch (e) {
      if (!controller.signal.aborted && generation === serial.current) {
        setDetail(null);
        setError(e instanceof MonitorError ? e.code : "unavailable");
      }
    } finally {
      if (reader.current === controller) reader.current = null;
    }
  }, [id, request]);
  useEffect(() => {
    const current = dialog.current,
      focus = document.activeElement;
    current?.showModal();
    queueMicrotask(() => void load());
    const timer = setInterval(() => {
      if (!working.current && !reader.current && document.visibilityState !== "hidden") void load();
    }, 5000);
    return () => {
      cancelRequests();
      clearInterval(timer);
      current?.close();
      if (focus instanceof HTMLElement) focus.focus();
    };
  }, [load, cancelRequests]);
  const acknowledge = async () => {
    if (!detail || busy) return;
    working.current = true;
    setBusy(true);
    serial.current++;
    reader.current?.abort();
    reader.current = null;
    const controller = new AbortController();
    writer.current = controller;
    const generation = serial.current;
    try {
      const v = (await (
        await request(
          "alerts/" + encodeURIComponent(id) + "/acknowledge",
          "POST",
          {
            revision: detail.revision,
            comment,
          },
          controller.signal,
        )
      ).json()) as Alert;
      if (controller.signal.aborted || generation !== serial.current) return;
      setDetail(v);
      setError("");
      onChanged();
    } catch (e) {
      if (controller.signal.aborted || generation !== serial.current) return;
      if (e instanceof MonitorError && e.code === "conflict") await load();
      if (controller.signal.aborted) return;
      setError(e instanceof MonitorError ? e.code : "unavailable");
    } finally {
      working.current = false;
      if (writer.current === controller) writer.current = null;
      if (!controller.signal.aborted) setBusy(false);
    }
  };
  const date = (value: string) => new Date(value).toLocaleString(i18n.language);
  return (
    <dialog
      ref={dialog}
      className="rotation-dialog monitoring-dialog"
      aria-labelledby="monitor-alert-title"
      onCancel={(e) => {
        e.preventDefault();
        if (!busy) onClose();
      }}
    >
      <h2 id="monitor-alert-title">{t("monitoring.details")}</h2>
      {error && <p role="alert">{t(`monitoring.errors.${error}`)}</p>}
      {detail && (
        <>
          <h3>{detail.asset_name}</h3>
          <dl className="monitor-fields">
            <dt>{t("monitoring.rule")}</dt>
            <dd>{detail.rule_name}</dd>
            <dt>{t("monitoring.metric")}</dt>
            <dd>{t(`monitoring.metrics.${detail.metric}`)}</dd>
            <dt>{t("monitoring.state")}</dt>
            <dd>{t(`monitoring.states.${detail.state}`)}</dd>
            <dt>{t("monitoring.value")}</dt>
            <dd>
              {detail.value?.toLocaleString(i18n.language, { maximumFractionDigits: 2 }) ??
                t("monitoring.noValue")}
            </dd>
            <dt>{t("monitoring.threshold")}</dt>
            <dd>{detail.threshold.toLocaleString(i18n.language)}</dd>
            <dt>{t("monitoring.recovery")}</dt>
            <dd>{detail.recovery_threshold.toLocaleString(i18n.language)}</dd>
            <dt>{t("monitoring.started")}</dt>
            <dd>{date(detail.started_at)}</dd>
            <dt>{t("monitoring.observed")}</dt>
            <dd>{date(detail.last_observed_at)}</dd>
            {detail.ended_at && (
              <>
                <dt>{t("monitoring.ended")}</dt>
                <dd>{date(detail.ended_at)}</dd>
              </>
            )}
            {detail.reason && (
              <>
                <dt>{t("monitoring.reason")}</dt>
                <dd>{t(`monitoring.reasons.${detail.reason}`)}</dd>
              </>
            )}
            {detail.acknowledged_at && (
              <>
                <dt>{t("monitoring.acknowledged")}</dt>
                <dd>
                  {detail.acknowledged_by?.name} · {date(detail.acknowledged_at)}
                </dd>
                <dt>{t("monitoring.comment")}</dt>
                <dd>{detail.comment}</dd>
              </>
            )}
          </dl>
          {canAck && detail.state === "firing" && !detail.acknowledged_at && (
            <form
              onSubmit={(e) => {
                e.preventDefault();
                void acknowledge();
              }}
            >
              <label>
                {t("monitoring.comment")}
                <textarea
                  maxLength={500}
                  value={comment}
                  onChange={(e) => setComment(e.target.value)}
                />
              </label>
              <p>{t("monitoring.ackHint")}</p>
              <button type="submit" disabled={busy}>
                {t("monitoring.acknowledge")}
              </button>
            </form>
          )}
        </>
      )}
      <div className="rotation-actions">
        <button type="button" disabled={busy} onClick={onClose}>
          {t("monitoring.close")}
        </button>
      </div>
    </dialog>
  );
}
