import { useCallback, useEffect, useRef, useState, type FormEvent } from "react";
import { useTranslation } from "react-i18next";
import { usePermissions } from "../auth/usePermissions";

type Asset = { id: string; name: string; username: string };
type Template = {
  id: string;
  name: string;
  command: string;
  timeout_seconds: number;
  revision: number;
};
type Plan = {
  id: string;
  owner_id: string;
  name: string;
  kind: string;
  asset_ids: string[];
  enabled: boolean;
  next_run?: string;
  last_run_id?: string;
  error_code?: string;
};
type Item = {
  asset_id: string;
  job_id?: string;
  state: string;
  review_id?: string;
  error_code?: string;
};
type Run = {
  id: string;
  owner_id: string;
  name: string;
  state: string;
  created_at: string;
  items: Item[];
  cancelled: boolean;
};
type Props = {
  assets: Asset[];
  request: (url: string, init?: RequestInit) => Promise<Response>;
  onJob: (id: string) => void;
};
const isActive = (state: string) => ["running", "waiting_review"].includes(state);

export default function OperationsPanel({ assets, request, onJob }: Props) {
  const { t, i18n } = useTranslation();
  const { allows, userID } = usePermissions();
  const [open, setOpen] = useState(false);
  const [templates, setTemplates] = useState<Template[]>([]);
  const [plans, setPlans] = useState<Plan[]>([]);
  const [planOffset, setPlanOffset] = useState(0);
  const [runs, setRuns] = useState<Run[]>([]);
  const [offset, setOffset] = useState(0);
  const [total, setTotal] = useState(0);
  const [selected, setSelected] = useState<Run | null>(null);
  const [name, setName] = useState("");
  const [targets, setTargets] = useState<string[]>([]);
  const [command, setCommand] = useState("");
  const [timeout, setTimeoutSeconds] = useState(60);
  const [templateID, setTemplateID] = useState("");
  const [kind, setKind] = useState("batch");
  const [runAt, setRunAt] = useState("");
  const [interval, setIntervalSeconds] = useState(3600);
  const [editing, setEditing] = useState<Template | null>(null);
  const [templateName, setTemplateName] = useState("");
  const [templateCommand, setTemplateCommand] = useState("");
  const [templateTimeout, setTemplateTimeout] = useState(60);
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState("");
  const [error, setError] = useState(false);
  const requestID = useRef("");
  const resetID = () => {
    requestID.current = "";
    setMessage("");
  };
  const load = useCallback(
    async (signal?: AbortSignal) => {
      try {
        const responses = await Promise.all([
          request("/api/v1/ops/templates", { signal }),
          request("/api/v1/ops/plans", { signal }),
          request(`/api/v1/ops/runs?limit=50&offset=${offset}`, { signal }),
        ]);
        if (responses.some((r) => !r.ok)) throw new Error("operations unavailable");
        const [templateData, planData, runData] = (await Promise.all(
          responses.map((r) => r.json()),
        )) as [Template[], Plan[], { results: Run[]; total: number }];
        if (signal?.aborted) return;
        setTemplates(templateData);
        setPlans(planData);
        setRuns(runData.results);
        setTotal(runData.total);
        setSelected((previous) =>
          previous ? runData.results.find((run) => run.id === previous.id) || previous : null,
        );
        setError(false);
      } catch {
        if (!signal?.aborted) setError(true);
      }
    },
    [offset, request],
  );
  useEffect(() => {
    if (!open) return;
    const controller = new AbortController();
    queueMicrotask(() => {
      if (!controller.signal.aborted) void load(controller.signal);
    });
    const timer = window.setInterval(() => {
      void load(controller.signal);
    }, 3000);
    return () => {
      controller.abort();
      window.clearInterval(timer);
    };
  }, [load, open]);
  function edit(template: Template | null) {
    setEditing(template);
    setTemplateName(template?.name || "");
    setTemplateCommand(template?.command || "");
    setTemplateTimeout(template?.timeout_seconds || 60);
  }
  async function saveTemplate(event: FormEvent) {
    event.preventDefault();
    setBusy(true);
    setError(false);
    try {
      const response = await request(
        `/api/v1/ops/templates${editing ? `/${encodeURIComponent(editing.id)}` : ""}`,
        {
          method: editing ? "PUT" : "POST",
          body: JSON.stringify({
            name: templateName,
            command: templateCommand,
            timeout_seconds: templateTimeout,
            revision: editing?.revision || 0,
          }),
        },
      );
      if (!response.ok) throw new Error("template save failed");
      edit((await response.json()) as Template);
      setMessage("templateSaved");
      await load();
    } catch {
      setError(true);
    } finally {
      setBusy(false);
    }
  }
  async function removeTemplate() {
    if (!editing || !window.confirm(t("operations.deleteConfirm"))) return;
    setBusy(true);
    try {
      const response = await request(
        `/api/v1/ops/templates/${encodeURIComponent(editing.id)}?revision=${editing.revision}`,
        { method: "DELETE" },
      );
      if (!response.ok) throw new Error("template deletion failed");
      if (templateID === editing.id) {
        setTemplateID("");
        resetID();
      }
      edit(null);
      await load();
    } catch {
      setError(true);
    } finally {
      setBusy(false);
    }
  }
  async function createPlan(event: FormEvent) {
    event.preventDefault();
    setBusy(true);
    setError(false);
    if (!requestID.current) requestID.current = crypto.randomUUID();
    try {
      const body = {
        name,
        asset_ids: targets,
        kind,
        request_id: requestID.current,
        ...(templateID ? { template_id: templateID } : { command, timeout_seconds: timeout }),
        ...(kind !== "batch" && runAt ? { run_at: new Date(runAt).toISOString() } : {}),
        ...(kind === "interval" ? { interval_seconds: interval } : {}),
      };
      const response = await request("/api/v1/ops/plans", {
        method: "POST",
        body: JSON.stringify(body),
      });
      if (!response.ok) throw new Error("plan creation failed");
      requestID.current = "";
      setMessage("planCreated");
      await load();
    } catch {
      setError(true);
    } finally {
      setBusy(false);
    }
  }
  async function toggle(plan: Plan) {
    setBusy(true);
    try {
      const response = await request(`/api/v1/ops/plans/${encodeURIComponent(plan.id)}`, {
        method: "PUT",
        body: JSON.stringify({ enabled: !plan.enabled }),
      });
      if (!response.ok) throw new Error("plan update failed");
      await load();
    } catch {
      setError(true);
    } finally {
      setBusy(false);
    }
  }
  async function cancel(run: Run) {
    setBusy(true);
    try {
      const response = await request(`/api/v1/ops/runs/${encodeURIComponent(run.id)}/cancel`, {
        method: "POST",
      });
      if (!response.ok) throw new Error("run cancellation failed");
      await load();
    } catch {
      setError(true);
    } finally {
      setBusy(false);
    }
  }
  const time = (value?: string) => (value ? new Date(value).toLocaleString(i18n.language) : "—");
  return (
    <details className="operations-panel" onToggle={(event) => setOpen(event.currentTarget.open)}>
      <summary>{t("operations.title")}</summary>
      {open && (
        <div>
          <p>{t("operations.description")}</p>
          {error && (
            <p role="alert" className="login-error">
              {t("operations.error")}
            </p>
          )}
          {message && <p role="status">{t(`operations.${message}`)}</p>}
          <details className="operations-templates">
            <summary>{t("operations.templates")}</summary>
            <label>
              {t("operations.editTemplate")}
              <select
                value={editing?.id || ""}
                onChange={(event) =>
                  edit(templates.find((item) => item.id === event.target.value) || null)
                }
              >
                <option value="">{t("operations.newTemplate")}</option>
                {templates.map((item) => (
                  <option key={item.id} value={item.id}>
                    {item.name} · v{item.revision}
                  </option>
                ))}
              </select>
            </label>
            <form
              className="operations-form"
              onSubmit={(event) => {
                void saveTemplate(event);
              }}
            >
              <label>
                {t("operations.templateName")}
                <input
                  required
                  maxLength={100}
                  value={templateName}
                  onChange={(event) => setTemplateName(event.target.value)}
                />
              </label>
              <label>
                {t("operations.templateCommand")}
                <input
                  required
                  maxLength={8192}
                  value={templateCommand}
                  onChange={(event) => setTemplateCommand(event.target.value)}
                  autoComplete="off"
                  spellCheck={false}
                />
              </label>
              <label>
                {t("operations.templateTimeout")}
                <input
                  type="number"
                  required
                  min={1}
                  max={300}
                  value={templateTimeout}
                  onChange={(event) => setTemplateTimeout(Number(event.target.value))}
                />
              </label>
              <div>
                <button type="submit" disabled={busy}>
                  {t("operations.saveTemplate")}
                </button>
                {editing && (
                  <button
                    type="button"
                    disabled={busy}
                    onClick={() => {
                      void removeTemplate();
                    }}
                  >
                    {t("operations.deleteTemplate")}
                  </button>
                )}
              </div>
            </form>
          </details>
          <form
            className="operations-form"
            onSubmit={(event) => {
              void createPlan(event);
            }}
          >
            <label>
              {t("operations.name")}
              <input
                required
                maxLength={100}
                value={name}
                onChange={(event) => {
                  setName(event.target.value);
                  resetID();
                }}
              />
            </label>
            <fieldset className="operations-targets">
              <legend>{t("operations.targets")}</legend>
              {assets.map((asset) => (
                <label key={asset.id}>
                  <input
                    type="checkbox"
                    checked={targets.includes(asset.id)}
                    onChange={(event) => {
                      setTargets((previous) =>
                        event.target.checked
                          ? [...previous, asset.id]
                          : previous.filter((id) => id !== asset.id),
                      );
                      resetID();
                    }}
                  />
                  {asset.name} ({asset.username})
                </label>
              ))}
              {assets.length === 0 && <p>{t("jobs.noAssets")}</p>}
            </fieldset>
            <label>
              {t("operations.useTemplate")}
              <select
                value={templateID}
                onChange={(event) => {
                  setTemplateID(event.target.value);
                  resetID();
                }}
              >
                <option value="">{t("operations.customCommand")}</option>
                {templates.map((item) => (
                  <option key={item.id} value={item.id}>
                    {item.name} · v{item.revision}
                  </option>
                ))}
              </select>
            </label>
            {!templateID && (
              <>
                <label>
                  {t("operations.command")}
                  <input
                    required
                    maxLength={8192}
                    value={command}
                    onChange={(event) => {
                      setCommand(event.target.value);
                      resetID();
                    }}
                    autoComplete="off"
                    spellCheck={false}
                  />
                </label>
                <label>
                  {t("operations.timeout")}
                  <input
                    required
                    type="number"
                    min={1}
                    max={300}
                    value={timeout}
                    onChange={(event) => {
                      setTimeoutSeconds(Number(event.target.value));
                      resetID();
                    }}
                  />
                </label>
              </>
            )}
            <label>
              {t("operations.kind")}
              <select
                value={kind}
                onChange={(event) => {
                  setKind(event.target.value);
                  setRunAt("");
                  resetID();
                }}
              >
                <option value="batch">{t("operations.kinds.batch")}</option>
                <option value="once">{t("operations.kinds.once")}</option>
                <option value="interval">{t("operations.kinds.interval")}</option>
              </select>
            </label>
            {kind !== "batch" && (
              <label>
                {t("operations.runAt")}
                <input
                  type="datetime-local"
                  step={1}
                  required={kind === "once"}
                  value={runAt}
                  onChange={(event) => {
                    setRunAt(event.target.value);
                    resetID();
                  }}
                />
              </label>
            )}
            {kind === "interval" && (
              <label>
                {t("operations.interval")}
                <input
                  type="number"
                  required
                  min={60}
                  max={2678400}
                  value={interval}
                  onChange={(event) => {
                    setIntervalSeconds(Number(event.target.value));
                    resetID();
                  }}
                />
              </label>
            )}
            <button type="submit" disabled={busy || targets.length < 1 || targets.length > 50}>
              {t("operations.create")}
            </button>
          </form>
          <h2>{t("operations.plans")}</h2>
          <div className="jobs-table-scroll">
            <table className="jobs-table">
              <thead>
                <tr>
                  <th>{t("operations.name")}</th>
                  <th>{t("operations.kind")}</th>
                  <th>{t("operations.nextRun")}</th>
                  <th>{t("jobs.status")}</th>
                  <th>{t("jobs.actions")}</th>
                </tr>
              </thead>
              <tbody>
                {plans.slice(planOffset, planOffset + 50).map((plan) => (
                  <tr key={plan.id}>
                    <td>{plan.name}</td>
                    <td>{t(`operations.kinds.${plan.kind}`)}</td>
                    <td>{time(plan.next_run)}</td>
                    <td>
                      {t(plan.enabled ? "operations.enabled" : "operations.paused")}
                      {plan.error_code && <p>{t(`operations.errors.${plan.error_code}`)}</p>}
                    </td>
                    <td>
                      {(plan.owner_id === userID || allows("plans.manage_all")) &&
                        plan.kind !== "batch" &&
                        !(plan.kind === "once" && plan.last_run_id) && (
                          <button
                            type="button"
                            disabled={busy}
                            onClick={() => {
                              void toggle(plan);
                            }}
                          >
                            {t(plan.enabled ? "operations.pause" : "operations.resume")}
                          </button>
                        )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <nav className="jobs-pagination" aria-label={t("operations.planPages")}>
            <button
              type="button"
              disabled={!planOffset}
              onClick={() => setPlanOffset(Math.max(0, planOffset - 50))}
            >
              {t("jobs.previous")}
            </button>
            <span>{t("operations.planCount", { count: plans.length })}</span>
            <button
              type="button"
              disabled={planOffset + 50 >= plans.length}
              onClick={() => setPlanOffset(planOffset + 50)}
            >
              {t("jobs.next")}
            </button>
          </nav>
          <h2>{t("operations.runs")}</h2>
          <div className="jobs-table-scroll">
            <table className="jobs-table">
              <thead>
                <tr>
                  <th>{t("operations.name")}</th>
                  <th>{t("jobs.created")}</th>
                  <th>{t("jobs.status")}</th>
                  <th>{t("jobs.actions")}</th>
                </tr>
              </thead>
              <tbody>
                {runs.map((run) => (
                  <tr key={run.id}>
                    <td>{run.name}</td>
                    <td>{time(run.created_at)}</td>
                    <td>{t(`operations.states.${run.state}`)}</td>
                    <td>
                      <button type="button" onClick={() => setSelected(run)}>
                        {t("jobs.details")}
                      </button>
                      {isActive(run.state) &&
                        (run.owner_id === userID || allows("plans.manage_all")) && (
                          <button
                            type="button"
                            disabled={busy}
                            onClick={() => {
                              void cancel(run);
                            }}
                          >
                            {t("operations.cancel")}
                          </button>
                        )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <div className="jobs-pagination">
            <button
              type="button"
              disabled={!offset}
              onClick={() => setOffset(Math.max(0, offset - 50))}
            >
              {t("jobs.previous")}
            </button>
            <span>{t("operations.count", { count: total })}</span>
            <button
              type="button"
              disabled={offset + 50 >= total}
              onClick={() => setOffset(offset + 50)}
            >
              {t("jobs.next")}
            </button>
          </div>
          {selected && (
            <section aria-label={t("operations.runDetail")} className="jobs-detail">
              <header>
                <h3>{selected.name}</h3>
                <button type="button" onClick={() => setSelected(null)}>
                  {t("jobs.close")}
                </button>
              </header>
              <p>{t(`operations.states.${selected.state}`)}</p>
              <ul>
                {selected.items.map((item) => (
                  <li key={item.asset_id}>
                    {assets.find((asset) => asset.id === item.asset_id)?.name || item.asset_id} ·{" "}
                    {t(`operations.states.${item.state}`)}
                    {item.error_code && (
                      <p>
                        {t(`operations.errors.${item.error_code}`, {
                          defaultValue: t("operations.dispatchError"),
                        })}
                      </p>
                    )}
                    {item.review_id && (
                      <p>
                        {t("operations.loginReview")} <code>{item.review_id}</code>
                      </p>
                    )}
                    {item.job_id && (
                      <button type="button" onClick={() => onJob(item.job_id!)}>
                        {t("operations.openJob")}
                      </button>
                    )}
                  </li>
                ))}
              </ul>
            </section>
          )}
        </div>
      )}
    </details>
  );
}
