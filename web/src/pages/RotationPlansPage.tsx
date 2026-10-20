import { useCallback, useEffect, useRef, useState, type ReactNode, type FormEvent } from "react";
import { useTranslation } from "react-i18next";
import { useLocation } from "react-router-dom";
import { useAuth } from "../auth/AuthContext";
import { usePermissions } from "../auth/usePermissions";
import "../i18n/locales/features/rotation-plans/register";
import "./rotation-plans.css";
import SSHPasswordPolicy from "../components/SSHPasswordPolicy";
import SSHPasswordRuleFields, {
  inheritedPasswordRules,
  type SSHPasswordRules,
} from "../components/SSHPasswordRuleFields";

type Ref = {
  asset_id: string;
  account_id: string;
  asset_name: string;
  username: string;
  credential_type: string;
  collector_id?: string;
  collector_username?: string;
};
type Actor = { id: string; name: string };
type Plan = {
  id: string;
  name: string;
  owner: Actor;
  kind: string;
  enabled: boolean;
  interval_hours?: number;
  run_at?: string;
  only_due: boolean;
  password_mode?: string;
  password_policy?: SSHPasswordRules;
  revision: number;
  target_count: number;
  targets?: { account_id: string; collector_id?: string }[];
  accounts?: Ref[];
  next_run?: string;
  last_run_id?: string;
  error_code?: string;
};
type Item = Ref & {
  source_item_id?: string;
  retry_run_id?: string;
  id: string;
  state: string;
  error_code?: string;
  linked_to?: string;
  before_revision: number;
  after_revision?: number;
  finished_at?: string;
};
type Run = {
  parent_run_id?: string;
  id: string;
  plan_id: string;
  password_mode?: string;
  password_policy?: SSHPasswordRules;
  name: string;
  owner: Actor;
  request_id: string;
  state: string;
  scheduled: boolean;
  cancelled: boolean;
  created_at: string;
  finished_at?: string;
  total?: number;
  succeeded?: number;
  failed?: number;
  items?: Item[];
};
type Audit = { at: string; actor: Actor; action: string; plan_id: string; run_id?: string };
type Page<T> = { results: T[]; total: number };
type Draft = {
  id: string;
  revision: number;
  name: string;
  kind: string;
  enabled: boolean;
  runAt: string;
  hours: number;
  onlyDue: boolean;
  passwordPolicy: SSHPasswordRules | null;
  passwordMode: string;
  fixedPassword: string;
  fixedConfigured: boolean;
  accounts: Record<string, Ref>;
};
type Confirm = {
  mode: "run" | "delete" | "cancel" | "recover" | "retry";
  id: string;
  name: string;
  revision?: number;
  itemIDs?: string[];
  requestID?: string;
  plan?: Plan;
};
const newRequestID = () =>
  Array.from(crypto.getRandomValues(new Uint8Array(16)), (value) =>
    value.toString(16).padStart(2, "0"),
  ).join("");
const empty = <T,>(): Page<T> => ({ results: [], total: 0 });
const active = (state: string) => ["queued", "running", "recovery_required"].includes(state);
const retryable = (item: Item) =>
  !item.retry_run_id &&
  ["failed", "denied", "changed", "cancelled", "interrupted"].includes(item.state);
const codes = new Set([
  "invalid",
  "denied",
  "not_found",
  "conflict",
  "busy",
  "capacity",
  "unavailable",
]);
class RotationError extends Error {
  constructor(readonly code: string) {
    super(code);
  }
}
function Modal({
  title,
  children,
  close,
  busy,
}: {
  title: string;
  children: ReactNode;
  close: () => void;
  busy: boolean;
}) {
  const ref = useRef<HTMLDialogElement>(null);
  useEffect(() => {
    const dialog = ref.current;
    dialog?.showModal();
    return () => {
      dialog?.close();
    };
  }, []);
  return (
    <dialog
      className="rotation-dialog"
      ref={ref}
      aria-label={title}
      onCancel={(event) => {
        if (busy) event.preventDefault();
        else close();
      }}
    >
      <h2>{title}</h2>
      {children}
    </dialog>
  );
}
export default function RotationPlansPage() {
  const { search: notificationSearch } = useLocation();
  const { t, i18n } = useTranslation();
  const { accessToken } = useAuth();
  const { ready, allows, userID } = usePermissions();
  const view = allows("accounts.rotation.view") && allows("assets.view_all");
  const manage = allows("accounts.rotation.manage"),
    all = allows("accounts.rotation.manage_all");
  const execute = allows("accounts.rotation.execute") && allows("assets.rotate");
  const privileged = allows("accounts.rotation.privileged"),
    fixedAllowed = allows("accounts.rotation.fixed_password");
  const saveRequests = useRef(new WeakMap<Draft, string>());
  const life = useRef<AbortController | null>(null),
    pending = useRef<{ plan: string; request: string } | null>(null);
  const [plans, setPlans] = useState<Page<Plan>>(empty),
    [runs, setRuns] = useState<Page<Run>>(empty),
    [audit, setAudit] = useState<Page<Audit>>(empty);
  const [tab, setTab] = useState("plans"),
    [offset, setOffset] = useState(0),
    [epoch, setEpoch] = useState(0);
  const [draft, setDraft] = useState<Draft | null>(null),
    [selectedRun, setSelectedRun] = useState<Run | null>(null),
    [itemOffset, setItemOffset] = useState(0);
  const [candidates, setCandidates] = useState<Page<Ref>>(empty),
    [candidateOffset, setCandidateOffset] = useState(0),
    [search, setSearch] = useState(""),
    [query, setQuery] = useState("");
  const [collectorFor, setCollectorFor] = useState<Ref | null>(null),
    [collectors, setCollectors] = useState<Page<Ref>>(empty),
    [collectorOffset, setCollectorOffset] = useState(0),
    [collectorSearch, setCollectorSearch] = useState(""),
    [collectorQuery, setCollectorQuery] = useState("");
  const [confirm, setConfirm] = useState<Confirm | null>(null),
    [busy, setBusy] = useState(false),
    [error, setError] = useState(""),
    [notice, setNotice] = useState("");
  useEffect(() => {
    life.current = new AbortController();
    return () => {
      life.current?.abort();
      saveRequests.current = new WeakMap();
    };
  }, []);
  const request = useCallback(
    async (path: string, init?: RequestInit) => {
      const headers = new Headers(init?.headers);
      if (accessToken) headers.set("Authorization", `Bearer ${accessToken}`);
      if (init?.body) headers.set("Content-Type", "application/json");
      const signals = [AbortSignal.timeout(65_000)];
      if (life.current) signals.push(life.current.signal);
      if (init?.signal) signals.push(init.signal);
      const result = await fetch(`/api/v1/accounts/rotation-${path}`, {
        ...init,
        headers,
        signal: AbortSignal.any(signals),
      });
      if (!result.ok) {
        let code = result.status === 403 ? "denied" : "unavailable";
        try {
          code = (await result.json()).error_code || code;
        } catch {
          /* Status fallback. */
        }
        throw new RotationError(codes.has(code) ? code : "unavailable");
      }
      return result;
    },
    [accessToken],
  );
  const fail = useCallback((e: unknown) => {
    if (!life.current?.signal.aborted)
      setError(e instanceof RotationError ? e.code : "unavailable");
  }, []);
  const load = useCallback(
    async (signal: AbortSignal) => {
      if (!view) return;
      try {
        const path = tab === "plans" ? "plans" : tab === "runs" ? "runs" : "audit";
        const data = await request(`${path}?offset=${offset}&limit=20`, { signal }).then((r) =>
          r.json(),
        );
        if (signal.aborted) return;
        if (tab === "plans") setPlans(data);
        else if (tab === "runs") setRuns(data);
        else setAudit(data);
      } catch (e) {
        if (!signal.aborted) fail(e);
      }
    },
    [view, tab, offset, request, fail],
  );
  useEffect(() => {
    const controller = new AbortController();
    queueMicrotask(() => void load(controller.signal));
    return () => controller.abort();
  }, [load, epoch]);
  const editing = draft !== null;
  useEffect(() => {
    if (!editing || !view) return;
    const controller = new AbortController();
    void request(`targets?offset=${candidateOffset}&limit=25&q=${encodeURIComponent(query)}`, {
      signal: controller.signal,
    })
      .then((r) => r.json())
      .then((data) => {
        if (!controller.signal.aborted) setCandidates(data);
      })
      .catch((e) => {
        if (!controller.signal.aborted) fail(e);
      });
    return () => controller.abort();
  }, [editing, view, candidateOffset, query, request, fail]);
  const collectorID = collectorFor?.account_id;
  useEffect(() => {
    const id = new URLSearchParams(notificationSearch).get("run");
    if (!id || !/^[A-Za-z0-9_-]{1,128}$/.test(id) || !view) return;
    const controller = new AbortController();
    void request(`runs/${encodeURIComponent(id)}`, { signal: controller.signal })
      .then((r) => r.json())
      .then((v) => {
        if (!controller.signal.aborted) setSelectedRun(v);
      })
      .catch((e) => {
        if (!controller.signal.aborted) fail(e);
      });
    return () => controller.abort();
  }, [notificationSearch, view, request, fail]);
  useEffect(() => {
    if (!collectorID) return;
    const controller = new AbortController();
    void request(
      `targets?collector_for=${encodeURIComponent(collectorID)}&offset=${collectorOffset}&limit=25&q=${encodeURIComponent(collectorQuery)}`,
      { signal: controller.signal },
    )
      .then((r) => r.json())
      .then((data) => {
        if (!controller.signal.aborted) setCollectors(data);
      })
      .catch((e) => {
        if (!controller.signal.aborted) fail(e);
      });
    return () => controller.abort();
  }, [collectorID, collectorOffset, collectorQuery, request, fail]);
  const runID = selectedRun?.id,
    runActive = selectedRun ? active(selectedRun.state) : false;
  useEffect(() => {
    if (!runID || !runActive || !view) return;
    const controller = new AbortController();
    let timer: ReturnType<typeof setTimeout>;
    const poll = async () => {
      try {
        const next: Run = await request(`runs/${encodeURIComponent(runID)}`, {
          signal: controller.signal,
        }).then((r) => r.json());
        if (controller.signal.aborted) return;
        setSelectedRun(next);
        if (active(next.state))
          timer = setTimeout(() => void poll(), next.state === "recovery_required" ? 5000 : 1000);
        else setEpoch((v) => v + 1);
      } catch (e) {
        if (!controller.signal.aborted) {
          fail(e);
          timer = setTimeout(() => void poll(), 5000);
        }
      }
    };
    timer = setTimeout(() => void poll(), 700);
    return () => {
      controller.abort();
      clearTimeout(timer);
    };
  }, [runID, runActive, view, request, fail]);
  const date = (value?: string) =>
    value ? new Date(value).toLocaleString(i18n.language) : t("rotationPlans.none");
  const state = (value: string) =>
    t(`rotationPlans.states.${value}`, { defaultValue: t("rotationPlans.attention") });
  function pages(total: number, start: number, set: (value: number) => void, size = 20) {
    return (
      <div className="rotation-actions">
        <button
          type="button"
          disabled={busy || start === 0}
          onClick={() => set(Math.max(0, start - size))}
        >
          {t("rotationPlans.previous")}
        </button>
        <span>
          {t("rotationPlans.page", {
            from: total ? start + 1 : 0,
            to: Math.min(start + size, total),
            total,
          })}
        </span>
        <button
          type="button"
          disabled={busy || start + size >= total}
          onClick={() => set(start + size)}
        >
          {t("rotationPlans.next")}
        </button>
      </div>
    );
  }
  async function action(fn: () => Promise<void>) {
    setBusy(true);
    setError("");
    setNotice("");
    try {
      await fn();
    } catch (e) {
      fail(e);
    } finally {
      if (!life.current?.signal.aborted) setBusy(false);
    }
  }
  async function edit(plan?: Plan) {
    await action(async () => {
      const full: Plan | undefined = plan
        ? await request(`plans/${encodeURIComponent(plan.id)}`).then((r) => r.json())
        : undefined;
      setDraft({
        id: full?.id || "",
        revision: full?.revision || 0,
        name: full?.name || "",
        kind: full?.kind || "manual",
        enabled: full?.enabled || false,
        runAt: full?.run_at
          ? new Date(
              new Date(full.run_at).getTime() - new Date(full.run_at).getTimezoneOffset() * 60000,
            )
              .toISOString()
              .slice(0, 16)
          : "",
        hours: full?.interval_hours || 168,
        onlyDue: full?.only_due ?? true,
        passwordPolicy: full?.password_policy || null,
        passwordMode: full?.password_mode || "generated",
        fixedPassword: "",
        fixedConfigured: full?.password_mode === "fixed",
        accounts: Object.fromEntries((full?.accounts || []).map((v) => [v.account_id, v])),
      });
      setSearch("");
      setQuery("");
      setCandidateOffset(0);
      setCandidates(empty());
    });
  }
  function select(ref: Ref, checked: boolean) {
    setDraft((old) => {
      if (!old) return old;
      const accounts = { ...old.accounts };
      if (checked) {
        if (Object.keys(accounts).length >= 500) return old;
        accounts[ref.account_id] = ref;
      } else delete accounts[ref.account_id];
      return { ...old, accounts };
    });
  }
  async function save(event: FormEvent) {
    event.preventDefault();
    if (!draft) return;
    const current = draft;
    await action(async () => {
      let requestID = saveRequests.current.get(current);
      if (!requestID) {
        requestID = newRequestID();
        saveRequests.current.set(current, requestID);
      }
      const body = {
        request_id: requestID,
        password_mode: current.passwordMode,
        ...(current.passwordMode === "fixed" && current.fixedPassword
          ? { fixed_password: current.fixedPassword }
          : {}),
        name: current.name,
        revision: current.revision,
        kind: current.kind,
        enabled: current.kind !== "manual" && current.enabled,
        interval_hours: current.kind === "interval" ? current.hours : 0,
        only_due: current.kind === "interval" && current.onlyDue,
        ...(current.passwordPolicy ? { password_policy: current.passwordPolicy } : {}),
        ...(current.kind === "once" ? { run_at: new Date(current.runAt).toISOString() } : {}),
        targets: Object.values(current.accounts).map((v) => ({
          account_id: v.account_id,
          ...(v.collector_id ? { collector_id: v.collector_id } : {}),
        })),
      };
      await request(`plans${current.id ? "/" + encodeURIComponent(current.id) : ""}`, {
        method: current.id ? "PUT" : "POST",
        body: JSON.stringify(body),
      }).then((response) => response.json());
      if (life.current?.signal.aborted) return;
      saveRequests.current = new WeakMap();
      setDraft(null);
      setNotice("saved");
      setOffset(0);
      setEpoch((v) => v + 1);
    });
  }
  async function showRun(id: string) {
    await action(async () => {
      const data = await request(`runs/${encodeURIComponent(id)}`).then((r) => r.json());
      if (!life.current?.signal.aborted) {
        setSelectedRun(data);
        setItemOffset(0);
      }
    });
  }
  async function confirmed() {
    if (!confirm) return;
    const next = confirm;
    await action(async () => {
      if (next.mode === "run") {
        if (pending.current?.plan !== next.id)
          pending.current = { plan: next.id, request: newRequestID() };
        const data = await request(`plans/${encodeURIComponent(next.id)}/runs`, {
          method: "POST",
          body: JSON.stringify({ request_id: pending.current.request }),
        }).then((r) => r.json());
        pending.current = null;
        setSelectedRun(data);
        setItemOffset(0);
      } else if (next.mode === "retry") {
        const data = await request(`runs/${encodeURIComponent(next.id)}/retry`, {
          method: "POST",
          body: JSON.stringify({
            request_id: next.requestID,
            plan_revision: next.revision,
            ...(next.itemIDs ? { item_ids: next.itemIDs } : {}),
          }),
        }).then((r) => r.json());
        if (life.current?.signal.aborted) return;
        setSelectedRun(data);
        setItemOffset(0);
      } else if (next.mode === "delete")
        await request(`plans/${encodeURIComponent(next.id)}?revision=${next.revision}`, {
          method: "DELETE",
        });
      else await request(`runs/${encodeURIComponent(next.id)}/${next.mode}`, { method: "POST" });
      if (life.current?.signal.aborted) return;
      setConfirm(null);
      setNotice(
        next.mode === "recover"
          ? "recoveryRequested"
          : next.mode === "cancel"
            ? "cancelRequested"
            : next.mode === "delete"
              ? "deleted"
              : "submitted",
      );
      setEpoch((v) => v + 1);
    });
  }
  async function prepareRetry(itemIDs?: string[]) {
    if (!selectedRun) return;
    const run = selectedRun;
    await action(async () => {
      const plan: Plan = await request(`plans/${encodeURIComponent(run.plan_id)}`).then((r) =>
        r.json(),
      );
      if (plan.password_mode === "fixed" && !fixedAllowed) throw new RotationError("denied");
      if (!life.current?.signal.aborted)
        setConfirm({
          mode: "retry",
          id: run.id,
          name: plan.name,
          revision: plan.revision,
          itemIDs,
          requestID: newRequestID(),
          plan,
        });
    });
  }
  async function exportRun(id: string) {
    await action(async () => {
      const blob = await request(`runs/${encodeURIComponent(id)}/export`).then((r) => r.blob());
      if (life.current?.signal.aborted) return;
      const url = URL.createObjectURL(blob),
        a = document.createElement("a");
      a.href = url;
      a.download = "credential-rotation.csv";
      a.click();
      setTimeout(() => URL.revokeObjectURL(url), 1000);
    });
  }
  const closeEditor = () => {
    saveRequests.current = new WeakMap();
    setDraft(null);
    setCollectorFor(null);
  };
  if (!ready) return <p role="status">{t("placeholder.skeleton")}</p>;
  if (!view)
    return (
      <>
        <SSHPasswordPolicy
          view={allows("accounts.password_policy.view")}
          manage={allows("accounts.password_policy.manage")}
        />
        <p role="alert">{t("rotationPlans.noView")}</p>
      </>
    );
  const total = tab === "plans" ? plans.total : tab === "runs" ? runs.total : audit.total;
  return (
    <section className="rotation-page" aria-labelledby="rotation-title">
      <header>
        <div>
          <h1 id="rotation-title">{t("rotationPlans.title")}</h1>
          <p className="settings-help">{t("rotationPlans.hint")}</p>
        </div>
        <div className="rotation-actions">
          <button
            type="button"
            disabled={busy}
            onClick={() => {
              setError("");
              setEpoch((v) => v + 1);
            }}
          >
            {t("rotationPlans.refresh")}
          </button>
          {manage && (
            <button
              className="button-primary"
              type="button"
              disabled={busy}
              onClick={() => void edit()}
            >
              {t("rotationPlans.create")}
            </button>
          )}
        </div>
      </header>
      <p className="settings-help">{t("rotationPlans.coverage")}</p>
      <SSHPasswordPolicy
        view={allows("accounts.password_policy.view")}
        manage={allows("accounts.password_policy.manage")}
      />
      {error && (
        <p role="alert" className="asset-error">
          {t(`rotationPlans.errors.${error}`)}
        </p>
      )}
      {notice && <p role="status">{t(`rotationPlans.${notice}`)}</p>}
      <nav className="rotation-actions" aria-label={t("rotationPlans.sections")}>
        {["plans", "runs", "audit"].map((value) => (
          <button
            type="button"
            key={value}
            aria-current={tab === value ? "page" : undefined}
            disabled={busy}
            onClick={() => {
              setTab(value);
              setOffset(0);
            }}
          >
            {t(`rotationPlans.${value}`)}
          </button>
        ))}
      </nav>
      <div
        className="rotation-table"
        tabIndex={0}
        role="region"
        aria-label={t(`rotationPlans.${tab}`)}
      >
        {tab === "plans" ? (
          <table>
            <thead>
              <tr>
                {["name", "schedule", "accounts", "owner", "nextRun", "actions"].map((key) => (
                  <th key={key}>{t(`rotationPlans.${key}`)}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {plans.results.map((p) => (
                <tr key={p.id}>
                  <td>
                    <strong>{p.name}</strong>
                    <small>{t("rotationPlans.revision", { count: p.revision })}</small>
                    <small>
                      {t(
                        p.password_mode === "fixed"
                          ? "rotationPlans.fixedMode"
                          : "rotationPlans.generatedMode",
                      )}
                    </small>
                    {p.error_code && (
                      <small>
                        {t(
                          `rotationPlans.errors.${codes.has(p.error_code) ? p.error_code : "unavailable"}`,
                        )}
                      </small>
                    )}
                  </td>
                  <td>
                    {t(`rotationPlans.kinds.${p.kind}`)}
                    {p.kind === "interval" && (
                      <small>{t("rotationPlans.every", { hours: p.interval_hours })}</small>
                    )}
                    {p.kind !== "manual" && (
                      <small>{t(`rotationPlans.${p.enabled ? "enabled" : "disabled"}`)}</small>
                    )}
                  </td>
                  <td>{p.target_count}</td>
                  <td>{p.owner.name}</td>
                  <td>{date(p.next_run)}</td>
                  <td>
                    <div className="rotation-actions">
                      {execute &&
                        (p.password_mode !== "fixed" || fixedAllowed) &&
                        (all || p.owner.id === userID) && (
                          <button
                            disabled={busy}
                            type="button"
                            onClick={() => setConfirm({ mode: "run", id: p.id, name: p.name })}
                          >
                            {t("rotationPlans.run")}
                          </button>
                        )}
                      {manage && (all || p.owner.id === userID) && (
                        <>
                          <button
                            disabled={busy || (p.password_mode === "fixed" && !fixedAllowed)}
                            type="button"
                            onClick={() => void edit(p)}
                          >
                            {t("rotationPlans.edit")}
                          </button>
                          <button
                            disabled={busy}
                            type="button"
                            onClick={() =>
                              setConfirm({
                                mode: "delete",
                                id: p.id,
                                name: p.name,
                                revision: p.revision,
                              })
                            }
                          >
                            {t("rotationPlans.delete")}
                          </button>
                        </>
                      )}
                      {p.last_run_id && (
                        <button
                          disabled={busy}
                          type="button"
                          onClick={() => void showRun(p.last_run_id!)}
                        >
                          {t("rotationPlans.lastRun")}
                        </button>
                      )}
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        ) : tab === "runs" ? (
          <table>
            <thead>
              <tr>
                {["name", "state", "owner", "createdAt", "result", "actions"].map((key) => (
                  <th key={key}>{t(`rotationPlans.${key}`)}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {runs.results.map((r) => (
                <tr key={r.id}>
                  <td>
                    {r.name}
                    <small>{r.id}</small>
                  </td>
                  <td>{state(r.state)}</td>
                  <td>{r.owner.name}</td>
                  <td>{date(r.created_at)}</td>
                  <td>
                    {t("rotationPlans.counts", {
                      total: r.total,
                      succeeded: r.succeeded,
                      failed: r.failed,
                    })}
                  </td>
                  <td>
                    <button disabled={busy} type="button" onClick={() => void showRun(r.id)}>
                      {t("rotationPlans.details")}
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        ) : (
          <table>
            <thead>
              <tr>
                {["createdAt", "owner", "action", "plan"].map((key) => (
                  <th key={key}>{t(`rotationPlans.${key}`)}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {audit.results.map((a, i) => (
                <tr key={`${a.at}-${i}`}>
                  <td>{date(a.at)}</td>
                  <td>{a.actor.name}</td>
                  <td>
                    {t(`rotationPlans.auditActions.${a.action}`, {
                      defaultValue: t("rotationPlans.attention"),
                    })}
                  </td>
                  <td>
                    {a.plan_id}
                    {a.run_id && (
                      <button type="button" onClick={() => void showRun(a.run_id!)}>
                        {t("rotationPlans.details")}
                      </button>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
      {!total && <p>{t("rotationPlans.empty")}</p>}
      {pages(total, offset, setOffset)}
      {draft && (
        <Modal
          title={t(draft.id ? "rotationPlans.edit" : "rotationPlans.create")}
          close={closeEditor}
          busy={busy}
        >
          <form onSubmit={(event) => void save(event)}>
            <fieldset disabled={busy} className="rotation-fields">
              <legend>{t("rotationPlans.configuration")}</legend>
              <label>
                {t("rotationPlans.name")}
                <input
                  required
                  maxLength={120}
                  value={draft.name}
                  onChange={(e) => setDraft({ ...draft, name: e.target.value })}
                />
              </label>
              <label>
                {t("rotationPlans.schedule")}
                <select
                  aria-label={t("rotationPlans.schedule")}
                  value={draft.kind}
                  onChange={(e) => setDraft({ ...draft, kind: e.target.value, enabled: false })}
                >
                  {["manual", "once", "interval"].map((v) => (
                    <option value={v} key={v}>
                      {t(`rotationPlans.kinds.${v}`)}
                    </option>
                  ))}
                </select>
              </label>
              {draft.kind === "once" && (
                <label>
                  {t("rotationPlans.runAt")}
                  <input
                    type="datetime-local"
                    required
                    value={draft.runAt}
                    onChange={(e) => setDraft({ ...draft, runAt: e.target.value })}
                  />
                </label>
              )}
              {draft.kind === "interval" && (
                <>
                  <label>
                    {t("rotationPlans.interval")}
                    <input
                      type="number"
                      required
                      min={1}
                      max={8760}
                      value={draft.hours}
                      onChange={(e) => setDraft({ ...draft, hours: Number(e.target.value) })}
                    />
                  </label>
                  <label className="rotation-check">
                    <input
                      type="checkbox"
                      checked={draft.onlyDue}
                      onChange={(e) => setDraft({ ...draft, onlyDue: e.target.checked })}
                    />
                    {t("rotationPlans.onlyDue")}
                  </label>
                </>
              )}
              <fieldset className="rotation-password-policy">
                <legend>{t("rotationPlans.passwordMode")}</legend>
                <label>
                  {t("rotationPlans.passwordMode")}
                  <select
                    aria-label={t("rotationPlans.passwordMode")}
                    value={draft.passwordMode}
                    onChange={(e) =>
                      setDraft({ ...draft, passwordMode: e.target.value, fixedPassword: "" })
                    }
                  >
                    <option value="generated">{t("rotationPlans.generatedMode")}</option>
                    <option value="fixed" disabled={!fixedAllowed}>
                      {t("rotationPlans.fixedMode")}
                    </option>
                  </select>
                </label>
                {draft.passwordMode === "fixed" && (
                  <>
                    <label>
                      {t("rotationPlans.fixedPassword")}
                      <input
                        type="password"
                        autoComplete="new-password"
                        minLength={16}
                        maxLength={128}
                        required={!draft.fixedConfigured}
                        value={draft.fixedPassword}
                        disabled={!fixedAllowed}
                        onChange={(e) => setDraft({ ...draft, fixedPassword: e.target.value })}
                      />
                    </label>
                    <p className="settings-help">
                      {t(
                        draft.fixedConfigured
                          ? "rotationPlans.keepFixed"
                          : "rotationPlans.fixedHint",
                      )}
                    </p>
                    <p className="settings-help">{t("rotationPlans.fixedScheduleHint")}</p>
                    {!draft.passwordPolicy && (
                      <p className="settings-help">{t("sshPasswordPolicy.allowed")}</p>
                    )}
                  </>
                )}
              </fieldset>
              <fieldset className="rotation-password-policy">
                <legend>{t("rotationPlans.passwordPolicy")}</legend>
                <label className="rotation-check">
                  <input
                    type="checkbox"
                    checked={draft.passwordPolicy !== null}
                    onChange={(e) =>
                      setDraft({
                        ...draft,
                        passwordPolicy: e.target.checked ? { ...inheritedPasswordRules } : null,
                      })
                    }
                  />
                  {t("rotationPlans.customPasswordPolicy")}
                </label>
                <p className="settings-help">{t("rotationPlans.passwordPolicyHint")}</p>
                {draft.passwordPolicy && (
                  <SSHPasswordRuleFields
                    rules={draft.passwordPolicy}
                    disabled={busy}
                    onChange={(passwordPolicy) => setDraft({ ...draft, passwordPolicy })}
                  />
                )}
              </fieldset>
              {draft.kind !== "manual" && (
                <label className="rotation-check">
                  <input
                    type="checkbox"
                    disabled={
                      !execute ||
                      (Object.values(draft.accounts).some((v) => v.collector_id) && !privileged)
                    }
                    checked={draft.enabled}
                    onChange={(e) => setDraft({ ...draft, enabled: e.target.checked })}
                  />
                  {t("rotationPlans.enableHint")}
                </label>
              )}
            </fieldset>
            <h3>{t("rotationPlans.selected", { count: Object.keys(draft.accounts).length })}</h3>
            <p className="settings-help">{t("rotationPlans.collectorHint")}</p>
            <ul className="rotation-selected">
              {Object.values(draft.accounts).map((a) => (
                <li key={a.account_id}>
                  <span>
                    <strong>
                      {a.asset_name} · {a.username}
                    </strong>
                    <small>
                      {a.account_id} · {t(`rotationPlans.credentials.${a.credential_type}`)}
                    </small>
                    <small>
                      {t("rotationPlans.collector")}:{" "}
                      {a.collector_username || t("rotationPlans.self")}
                    </small>
                  </span>
                  <div className="rotation-actions">
                    {a.credential_type === "password" && (
                      <button
                        type="button"
                        disabled={busy || !privileged}
                        onClick={() => {
                          setCollectorFor(a);
                          setCollectorOffset(0);
                          setCollectorSearch("");
                          setCollectorQuery("");
                          setCollectors(empty());
                        }}
                      >
                        {t("rotationPlans.chooseCollector")}
                      </button>
                    )}
                    <button
                      type="button"
                      disabled={busy}
                      onClick={() => select(a, false)}
                      aria-label={t("rotationPlans.removeAccount", { username: a.username })}
                    >
                      {t("rotationPlans.remove")}
                    </button>
                  </div>
                </li>
              ))}
            </ul>
            <fieldset disabled={busy}>
              <legend>{t("rotationPlans.chooseAccounts")}</legend>
              <div className="rotation-actions">
                <label>
                  {t("rotationPlans.search")}
                  <input
                    value={search}
                    onChange={(e) => setSearch(e.target.value)}
                    maxLength={128}
                  />
                </label>
                <button
                  type="button"
                  onClick={() => {
                    setQuery(search);
                    setCandidateOffset(0);
                  }}
                >
                  {t("rotationPlans.searchAction")}
                </button>
              </div>
              <ul className="rotation-candidates">
                {candidates.results.map((a) => (
                  <li key={a.account_id}>
                    <label className="rotation-check">
                      <input
                        type="checkbox"
                        aria-label={`${a.asset_name} · ${a.username}`}
                        checked={Boolean(draft.accounts[a.account_id])}
                        disabled={
                          !draft.accounts[a.account_id] && Object.keys(draft.accounts).length >= 500
                        }
                        onChange={(e) => select(a, e.target.checked)}
                      />
                      <span>
                        {a.asset_name} · {a.username}
                        <small>
                          {a.account_id} · {t(`rotationPlans.credentials.${a.credential_type}`)}
                        </small>
                      </span>
                    </label>
                  </li>
                ))}
              </ul>
              {pages(candidates.total, candidateOffset, setCandidateOffset, 25)}
            </fieldset>
            {error && (
              <p role="alert" className="asset-error">
                {t(`rotationPlans.errors.${error}`)}
              </p>
            )}
            <p className="settings-help">
              {t(draft.enabled ? "rotationPlans.scheduledSave" : "rotationPlans.saveHint")}
            </p>
            <div className="rotation-actions">
              <button type="button" disabled={busy} onClick={closeEditor}>
                {t("rotationPlans.close")}
              </button>
              <button
                className="button-primary"
                disabled={busy || !Object.keys(draft.accounts).length}
                type="submit"
              >
                {t("rotationPlans.save")}
              </button>
            </div>
          </form>
        </Modal>
      )}
      {collectorFor && (
        <Modal
          title={t("rotationPlans.chooseCollector")}
          close={() => setCollectorFor(null)}
          busy={busy}
        >
          <p>
            {collectorFor.asset_name} · {collectorFor.username}
          </p>
          <p>{t("rotationPlans.collectorHint")}</p>
          <div className="rotation-actions">
            <label>
              {t("rotationPlans.search")}
              <input
                maxLength={128}
                value={collectorSearch}
                onChange={(e) => setCollectorSearch(e.target.value)}
              />
            </label>
            <button
              type="button"
              onClick={() => {
                setCollectorQuery(collectorSearch);
                setCollectorOffset(0);
              }}
            >
              {t("rotationPlans.searchAction")}
            </button>
          </div>
          <ul className="rotation-candidates">
            {collectors.results.map((c) => (
              <li key={c.account_id}>
                <button
                  type="button"
                  onClick={() => {
                    const updated = {
                      ...collectorFor,
                      collector_id: c.account_id,
                      collector_username: c.username,
                    };
                    setDraft((old) =>
                      old
                        ? { ...old, accounts: { ...old.accounts, [updated.account_id]: updated } }
                        : old,
                    );
                    setCollectorFor(null);
                  }}
                >
                  {c.asset_name} · {c.username}
                </button>
              </li>
            ))}
          </ul>
          {pages(collectors.total, collectorOffset, setCollectorOffset, 25)}
          <div className="rotation-actions">
            <button
              type="button"
              onClick={() => {
                const updated = {
                  ...collectorFor,
                  collector_id: undefined,
                  collector_username: undefined,
                };
                setDraft((old) =>
                  old
                    ? { ...old, accounts: { ...old.accounts, [updated.account_id]: updated } }
                    : old,
                );
                setCollectorFor(null);
              }}
            >
              {t("rotationPlans.self")}
            </button>
            <button type="button" onClick={() => setCollectorFor(null)}>
              {t("rotationPlans.close")}
            </button>
          </div>
        </Modal>
      )}
      {selectedRun && (
        <Modal title={t("rotationPlans.runDetails")} close={() => setSelectedRun(null)} busy={busy}>
          <h3>{selectedRun.name}</h3>
          <p>
            {t(
              selectedRun.password_mode === "fixed"
                ? "rotationPlans.fixedMode"
                : "rotationPlans.generatedMode",
            )}
          </p>
          {selectedRun.password_policy ? (
            <details className="rotation-password-policy">
              <summary>{t("rotationPlans.policySnapshot")}</summary>
              <SSHPasswordRuleFields
                rules={selectedRun.password_policy}
                disabled
                onChange={() => {}}
              />
            </details>
          ) : (
            <p className="settings-help">{t("rotationPlans.inheritedPolicy")}</p>
          )}
          <p role="status">{state(selectedRun.state)}</p>
          <dl className="rotation-meta">
            {selectedRun.parent_run_id && (
              <>
                <dt>{t("rotationPlans.parentRun")}</dt>
                <dd>
                  <button
                    type="button"
                    disabled={busy}
                    onClick={() => void showRun(selectedRun.parent_run_id!)}
                  >
                    {selectedRun.parent_run_id}
                  </button>
                </dd>
              </>
            )}
            <dt>{t("rotationPlans.request")}</dt>
            <dd>{selectedRun.request_id}</dd>
            <dt>{t("rotationPlans.createdAt")}</dt>
            <dd>{date(selectedRun.created_at)}</dd>
            <dt>{t("rotationPlans.finishedAt")}</dt>
            <dd>{date(selectedRun.finished_at)}</dd>
          </dl>
          <p className="settings-help">{t("rotationPlans.resultHint")}</p>
          <div
            className="rotation-table"
            tabIndex={0}
            role="region"
            aria-label={t("rotationPlans.accounts")}
          >
            <table>
              <thead>
                <tr>
                  {["account", "credential", "state", "result"].map((key) => (
                    <th key={key}>{t(`rotationPlans.${key}`)}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {(selectedRun.items || []).slice(itemOffset, itemOffset + 25).map((item) => (
                  <tr key={item.id}>
                    <td>
                      {item.asset_name} · {item.username}
                      <small>{item.account_id}</small>
                      {item.collector_username && (
                        <small>
                          {t("rotationPlans.collector")}: {item.collector_username}
                        </small>
                      )}
                    </td>
                    <td>{t(`rotationPlans.credentials.${item.credential_type}`)}</td>
                    <td>{state(item.state)}</td>
                    <td>
                      {item.linked_to
                        ? t("rotationPlans.linked")
                        : t("rotationPlans.revisions", {
                            before: item.before_revision,
                            after: item.after_revision || t("rotationPlans.none"),
                          })}
                      {item.error_code && (
                        <small>
                          {t(`rotationPlans.itemErrors.${item.error_code}`, {
                            defaultValue: t("rotationPlans.itemErrors.rotation_failed"),
                          })}
                        </small>
                      )}
                      {item.source_item_id && (
                        <small>{t("rotationPlans.sourceItem", { id: item.source_item_id })}</small>
                      )}
                      {item.retry_run_id ? (
                        <button
                          type="button"
                          disabled={busy}
                          onClick={() => void showRun(item.retry_run_id!)}
                        >
                          {t("rotationPlans.openRetry")}
                        </button>
                      ) : (
                        !active(selectedRun.state) &&
                        retryable(item) &&
                        execute &&
                        (all || selectedRun.owner.id === userID) && (
                          <button
                            type="button"
                            disabled={busy}
                            onClick={() => void prepareRetry([item.id])}
                          >
                            {t("rotationPlans.retryAccount")}
                          </button>
                        )
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          {pages(selectedRun.items?.length || 0, itemOffset, setItemOffset, 25)}
          {error && (
            <p role="alert" className="asset-error">
              {t(`rotationPlans.errors.${error}`)}
            </p>
          )}
          <div className="rotation-actions">
            <button type="button" disabled={busy} onClick={() => setSelectedRun(null)}>
              {t("rotationPlans.close")}
            </button>
            <button type="button" disabled={busy} onClick={() => void exportRun(selectedRun.id)}>
              {t("rotationPlans.export")}
            </button>
            {!active(selectedRun.state) &&
              selectedRun.items?.some(retryable) &&
              execute &&
              (all || selectedRun.owner.id === userID) && (
                <button type="button" disabled={busy} onClick={() => void prepareRetry()}>
                  {t("rotationPlans.retryFailed")}
                </button>
              )}
            {active(selectedRun.state) &&
              !selectedRun.cancelled &&
              manage &&
              (all || selectedRun.owner.id === userID) && (
                <button
                  type="button"
                  disabled={busy}
                  onClick={() =>
                    setConfirm({ mode: "cancel", id: selectedRun.id, name: selectedRun.name })
                  }
                >
                  {t("rotationPlans.cancel")}
                </button>
              )}
            {selectedRun.state === "recovery_required" &&
              execute &&
              (all || selectedRun.owner.id === userID) && (
                <button
                  type="button"
                  disabled={busy}
                  onClick={() =>
                    setConfirm({ mode: "recover", id: selectedRun.id, name: selectedRun.name })
                  }
                >
                  {t("rotationPlans.recover")}
                </button>
              )}
          </div>
        </Modal>
      )}
      {confirm && (
        <Modal
          title={t(`rotationPlans.confirmTitles.${confirm.mode}`)}
          close={() => setConfirm(null)}
          busy={busy}
        >
          <p>
            <strong>{confirm.name}</strong>
          </p>
          <p>{t(`rotationPlans.confirmHints.${confirm.mode}`)}</p>
          {confirm.mode === "retry" && confirm.plan && (
            <>
              <p>
                {t("rotationPlans.retryConfiguration", {
                  revision: confirm.revision,
                  mode: t(
                    confirm.plan.password_mode === "fixed"
                      ? "rotationPlans.fixedMode"
                      : "rotationPlans.generatedMode",
                  ),
                })}
              </p>
              {confirm.plan.password_policy ? (
                <SSHPasswordRuleFields
                  rules={confirm.plan.password_policy}
                  disabled
                  onChange={() => {}}
                />
              ) : (
                <p className="settings-help">{t("rotationPlans.inheritedPolicy")}</p>
              )}
            </>
          )}
          {confirm.mode === "run" && (
            <p className="settings-help">{t("rotationPlans.retryHint")}</p>
          )}
          {error && (
            <p role="alert" className="asset-error">
              {t(`rotationPlans.errors.${error}`)}
            </p>
          )}
          <div className="rotation-actions">
            <button type="button" disabled={busy} onClick={() => setConfirm(null)}>
              {t("rotationPlans.close")}
            </button>
            <button
              className="button-primary"
              type="button"
              disabled={busy}
              onClick={() => void confirmed()}
            >
              {t(
                `rotationPlans.${confirm.mode === "delete" ? "delete" : confirm.mode === "cancel" ? "cancel" : confirm.mode === "recover" ? "recover" : confirm.mode === "retry" ? "retry" : "run"}`,
              )}
            </button>
          </div>
        </Modal>
      )}
    </section>
  );
}
