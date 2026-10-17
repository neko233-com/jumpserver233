import { useCallback, useEffect, useRef, useState, type FormEvent, type ReactNode } from "react";
import { useTranslation } from "react-i18next";
import { useLocation } from "react-router-dom";
import { useAuth } from "../auth/AuthContext";
import "../i18n/locales/features/access-tickets/register";
import "./rotation-plans.css";
import "./access-tickets.css";

type Actor = { id: string; name: string };
type Subject = { kind: string; id: string };
type Stage = { name: string; subjects: Subject[] };
type Target = { kind: string; id: string; account: string; actions: string[] };
type Ref = Target & { name: string; protocol: string };
type Scope = { kind: string; id: string; accounts: string[]; actions: string[] };
type Policy = {
  id: string;
  name: string;
  description: string;
  enabled: boolean;
  all_members: boolean;
  requesters: Subject[];
  cc: Subject[];
  stages: Stage[];
  scopes: Scope[];
  max_duration_minutes: number;
  approval_ttl_minutes: number;
  revision: number;
};
type Ticket = {
  id: string;
  name: string;
  owner: Actor;
  publisher: Actor;
  policy_id: string;
  policy_name: string;
  state: string;
  revision: number;
  current_stage: number;
  stages: Stage[];
  reason: string;
  targets: Ref[];
  starts_at: string;
  ends_at: string;
  approval_expires_at: string;
  approvals: { stage: number; actor: Actor; at: string; comment: string }[];
  comments: { actor: Actor; at: string; text: string }[];
  can_review: boolean;
  can_amend: boolean;
  can_revoke: boolean;
  outdated: boolean;
  error_code?: string;
};
type Audit = {
  at: string;
  actor: Actor;
  action: string;
  ticket_id?: string;
  policy_id?: string;
  revision?: number;
  note?: string;
};
type Page<T> = { results: T[]; total: number };
type Choice = Subject & { name: string };
type Resource = { kind: string; id: string; name: string; accounts: string[] };
type RequestDraft = {
  id: string;
  revision: number;
  name: string;
  policy: string;
  reason: string;
  start: string;
  end: string;
  selected: Record<string, Ref>;
  requestID: string;
};
const empty = <T,>(): Page<T> => ({ results: [], total: 0 });
const key = (v: Target) => `${v.kind}/${v.id}/${v.account}`;
const localTime = (iso: string) => {
  const d = new Date(iso);
  return new Date(d.getTime() - d.getTimezoneOffset() * 60000).toISOString().slice(0, 16);
};
const policyInput = (p: Policy) => ({
  name: p.name,
  description: p.description,
  enabled: p.enabled,
  all_members: p.all_members,
  requesters: p.requesters,
  cc: p.cc,
  stages: p.stages,
  scopes: p.scopes,
  max_duration_minutes: p.max_duration_minutes,
  approval_ttl_minutes: p.approval_ttl_minutes,
  revision: p.revision,
});
const errorCodes = new Set([
  "invalid",
  "not_found",
  "denied",
  "conflict",
  "source_changed",
  "reviewers_unavailable",
  "capacity",
  "unavailable",
]);
class TicketError extends Error {
  constructor(public code: string) {
    super(code);
  }
}
function Dialog({
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
    const before = document.activeElement;
    const dialog = ref.current;
    dialog?.showModal();
    return () => {
      dialog?.close();
      if (before instanceof HTMLElement && before.isConnected) before.focus();
    };
  }, []);
  return (
    <dialog
      ref={ref}
      className="rotation-dialog ticket-dialog"
      aria-label={title}
      onCancel={(e) => {
        if (busy) e.preventDefault();
        else close();
      }}
    >
      <h2>{title}</h2>
      {children}
    </dialog>
  );
}
export default function AccessTicketsPage() {
  const { search: notificationSearch } = useLocation();
  const { t, i18n } = useTranslation(),
    { accessToken } = useAuth();
  const life = useRef<AbortController | null>(null),
    serial = useRef(0);
  const [caps, setCaps] = useState({
    publish: false,
    review: false,
    view_all: false,
    revoke: false,
  });
  const [tab, setTab] = useState("mine"),
    [offset, setOffset] = useState(0),
    [epoch, setEpoch] = useState(0);
  const [requests, setRequests] = useState<Page<Ticket>>(empty),
    [policies, setPolicies] = useState<Page<Policy>>(empty),
    [audit, setAudit] = useState<Page<Audit>>(empty);
  const [detail, setDetail] = useState<Ticket | null>(null),
    [draft, setDraft] = useState<RequestDraft | null>(null),
    [editor, setEditor] = useState<Policy | null>(null);
  const [catalog, setCatalog] = useState<Page<Ref>>(empty),
    [resourcePage, setResources] = useState<Page<Resource>>(empty),
    [choices, setChoices] = useState<Choice[]>([]);
  const [search, setSearch] = useState(""),
    [query, setQuery] = useState(""),
    [catalogOffset, setCatalogOffset] = useState(0);
  const [resourceID, setResourceID] = useState(""),
    [account, setAccount] = useState(""),
    [scopeActions, setScopeActions] = useState(["connect"]);
  const [busy, setBusy] = useState(false),
    [error, setError] = useState(""),
    [notice, setNotice] = useState(""),
    [comment, setComment] = useState("");
  const [confirm, setConfirm] = useState<{
    action: string;
    ticket?: Ticket;
    policy?: Policy;
    requestID: string;
  } | null>(null);
  const policyID = draft?.policy || "",
    editing = Boolean(editor),
    requesting = Boolean(draft),
    confirming = Boolean(confirm),
    detailID = detail?.id || "";
  useEffect(() => {
    life.current = new AbortController();
    return () => life.current?.abort();
  }, []);
  const request = useCallback(
    async <T,>(path: string, method = "GET", body?: unknown, signal?: AbortSignal): Promise<T> => {
      const headers = new Headers();
      if (accessToken) headers.set("Authorization", `Bearer ${accessToken}`);
      if (body !== undefined) headers.set("Content-Type", "application/json");
      const signals = [AbortSignal.timeout(30_000)];
      if (life.current) signals.push(life.current.signal);
      if (signal) signals.push(signal);
      const init: RequestInit = {
        method,
        headers,
        signal: AbortSignal.any(signals),
      };
      if (body !== undefined) init.body = JSON.stringify(body);
      const r = await fetch(`/api/v1/tickets/${path}`, init);
      if (!r.ok) {
        const data = await r.json().catch(() => ({}));
        const code = data.error_code || "unavailable";
        throw new TicketError(errorCodes.has(code) ? code : "unavailable");
      }
      return r.json() as Promise<T>;
    },
    [accessToken],
  );
  const fail = useCallback((e: unknown) => {
    if (!life.current?.signal.aborted) setError(e instanceof TicketError ? e.code : "unavailable");
  }, []);
  useEffect(() => {
    const id = new URLSearchParams(notificationSearch).get("request");
    if (!id || !/^[A-Za-z0-9_-]{1,128}$/.test(id)) return;
    const controller = new AbortController();
    void request<Ticket>(`requests/${encodeURIComponent(id)}`, "GET", undefined, controller.signal)
      .then((v) => {
        if (!controller.signal.aborted) setDetail(v);
      })
      .catch((e) => {
        if (!controller.signal.aborted) fail(e);
      });
    return () => controller.abort();
  }, [notificationSearch, request, fail]);
  const load = useCallback(
    async (signal: AbortSignal) => {
      try {
        const path =
          tab === "policies" ? "policies" : tab === "audit" ? "audit" : `requests?view=${tab}`;
        const sep = path.includes("?") ? "&" : "?";
        const result = await request<Page<Policy> | Page<Ticket> | Page<Audit>>(
          `${path}${sep}offset=${offset}&limit=20`,
          "GET",
          undefined,
          signal,
        );
        if (signal.aborted) return;
        if (tab === "policies") setPolicies(result as Page<Policy>);
        else if (tab === "audit") setAudit(result as Page<Audit>);
        else setRequests(result as Page<Ticket>);
      } catch (e) {
        if (!signal.aborted) fail(e);
      }
    },
    [request, tab, offset, fail],
  );
  useEffect(() => {
    const c = new AbortController();
    void request<typeof caps>("capabilities", "GET", undefined, c.signal)
      .then((v) => {
        if (!c.signal.aborted) setCaps(v);
      })
      .catch((e) => {
        if (!c.signal.aborted) fail(e);
      });
    queueMicrotask(() => {
      if (!c.signal.aborted) void load(c.signal);
    });
    const timer = window.setInterval(() => {
      if (document.visibilityState === "visible" && !busy && !requesting && !editing && !confirming)
        void load(c.signal);
    }, 5000);
    return () => {
      c.abort();
      clearInterval(timer);
    };
  }, [request, load, epoch, busy, requesting, editing, confirming, fail]);
  useEffect(() => {
    if (!policyID && !editing) return;
    const c = new AbortController();
    const timer = setTimeout(() => {
      if (policyID)
        void request<Page<Ref>>(
          `policies/${policyID}/catalog?offset=${catalogOffset}&limit=25&search=${encodeURIComponent(query)}`,
          "GET",
          undefined,
          c.signal,
        )
          .then((v) => {
            if (!c.signal.aborted) setCatalog(v);
          })
          .catch((e) => {
            if (!c.signal.aborted) fail(e);
          });
      if (editing)
        void request<Page<Resource>>(
          `resources?offset=${catalogOffset}&limit=25&search=${encodeURIComponent(query)}`,
          "GET",
          undefined,
          c.signal,
        )
          .then((v) => {
            if (!c.signal.aborted) setResources(v);
          })
          .catch((e) => {
            if (!c.signal.aborted) fail(e);
          });
    }, 150);
    return () => {
      c.abort();
      clearTimeout(timer);
    };
  }, [request, policyID, editing, catalogOffset, query, fail]);
  useEffect(() => {
    if (!detailID) return;
    const c = new AbortController();
    const timer = setInterval(() => {
      if (document.visibilityState !== "visible" || busy || confirming || requesting) return;
      void request<Ticket>(`requests/${detailID}`, "GET", undefined, c.signal)
        .then((v) => {
          if (!c.signal.aborted) setDetail(v);
        })
        .catch((e) => {
          if (!c.signal.aborted) fail(e);
        });
    }, 5000);
    return () => {
      clearInterval(timer);
      c.abort();
    };
  }, [detailID, busy, confirming, requesting, request, fail]);
  const run = async (work: () => Promise<void>) => {
    setBusy(true);
    setError("");
    setNotice("");
    try {
      await work();
      if (!life.current?.signal.aborted) {
        setEpoch((v) => v + 1);
        setNotice(t("tickets.saved"));
      }
    } catch (e) {
      fail(e);
    } finally {
      if (!life.current?.signal.aborted) setBusy(false);
    }
  };
  const resetPicker = () => {
    setSearch("");
    setQuery("");
    setCatalogOffset(0);
    setCatalog(empty());
    setResources(empty());
    setResourceID("");
    setAccount("");
  };
  const show = async (id: string) => {
    const n = ++serial.current;
    try {
      const v = await request<Ticket>(`requests/${id}`);
      if (n === serial.current && !life.current?.signal.aborted) {
        setDetail(v);
        setComment("");
        setError("");
      }
    } catch (e) {
      fail(e);
    }
  };
  const openRequest = () =>
    void run(async () => {
      const p = await request<Page<Policy>>("policies?limit=100");
      setPolicies(p);
      resetPicker();
      setDetail(null);
      setDraft({
        id: "",
        revision: 0,
        name: "",
        reason: "",
        policy: p.results.find((v) => v.enabled)?.id || "",
        start: "",
        end: localTime(new Date(Date.now() + 3600_000).toISOString()),
        selected: {},
        requestID: crypto.randomUUID(),
      });
    });
  const openPolicy = (p?: Policy) =>
    void run(async () => {
      const data = await request<{ subjects: Choice[] }>("choices");
      setChoices(data.subjects);
      resetPicker();
      setEditor(
        p
          ? structuredClone(p)
          : {
              id: "",
              name: "",
              description: "",
              enabled: false,
              all_members: true,
              requesters: [],
              cc: [],
              stages: [{ name: t("tickets.stageName", { number: 1 }), subjects: [] }],
              scopes: [],
              max_duration_minutes: 60,
              approval_ttl_minutes: 1440,
              revision: 0,
            },
      );
    });
  const date = (v: string) => new Date(v).toLocaleString(i18n.language);
  const state = (v: string) =>
    t(`tickets.states.${v}`, { defaultValue: t("tickets.states.stale") });
  const subjectOptions = (values: Subject[], change: (rows: Subject[]) => void, label: string) => (
    <label>
      {label}
      <select
        aria-label={label}
        multiple
        value={values.map((v) => `${v.kind}/${v.id}`)}
        onChange={(e) =>
          change(
            Array.from(e.target.selectedOptions, (v) => {
              const [kind, ...id] = v.value.split("/");
              return { kind, id: id.join("/") };
            }),
          )
        }
      >
        {choices.map((v) => (
          <option key={`${v.kind}/${v.id}`} value={`${v.kind}/${v.id}`}>
            {t(`tickets.kinds.${v.kind}`)} · {v.name}
          </option>
        ))}
      </select>
    </label>
  );
  const pickerSearch = (
    <form
      className="rotation-actions"
      onSubmit={(e) => {
        e.preventDefault();
        setQuery(search);
        setCatalogOffset(0);
      }}
    >
      <label>
        {t("tickets.search")}
        <input value={search} maxLength={128} onChange={(e) => setSearch(e.target.value)} />
      </label>
      <button type="submit">{t("tickets.search")}</button>
    </form>
  );
  const pager = (total: number, current: number, change: (v: number) => void, size = 20) => (
    <div className="rotation-actions">
      <button
        type="button"
        disabled={current === 0 || busy}
        onClick={() => change(Math.max(0, current - size))}
      >
        {t("tickets.previous")}
      </button>
      <span>{t("tickets.count", { count: total })}</span>
      <button
        type="button"
        disabled={current + size >= total || busy}
        onClick={() => change(current + size)}
      >
        {t("tickets.next")}
      </button>
    </div>
  );
  const errorBox = error && (
    <p role="alert" id="ticket-error">
      {t(`tickets.errors.${error}`)}
    </p>
  );
  const closeDetail = () => {
    serial.current++;
    setDetail(null);
  };
  const total =
    tab === "policies" ? policies.total : tab === "audit" ? audit.total : requests.total;
  return (
    <section className="rotation-page ticket-page" aria-busy={busy}>
      <header>
        <div>
          <h1>{t("tickets.title")}</h1>
          <p>{t("tickets.hint")}</p>
        </div>
        <div className="rotation-actions">
          <button type="button" disabled={busy} onClick={openRequest}>
            {t("tickets.create")}
          </button>
          {caps.publish && (
            <button type="button" disabled={busy} onClick={() => openPolicy()}>
              {t("tickets.createPolicy")}
            </button>
          )}
          <button
            type="button"
            disabled={busy}
            onClick={() => {
              setError("");
              setEpoch((v) => v + 1);
              if (detail) void show(detail.id);
            }}
          >
            {t("tickets.refresh")}
          </button>
        </div>
      </header>
      {!detail && !draft && !editor && !confirm && errorBox}
      {notice && <p role="status">{notice}</p>}
      <nav className="rotation-actions" aria-label={t("tickets.views")}>
        {[
          "mine",
          ...(caps.review ? ["assigned"] : []),
          "cc",
          ...(caps.view_all ? ["all"] : []),
          "policies",
          "audit",
        ].map((v) => (
          <button
            type="button"
            key={v}
            aria-current={tab === v ? "page" : undefined}
            onClick={() => {
              setTab(v);
              setOffset(0);
            }}
          >
            {t(`tickets.tabs.${v}`)}
          </button>
        ))}
      </nav>
      <div className="rotation-table">
        {tab === "policies" ? (
          <table>
            <thead>
              <tr>
                {["policy", "status", "duration", "stages", "actions"].map((v) => (
                  <th key={v} scope="col">
                    {t(`tickets.${v}`)}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {policies.results.map((p) => (
                <tr key={p.id}>
                  <td>
                    {p.name}
                    <small>{p.description}</small>
                  </td>
                  <td>{t(p.enabled ? "tickets.enabled" : "tickets.disabled")}</td>
                  <td>{t("tickets.minutes", { count: p.max_duration_minutes })}</td>
                  <td>{p.stages.length}</td>
                  <td>
                    {caps.publish && (
                      <button type="button" disabled={busy} onClick={() => openPolicy(p)}>
                        {t("tickets.editPolicy")}
                      </button>
                    )}
                    {p.enabled && (
                      <button
                        type="button"
                        disabled={busy}
                        onClick={() =>
                          void run(async () => {
                            resetPicker();
                            setDraft({
                              id: "",
                              revision: 0,
                              name: "",
                              reason: "",
                              policy: p.id,
                              start: "",
                              end: localTime(
                                new Date(
                                  Date.now() + Math.min(60, p.max_duration_minutes) * 60000,
                                ).toISOString(),
                              ),
                              selected: {},
                              requestID: crypto.randomUUID(),
                            });
                          })
                        }
                      >
                        {t("tickets.apply")}
                      </button>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        ) : tab === "audit" ? (
          <table>
            <thead>
              <tr>
                {["time", "actor", "event", "request", "note"].map((v) => (
                  <th key={v} scope="col">
                    {t(`tickets.${v}`)}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {audit.results.map((v, i) => (
                <tr key={`${v.at}/${i}`}>
                  <td>{date(v.at)}</td>
                  <td>{v.actor.name}</td>
                  <td>{t(`tickets.events.${v.action}`, { defaultValue: t("tickets.event") })}</td>
                  <td>
                    {v.ticket_id ? (
                      <button type="button" onClick={() => void show(v.ticket_id!)}>
                        {v.ticket_id}
                      </button>
                    ) : (
                      v.policy_id
                    )}
                  </td>
                  <td>{v.note}</td>
                </tr>
              ))}
            </tbody>
          </table>
        ) : (
          <table>
            <thead>
              <tr>
                {["request", "owner", "status", "stages", "window", "actions"].map((v) => (
                  <th key={v} scope="col">
                    {t(`tickets.${v}`)}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {requests.results.map((v) => (
                <tr key={v.id}>
                  <td>
                    {v.name}
                    <small>{v.policy_name}</small>
                  </td>
                  <td>{v.owner.name}</td>
                  <td>{state(v.state)}</td>
                  <td>
                    {v.current_stage} / {v.stages.length}
                  </td>
                  <td>
                    {date(v.starts_at)}
                    <small>{date(v.ends_at)}</small>
                  </td>
                  <td>
                    <button type="button" onClick={() => void show(v.id)}>
                      {t("tickets.details")}
                    </button>
                    {v.can_review && <small>{t("tickets.needsReview")}</small>}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
      {total === 0 && <p>{t("tickets.empty")}</p>}
      {pager(total, offset, setOffset)}
      {detail && !draft && !confirm && (
        <Dialog title={t("tickets.details")} close={closeDetail} busy={busy}>
          {errorBox}
          <h3>{detail.name}</h3>
          <p role="status">
            {state(detail.state)} · {detail.current_stage} / {detail.stages.length}
          </p>
          {detail.outdated && <p>{t("tickets.outdated")}</p>}
          <dl className="rotation-meta">
            <dt>{t("tickets.owner")}</dt>
            <dd>{detail.owner.name}</dd>
            <dt>{t("tickets.policy")}</dt>
            <dd>{detail.policy_name}</dd>
            <dt>{t("tickets.window")}</dt>
            <dd>
              {date(detail.starts_at)} — {date(detail.ends_at)}
            </dd>
            <dt>{t("tickets.approvalExpiry")}</dt>
            <dd>{date(detail.approval_expires_at)}</dd>
            <dt>{t("tickets.reason")}</dt>
            <dd>{detail.reason}</dd>
          </dl>
          <h3>{t("tickets.targets")}</h3>
          <ul>
            {detail.targets.map((v) => (
              <li key={key(v)}>
                {v.name} · {v.account} ·{" "}
                {v.actions.map((a) => t(`tickets.actionsList.${a}`)).join(", ")}
                <small>
                  {t(`tickets.kinds.${v.kind}`)} · {v.protocol}
                </small>
              </li>
            ))}
          </ul>
          <h3>{t("tickets.stages")}</h3>
          <ol>
            {detail.stages.map((v, i) => {
              const a = detail.approvals.find((a) => a.stage === i);
              return (
                <li key={i}>
                  {v.name}
                  {a && (
                    <p>
                      {a.actor.name} · {date(a.at)}
                      <small>{a.comment}</small>
                    </p>
                  )}
                </li>
              );
            })}
          </ol>
          {detail.error_code && (
            <p>
              {t(`tickets.codes.${detail.error_code}`, {
                defaultValue: t("tickets.errors.unavailable"),
              })}
            </p>
          )}
          <div className="rotation-actions">
            {detail.can_review &&
              ["approve", "reject"].map((action) => (
                <button
                  type="button"
                  key={action}
                  disabled={busy}
                  onClick={() => {
                    setComment("");
                    setConfirm({ action, ticket: detail, requestID: crypto.randomUUID() });
                  }}
                >
                  {t(`tickets.${action}`)}
                </button>
              ))}
            {detail.can_amend && (
              <button
                type="button"
                disabled={busy}
                onClick={() =>
                  void run(async () => {
                    const p = await request<Policy>(`policies/${detail.policy_id}`);
                    setPolicies({ results: [p], total: 1 });
                    resetPicker();
                    setDraft({
                      id: detail.id,
                      revision: detail.revision,
                      name: detail.name,
                      reason: detail.reason,
                      policy: detail.policy_id,
                      start: localTime(detail.starts_at),
                      end: localTime(detail.ends_at),
                      selected: Object.fromEntries(detail.targets.map((v) => [key(v), v])),
                      requestID: crypto.randomUUID(),
                    });
                  })
                }
              >
                {t("tickets.amend")}
              </button>
            )}
            {detail.can_revoke && (
              <button
                type="button"
                disabled={busy}
                onClick={() => setConfirm({ action: "cancel", ticket: detail, requestID: "" })}
              >
                {t("tickets.cancelRequest")}
              </button>
            )}
          </div>
          <h3>{t("tickets.discussion")}</h3>
          <ul>
            {detail.comments.map((v, i) => (
              <li key={i}>
                {v.actor.name} · {date(v.at)}
                <p>{v.text}</p>
              </li>
            ))}
          </ul>
          <form
            onSubmit={(e) => {
              e.preventDefault();
              void run(async () => {
                setDetail(
                  await request<Ticket>(`requests/${detail.id}/comments`, "POST", {
                    text: comment,
                  }),
                );
                setComment("");
              });
            }}
          >
            <label>
              {t("tickets.comment")}
              <textarea
                aria-label={t("tickets.comment")}
                required
                maxLength={4000}
                value={comment}
                onChange={(e) => setComment(e.target.value)}
              />
            </label>
            <div className="rotation-actions">
              <button type="submit" disabled={busy}>
                {t("tickets.send")}
              </button>
              <button type="button" disabled={busy} onClick={closeDetail}>
                {t("tickets.close")}
              </button>
            </div>
          </form>
        </Dialog>
      )}
      {draft && (
        <Dialog
          title={t(draft.id ? "tickets.amend" : "tickets.create")}
          close={() => setDraft(null)}
          busy={busy}
        >
          {errorBox}
          {draft.id && <p id="ticket-amend-hint">{t("tickets.amendHint")}</p>}
          <form
            onSubmit={(e: FormEvent) => {
              e.preventDefault();
              void run(async () => {
                const selected = Object.values(draft.selected).map(
                  ({ kind, id, account, actions }) => ({ kind, id, account, actions }),
                );
                if (!selected.length) throw new TicketError("invalid");
                const current = policies.results.find((v) => v.id === draft.policy);
                if (!current) throw new TicketError("conflict");
                const body = {
                  reason: draft.reason,
                  targets: selected,
                  starts_at: draft.start ? new Date(draft.start).toISOString() : undefined,
                  ends_at: new Date(draft.end).toISOString(),
                };
                const result = await request<Ticket>(
                  draft.id ? `requests/${draft.id}` : "requests",
                  draft.id ? "PUT" : "POST",
                  draft.id
                    ? { ...body, revision: draft.revision }
                    : {
                        ...body,
                        name: draft.name,
                        policy_id: draft.policy,
                        policy_revision: current.revision,
                        request_id: draft.requestID,
                      },
                );
                setDraft(null);
                setDetail(result);
              });
            }}
          >
            <div className="rotation-fields">
              <label>
                {t("tickets.name")}
                <input
                  required
                  maxLength={240}
                  disabled={Boolean(draft.id)}
                  value={draft.name}
                  onChange={(e) => setDraft({ ...draft, name: e.target.value })}
                />
              </label>
              <label>
                {t("tickets.policy")}
                <select
                  aria-label={t("tickets.policy")}
                  required
                  disabled={Boolean(draft.id)}
                  value={draft.policy}
                  onChange={(e) => {
                    setDraft({ ...draft, policy: e.target.value, selected: {} });
                    setCatalogOffset(0);
                    setCatalog(empty());
                  }}
                >
                  <option value="">{t("tickets.choose")}</option>
                  {policies.results
                    .filter((v) => v.enabled)
                    .map((v) => (
                      <option key={v.id} value={v.id}>
                        {v.name}
                      </option>
                    ))}
                </select>
              </label>
              <label>
                {t("tickets.starts")}
                <input
                  type="datetime-local"
                  value={draft.start}
                  onChange={(e) => setDraft({ ...draft, start: e.target.value })}
                />
              </label>
              <label>
                {t("tickets.ends")}
                <input
                  required
                  type="datetime-local"
                  value={draft.end}
                  onChange={(e) => setDraft({ ...draft, end: e.target.value })}
                />
              </label>
            </div>
            <label>
              {t("tickets.reason")}
              <textarea
                aria-label={t("tickets.reason")}
                required
                maxLength={4000}
                value={draft.reason}
                onChange={(e) => setDraft({ ...draft, reason: e.target.value })}
              />
            </label>
            <p>{t("tickets.selected", { count: Object.keys(draft.selected).length })}</p>
            <ul>
              {Object.values(draft.selected).map((v) => (
                <li key={key(v)}>
                  {v.name} · {v.account}
                  <div className="rotation-actions">
                    {["view", "connect", "sftp"]
                      .filter(
                        (a) =>
                          (
                            catalog.results.find((row) => key(row) === key(v))?.actions || v.actions
                          ).includes(a) || a === "view",
                      )
                      .map((a) => (
                        <label key={a}>
                          <input
                            type="checkbox"
                            checked={v.actions.includes(a)}
                            disabled={a === "view"}
                            onChange={(e) => {
                              const actions = e.target.checked
                                ? [...v.actions, a]
                                : v.actions.filter((x) => x !== a);
                              setDraft({
                                ...draft,
                                selected: { ...draft.selected, [key(v)]: { ...v, actions } },
                              });
                            }}
                          />
                          {t(`tickets.actionsList.${a}`)}
                        </label>
                      ))}
                    <button
                      type="button"
                      onClick={() => {
                        const selected = { ...draft.selected };
                        delete selected[key(v)];
                        setDraft({ ...draft, selected });
                      }}
                    >
                      {t("tickets.remove")}
                    </button>
                  </div>
                </li>
              ))}
            </ul>
            <div className="rotation-actions">
              <button type="submit" disabled={busy || !Object.keys(draft.selected).length}>
                {t(draft.id ? "tickets.saveAmendment" : "tickets.submit")}
              </button>
              <button type="button" disabled={busy} onClick={() => setDraft(null)}>
                {t("tickets.close")}
              </button>
            </div>
          </form>
          <h3>{t("tickets.catalog")}</h3>
          {pickerSearch}
          <div className="ticket-catalog">
            {catalog.results.map((v) => (
              <button
                type="button"
                key={key(v)}
                disabled={
                  Boolean(draft.selected[key(v)]) || Object.keys(draft.selected).length >= 50
                }
                onClick={() =>
                  setDraft({
                    ...draft,
                    selected: {
                      ...draft.selected,
                      [key(v)]: { ...v, actions: Array.from(new Set(["view", ...v.actions])) },
                    },
                  })
                }
              >
                {v.name} · {v.account}
                <small>
                  {t(`tickets.kinds.${v.kind}`)} · {v.protocol}
                </small>
              </button>
            ))}
          </div>
          {pager(catalog.total, catalogOffset, setCatalogOffset, 25)}
        </Dialog>
      )}
      {editor && (
        <Dialog
          title={t(editor.id ? "tickets.editPolicy" : "tickets.createPolicy")}
          close={() => setEditor(null)}
          busy={busy}
        >
          {errorBox}
          <form
            onSubmit={(e) => {
              e.preventDefault();
              void run(async () => {
                await request(
                  editor.id ? `policies/${editor.id}` : "policies",
                  editor.id ? "PUT" : "POST",
                  policyInput(editor),
                );
                setEditor(null);
                setTab("policies");
                setOffset(0);
              });
            }}
          >
            <div className="rotation-fields">
              <label>
                {t("tickets.name")}
                <input
                  required
                  maxLength={240}
                  value={editor.name}
                  onChange={(e) => setEditor({ ...editor, name: e.target.value })}
                />
              </label>
              <label>
                {t("tickets.maxDuration")}
                <input
                  required
                  type="number"
                  min={1}
                  max={43200}
                  value={editor.max_duration_minutes}
                  onChange={(e) =>
                    setEditor({ ...editor, max_duration_minutes: Number(e.target.value) })
                  }
                />
              </label>
              <label>
                {t("tickets.approvalTTL")}
                <input
                  required
                  type="number"
                  min={1}
                  max={10080}
                  value={editor.approval_ttl_minutes}
                  onChange={(e) =>
                    setEditor({ ...editor, approval_ttl_minutes: Number(e.target.value) })
                  }
                />
              </label>
            </div>
            <label>
              {t("tickets.description")}
              <textarea
                aria-label={t("tickets.description")}
                maxLength={2000}
                value={editor.description}
                onChange={(e) => setEditor({ ...editor, description: e.target.value })}
              />
            </label>
            <label className="ticket-check">
              <input
                type="checkbox"
                checked={editor.enabled}
                onChange={(e) => setEditor({ ...editor, enabled: e.target.checked })}
              />
              {t("tickets.enablePolicy")}
            </label>
            <p>{t("tickets.disableHint")}</p>
            <label className="ticket-check">
              <input
                type="checkbox"
                checked={editor.all_members}
                onChange={(e) =>
                  setEditor({ ...editor, all_members: e.target.checked, requesters: [] })
                }
              />
              {t("tickets.allMembers")}
            </label>
            {!editor.all_members &&
              subjectOptions(
                editor.requesters,
                (rows) => setEditor({ ...editor, requesters: rows }),
                t("tickets.requesters"),
              )}
            {subjectOptions(
              editor.cc,
              (rows) => setEditor({ ...editor, cc: rows }),
              t("tickets.cc"),
            )}
            <h3>{t("tickets.stages")}</h3>
            <p>{t("tickets.stagesHint")}</p>
            {editor.stages.map((stage, i) => (
              <fieldset key={i}>
                <legend>{t("tickets.stageName", { number: i + 1 })}</legend>
                <label>
                  {t("tickets.stageLabel")}
                  <input
                    required
                    maxLength={120}
                    value={stage.name}
                    onChange={(e) =>
                      setEditor({
                        ...editor,
                        stages: editor.stages.map((v, j) =>
                          j === i ? { ...v, name: e.target.value } : v,
                        ),
                      })
                    }
                  />
                </label>
                {subjectOptions(
                  stage.subjects,
                  (rows) =>
                    setEditor({
                      ...editor,
                      stages: editor.stages.map((v, j) => (j === i ? { ...v, subjects: rows } : v)),
                    }),
                  t("tickets.reviewers"),
                )}
                <div className="rotation-actions">
                  <button
                    type="button"
                    disabled={i === 0}
                    onClick={() => {
                      const stages = [...editor.stages];
                      [stages[i - 1], stages[i]] = [stages[i], stages[i - 1]];
                      setEditor({ ...editor, stages });
                    }}
                  >
                    {t("tickets.moveUp")}
                  </button>
                  <button
                    type="button"
                    disabled={editor.stages.length <= 1}
                    onClick={() =>
                      setEditor({ ...editor, stages: editor.stages.filter((_, j) => i !== j) })
                    }
                  >
                    {t("tickets.remove")}
                  </button>
                </div>
              </fieldset>
            ))}
            <button
              type="button"
              disabled={editor.stages.length >= 5}
              onClick={() =>
                setEditor({
                  ...editor,
                  stages: [
                    ...editor.stages,
                    {
                      name: t("tickets.stageName", { number: editor.stages.length + 1 }),
                      subjects: [],
                    },
                  ],
                })
              }
            >
              {t("tickets.addStage")}
            </button>
            <h3>{t("tickets.scopes")}</h3>
            <p>{t("tickets.nodeHint")}</p>
            <ul>
              {editor.scopes.map((v, i) => (
                <li key={`${v.kind}/${v.id}`}>
                  {t(`tickets.kinds.${v.kind}`)} · {v.id}
                  <small>
                    {v.accounts.join(", ")} ·{" "}
                    {v.actions.map((a) => t(`tickets.actionsList.${a}`)).join(", ")}
                  </small>
                  <button
                    type="button"
                    onClick={() =>
                      setEditor({ ...editor, scopes: editor.scopes.filter((_, j) => j !== i) })
                    }
                  >
                    {t("tickets.remove")}
                  </button>
                </li>
              ))}
            </ul>
            <div className="rotation-actions">
              <button
                type="submit"
                disabled={
                  busy || !editor.scopes.length || editor.stages.some((v) => !v.subjects.length)
                }
              >
                {t("tickets.savePolicy")}
              </button>
              <button type="button" disabled={busy} onClick={() => setEditor(null)}>
                {t("tickets.close")}
              </button>
              {editor.id && (
                <button
                  type="button"
                  disabled={busy}
                  onClick={() =>
                    setConfirm({ action: "deletePolicy", policy: editor, requestID: "" })
                  }
                >
                  {t("tickets.deletePolicy")}
                </button>
              )}
            </div>
          </form>
          <h3>{t("tickets.addScope")}</h3>
          {pickerSearch}
          <label>
            {t("tickets.resource")}
            <select
              aria-label={t("tickets.resource")}
              value={resourceID}
              onChange={(e) => {
                setResourceID(e.target.value);
                setAccount("");
              }}
            >
              <option value="">{t("tickets.choose")}</option>
              {resourcePage.results.map((v) => (
                <option key={v.id} value={v.id}>
                  {t(`tickets.kinds.${v.kind}`)} · {v.name}
                </option>
              ))}
            </select>
          </label>
          {pager(resourcePage.total, catalogOffset, setCatalogOffset, 25)}
          {(() => {
            const resource = resourcePage.results.find((v) => v.id === resourceID);
            return (
              resource && (
                <div className="rotation-fields">
                  <label>
                    {t("tickets.account")}
                    {resource.kind === "asset" ? (
                      <select
                        aria-label={t("tickets.account")}
                        value={account}
                        onChange={(e) => setAccount(e.target.value)}
                      >
                        <option value="">{t("tickets.choose")}</option>
                        {resource.accounts.map((a) => (
                          <option key={a}>{a}</option>
                        ))}
                      </select>
                    ) : (
                      <input
                        maxLength={128}
                        value={account}
                        onChange={(e) => setAccount(e.target.value)}
                      />
                    )}
                  </label>
                  <fieldset>
                    <legend>{t("tickets.actions")}</legend>
                    {["view", "connect", "sftp"].map((a) => (
                      <label className="ticket-check" key={a}>
                        <input
                          type="checkbox"
                          checked={scopeActions.includes(a)}
                          onChange={(e) =>
                            setScopeActions(
                              e.target.checked
                                ? [...scopeActions, a]
                                : scopeActions.filter((v) => v !== a),
                            )
                          }
                        />
                        {t(`tickets.actionsList.${a}`)}
                      </label>
                    ))}
                  </fieldset>
                  <button
                    type="button"
                    disabled={!account || !scopeActions.length || editor.scopes.length >= 256}
                    onClick={() => {
                      const old = editor.scopes.find(
                        (v) => v.kind === resource.kind && v.id === resource.id,
                      );
                      if (old) {
                        setEditor({
                          ...editor,
                          scopes: editor.scopes.map((v) =>
                            v === old
                              ? {
                                  ...v,
                                  accounts: Array.from(new Set([...v.accounts, account])).slice(
                                    0,
                                    16,
                                  ),
                                  actions: Array.from(new Set([...v.actions, ...scopeActions])),
                                }
                              : v,
                          ),
                        });
                      } else
                        setEditor({
                          ...editor,
                          scopes: [
                            ...editor.scopes,
                            {
                              kind: resource.kind,
                              id: resource.id,
                              accounts: [account],
                              actions: [...scopeActions],
                            },
                          ],
                        });
                      setAccount("");
                    }}
                  >
                    {t("tickets.addScope")}
                  </button>
                </div>
              )
            );
          })()}
        </Dialog>
      )}
      {confirm && (
        <Dialog title={t(`tickets.${confirm.action}`)} close={() => setConfirm(null)} busy={busy}>
          {errorBox}
          <p>{confirm.ticket?.name || confirm.policy?.name}</p>
          <p>
            {t(
              confirm.action === "deletePolicy"
                ? "tickets.disableHint"
                : confirm.action === "cancel"
                  ? "tickets.cancelHint"
                  : "tickets.decisionHint",
            )}
          </p>
          {["approve", "reject"].includes(confirm.action) && (
            <label>
              {t("tickets.comment")}
              <textarea
                aria-label={t("tickets.comment")}
                maxLength={2000}
                value={comment}
                onChange={(e) => setComment(e.target.value)}
              />
            </label>
          )}
          <div className="rotation-actions">
            <button
              type="button"
              disabled={busy}
              onClick={() =>
                void run(async () => {
                  if (confirm.policy) {
                    await request(`policies/${confirm.policy.id}`, "DELETE", {
                      revision: confirm.policy.revision,
                    });
                    setEditor(null);
                  } else if (confirm.ticket) {
                    setDetail(
                      await request<Ticket>(
                        `requests/${confirm.ticket.id}/${confirm.action === "cancel" ? "cancel" : "decisions"}`,
                        "POST",
                        confirm.action === "cancel"
                          ? { revision: confirm.ticket.revision }
                          : {
                              revision: confirm.ticket.revision,
                              request_id: confirm.requestID,
                              action: confirm.action,
                              comment,
                            },
                      ),
                    );
                  }
                  setConfirm(null);
                })
              }
            >
              {t("tickets.confirm")}
            </button>
            <button type="button" disabled={busy} onClick={() => setConfirm(null)}>
              {t("tickets.close")}
            </button>
          </div>
        </Dialog>
      )}
    </section>
  );
}
