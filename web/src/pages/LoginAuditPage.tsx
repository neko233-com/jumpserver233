import { useCallback, useEffect, useRef, useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { useTranslation } from "react-i18next";
import { useAuth } from "../auth/AuthContext";
import "../i18n/locales/features/login-audit/register";
import "./rotation-plans.css";
import "./login-audit.css";

type Audit = {
  id: string;
  at: string;
  method: string;
  stage: string;
  outcome: string;
  reason?: string;
  user_id?: string;
  username?: string;
  attempted_name?: string;
  source_ip: string;
  client: string;
  review_id?: string;
  actor_id?: string;
  review_state?: string;
  can_review?: boolean;
  review_expires_at?: string;
};
type Caps = { view_all: boolean; export_all: boolean };
type Summary = {
  total: number;
  succeeded: number;
  failed: number;
  denied: number;
  challenges: number;
};
type Health = {
  records: number;
  error_code?: string;
  prune_pending: boolean;
  aggregation_limited: boolean;
  review_error_code?: string;
  review_gap: boolean;
};
type Filters = {
  scope: string;
  method: string;
  outcome: string;
  q: string;
  source_ip: string;
  from: string;
  to: string;
};
const initial: Filters = {
  scope: "mine",
  method: "",
  outcome: "",
  q: "",
  source_ip: "",
  from: "",
  to: "",
};
const methods = ["local", "ldap", "oidc", "saml", "cas", "passkey", "radius", "unknown"];
const outcomes = [
  "succeeded",
  "failed",
  "denied",
  "throttled",
  "challenge",
  "external_verified",
  "review_pending",
  "review_approved",
  "review_denied",
  "review_expired",
  "review_cancelled",
  "review_consumed",
  "review_invalidated",
  "policy_notified",
  "cancelled",
  "service_error",
  "invalid_request",
  "started",
  "exported",
];
class AuditError extends Error {
  constructor(public code: string) {
    super(code);
  }
}
function query(filters: Filters, offset: number) {
  const q = new URLSearchParams({ ...filters, offset: String(offset), limit: "25" });
  for (const key of ["from", "to"] as const)
    if (filters[key]) {
      const d = new Date(filters[key]);
      if (!Number.isFinite(d.getTime())) throw new AuditError("invalid");
      q.set(key, d.toISOString());
    }
  return q.toString();
}
export default function LoginAuditPage() {
  const { t, i18n } = useTranslation(),
    { accessToken } = useAuth();
  const [params, setParams] = useSearchParams(),
    eventID = params.get("event") || "";
  const [filters, setFilters] = useState(initial),
    [draft, setDraft] = useState(initial),
    [offset, setOffset] = useState(0),
    [version, setVersion] = useState(0);
  const [caps, setCaps] = useState<Caps>({ view_all: false, export_all: false }),
    [rows, setRows] = useState<Audit[]>([]),
    [total, setTotal] = useState(0),
    [summary, setSummary] = useState<Summary | null>(null),
    [health, setHealth] = useState<Health | null>(null);
  const [detail, setDetail] = useState<Audit | null>(null),
    [decision, setDecision] = useState(""),
    [busy, setBusy] = useState(false),
    [error, setError] = useState(""),
    [notice, setNotice] = useState("");
  const dialog = useRef<HTMLDialogElement>(null),
    initialized = useRef(false),
    action = useRef<AbortController | null>(null),
    working = useRef(false),
    listVersion = useRef(0),
    focus = useRef<HTMLElement | null>(null);
  const request = useCallback(
    async <T,>(path: string, signal: AbortSignal, method = "GET"): Promise<T> => {
      const r = await fetch(`/api/v1/${path}`, {
        method,
        headers: accessToken ? { Authorization: `Bearer ${accessToken}` } : {},
        signal: AbortSignal.any([signal, AbortSignal.timeout(30_000)]),
      });
      if (!r.ok)
        throw new AuditError(
          (
            {
              400: "invalid",
              401: "denied",
              403: "denied",
              404: "not_found",
              409: "conflict",
            } as Record<number, string>
          )[r.status] || "unavailable",
        );
      return r.status === 204 ? (undefined as T) : (r.json() as Promise<T>);
    },
    [accessToken],
  );
  const fail = useCallback(
    (e: unknown) => setError(e instanceof AuditError ? e.code : "unavailable"),
    [],
  );
  useEffect(() => {
    if (eventID) return;
    const controller = new AbortController();
    let running = false;
    const load = async () => {
      if (running || document.visibilityState === "hidden" || working.current) return;
      running = true;
      const serial = ++listVersion.current;
      try {
        const c = await request<Caps>("audits/logins/capabilities", controller.signal);
        if (controller.signal.aborted) return;
        setCaps(c);
        let f = filters;
        if (!initialized.current) {
          initialized.current = true;
          if (c.view_all) {
            f = { ...filters, scope: "all" };
            setFilters(f);
            setDraft(f);
            return;
          }
        }
        if (f.scope === "all" && !c.view_all) {
          setFilters({ ...f, scope: "mine" });
          setDraft({ ...f, scope: "mine" });
          setRows([]);
          setSummary(null);
          setHealth(null);
          setOffset(0);
          return;
        }
        const q = query(f, offset);
        const [p, s, h] = await Promise.all([
          request<{ results: Audit[]; total: number }>(`audits/logins?${q}`, controller.signal),
          request<Summary>(`audits/logins/summary?${q}`, controller.signal),
          c.view_all
            ? request<Health>("audits/logins/health", controller.signal)
            : Promise.resolve(null),
        ]);
        if (!controller.signal.aborted && serial === listVersion.current) {
          setRows(p.results);
          setTotal(p.total);
          setSummary(s);
          setHealth(h);
          setError("");
        }
      } catch (e) {
        if (!controller.signal.aborted) {
          setRows([]);
          setSummary(null);
          setHealth(null);
          fail(e);
        }
      } finally {
        running = false;
      }
    };
    void load();
    const timer = setInterval(() => void load(), 10_000);
    document.addEventListener("visibilitychange", load);
    return () => {
      controller.abort();
      clearInterval(timer);
      document.removeEventListener("visibilitychange", load);
    };
  }, [filters, offset, version, request, fail, eventID]);
  useEffect(() => {
    if (!eventID) return;
    const current = dialog.current;
    focus.current = document.activeElement instanceof HTMLElement ? document.activeElement : null;
    current?.showModal();
    return () => {
      action.current?.abort();
      working.current = false;
      current?.close();
      focus.current?.focus();
    };
  }, [eventID]);
  useEffect(() => {
    if (!eventID) return;
    const controller = new AbortController();
    let running = false;
    const load = async () => {
      if (running || working.current || document.visibilityState === "hidden") return;
      running = true;
      try {
        const d = await request<Audit>(
          `audits/logins/${encodeURIComponent(eventID)}`,
          controller.signal,
        );
        if (!controller.signal.aborted) {
          setDetail(d);
          setError("");
        }
      } catch (e) {
        if (!controller.signal.aborted) {
          setDetail(null);
          setDecision("");
          fail(e);
        }
      } finally {
        running = false;
      }
    };
    void load();
    const timer = setInterval(() => void load(), 5_000);
    return () => {
      controller.abort();
      clearInterval(timer);
    };
  }, [eventID, request, fail, version]);
  const close = () => {
    action.current?.abort();
    working.current = false;
    setBusy(false);
    setError("");
    setDetail(null);
    setDecision("");
    const p = new URLSearchParams(params);
    p.delete("event");
    setParams(p);
  };
  const review = async () => {
    if (!detail?.review_id || !decision || working.current) return;
    const controller = new AbortController();
    action.current = controller;
    working.current = true;
    setBusy(true);
    setError("");
    try {
      await request(
        `login-reviews/${encodeURIComponent(detail.review_id)}/${decision}`,
        controller.signal,
        "POST",
      );
      if (!controller.signal.aborted) {
        setNotice("loginAudit.saved");
        setDecision("");
        setVersion((v) => v + 1);
        window.dispatchEvent(new Event("jms233-notifications"));
      }
    } catch (e) {
      if (!controller.signal.aborted) fail(e);
    } finally {
      if (!controller.signal.aborted) {
        working.current = false;
        setBusy(false);
      }
    }
  };
  const exportCSV = async () => {
    if (working.current) return;
    const controller = new AbortController();
    action.current = controller;
    working.current = true;
    setBusy(true);
    setError("");
    try {
      const r = await fetch(`/api/v1/audits/logins/export.csv?${query(filters, 0)}`, {
        headers: accessToken ? { Authorization: `Bearer ${accessToken}` } : {},
        signal: AbortSignal.any([controller.signal, AbortSignal.timeout(30_000)]),
      });
      if (!r.ok)
        throw new AuditError(
          r.status === 403 || r.status === 401
            ? "denied"
            : r.status === 400
              ? "invalid"
              : "unavailable",
        );
      if (!r.headers.get("Content-Type")?.startsWith("text/csv"))
        throw new AuditError("unavailable");
      const b = await r.blob();
      if (!controller.signal.aborted) {
        const u = URL.createObjectURL(b),
          a = document.createElement("a");
        a.href = u;
        a.download = "platform-login-audit.csv";
        a.click();
        setTimeout(() => URL.revokeObjectURL(u), 1000);
      }
    } catch (e) {
      if (!controller.signal.aborted) fail(e);
    } finally {
      if (!controller.signal.aborted) {
        working.current = false;
        setBusy(false);
      }
    }
  };
  useEffect(() => () => action.current?.abort(), []);
  const date = (value: string) => new Date(value).toLocaleString(i18n.language);
  const field = (name: string, value: string | undefined) =>
    value ? (
      <>
        <dt>{t(`loginAudit.${name}`)}</dt>
        <dd>{value}</dd>
      </>
    ) : null;
  return (
    <section className="rotation-page login-audit-page" aria-busy={busy}>
      <header>
        <div>
          <h1>{t("loginAudit.title")}</h1>
          <p>{t("loginAudit.hint")}</p>
        </div>
        <div className="rotation-actions">
          <Link to="/console/platform-notifications">{t("loginAudit.notifications")}</Link>
          <button type="button" disabled={busy} onClick={() => setVersion((v) => v + 1)}>
            {t("loginAudit.refresh")}
          </button>
          <button
            type="button"
            disabled={busy || (filters.scope === "all" && !caps.export_all)}
            onClick={() => void exportCSV()}
          >
            {t("loginAudit.export")}
          </button>
        </div>
      </header>
      <p role="status">{notice && t(notice)}</p>
      {error && !eventID && <p role="alert">{t(`loginAudit.errors.${error}`)}</p>}
      <form
        className="login-audit-filters"
        onSubmit={(e) => {
          e.preventDefault();
          setFilters({ ...draft });
          setOffset(0);
          setVersion((v) => v + 1);
        }}
      >
        <label>
          {t("loginAudit.scope")}
          <select
            value={draft.scope}
            onChange={(e) => setDraft({ ...draft, scope: e.target.value })}
          >
            <option value="mine">{t("loginAudit.mine")}</option>
            {caps.view_all && <option value="all">{t("loginAudit.all")}</option>}
          </select>
        </label>
        {(["method", "outcome"] as const).map((key) => (
          <label key={key}>
            {t(`loginAudit.${key}`)}
            <select
              value={draft[key]}
              onChange={(e) => setDraft({ ...draft, [key]: e.target.value })}
            >
              <option value="">{t("loginAudit.any")}</option>
              {(key === "method" ? methods : outcomes).map((v) => (
                <option key={v} value={v}>
                  {t(`loginAudit.${key === "method" ? "methods" : "outcomes"}.${v}`)}
                </option>
              ))}
            </select>
          </label>
        ))}
        {(["q", "source_ip", "from", "to"] as const).map((key) => (
          <label key={key}>
            {t(`loginAudit.${key === "q" ? "query" : key === "source_ip" ? "sourceIP" : key}`)}
            <input
              type={key === "from" || key === "to" ? "datetime-local" : "text"}
              maxLength={128}
              value={draft[key]}
              onChange={(e) => setDraft({ ...draft, [key]: e.target.value })}
            />
          </label>
        ))}
        <button type="submit" disabled={busy}>
          {t("loginAudit.filter")}
        </button>
      </form>
      {summary && (
        <div className="rotation-actions">
          {(["total", "succeeded", "failed", "denied", "challenges"] as const).map((k) => (
            <span key={k}>
              {t(`loginAudit.${k}`)}: <strong>{summary[k]}</strong>
            </span>
          ))}
        </div>
      )}
      {health && (
        <details>
          <summary>
            {t("loginAudit.health")} · {t("loginAudit.retained", { count: health.records })}
          </summary>
          {health.error_code && <p role="alert">{t("loginAudit.storeError")}</p>}
          {health.prune_pending && <p>{t("loginAudit.prune")}</p>}
          {health.aggregation_limited && <p>{t("loginAudit.aggregation")}</p>}
          {health.review_error_code && <p role="alert">{t("loginAudit.sourceError")}</p>}
          {health.review_gap && <p>{t("loginAudit.sourceGap")}</p>}
        </details>
      )}
      <div className="login-audit-table">
        <table>
          <thead>
            <tr>
              {["at", "user", "method", "outcome", "sourceIP", "details"].map((k) => (
                <th key={k} scope="col">
                  {t(`loginAudit.${k}`)}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {rows.map((r) => (
              <tr key={r.id}>
                <td>
                  <time dateTime={r.at}>{date(r.at)}</time>
                </td>
                <td>{r.username || r.attempted_name || t("loginAudit.anonymous")}</td>
                <td>{t(`loginAudit.methods.${r.method}`)}</td>
                <td>{t(`loginAudit.outcomes.${r.outcome}`)}</td>
                <td>{r.source_ip}</td>
                <td>
                  <button type="button" onClick={() => setParams({ event: r.id })}>
                    {t("loginAudit.details")}
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      {!rows.length && <p>{t("loginAudit.empty")}</p>}
      <div className="rotation-actions">
        <button
          type="button"
          disabled={busy || offset === 0}
          onClick={() => setOffset((v) => Math.max(0, v - 25))}
        >
          {t("loginAudit.previous")}
        </button>
        <span>
          {t("loginAudit.pagination", {
            from: total ? offset + 1 : 0,
            to: Math.min(offset + 25, total),
            total,
          })}
        </span>
        <button
          type="button"
          disabled={busy || offset + 25 >= total}
          onClick={() => setOffset((v) => v + 25)}
        >
          {t("loginAudit.next")}
        </button>
      </div>
      <dialog
        ref={dialog}
        className="login-audit-detail"
        aria-labelledby="login-audit-detail-title"
        onCancel={(e) => {
          e.preventDefault();
          close();
        }}
      >
        <h2 id="login-audit-detail-title">{t("loginAudit.details")}</h2>
        <button type="button" onClick={close}>
          {t("loginAudit.close")}
        </button>
        {error && <p role="alert">{t(`loginAudit.errors.${error}`)}</p>}
        {detail ? (
          <>
            <dl>
              {field("at", date(detail.at))}
              {field("user", detail.username || detail.attempted_name || t("loginAudit.anonymous"))}
              {field("method", t(`loginAudit.methods.${detail.method}`))}
              {field("stage", t(`loginAudit.stages.${detail.stage}`))}
              {field("outcome", t(`loginAudit.outcomes.${detail.outcome}`))}
              {field(
                "reason",
                detail.reason ? t(`loginAudit.reasons.${detail.reason}`) : undefined,
              )}
              {field("sourceIP", detail.source_ip)}
              {field("client", detail.client)}
              {field("actor", detail.actor_id)}
              {field("review", detail.review_id)}
              {field(
                "reviewState",
                detail.review_state
                  ? t(`loginAudit.reviews.${detail.review_state}`, {
                      defaultValue: t("loginAudit.unknown"),
                    })
                  : undefined,
              )}
              {field(
                "expires",
                detail.review_expires_at ? date(detail.review_expires_at) : undefined,
              )}
            </dl>
            {detail.can_review &&
              (decision ? (
                <div>
                  <p>{t("loginAudit.confirmHint")}</p>
                  <div className="rotation-actions">
                    <button type="button" disabled={busy} onClick={() => void review()}>
                      {t("loginAudit.confirm")}
                    </button>
                    <button type="button" disabled={busy} onClick={() => setDecision("")}>
                      {t("loginAudit.cancel")}
                    </button>
                  </div>
                </div>
              ) : (
                <div className="rotation-actions">
                  <button type="button" disabled={busy} onClick={() => setDecision("approve")}>
                    {t("loginAudit.approve")}
                  </button>
                  <button type="button" disabled={busy} onClick={() => setDecision("deny")}>
                    {t("loginAudit.deny")}
                  </button>
                </div>
              ))}
          </>
        ) : (
          !error && <p>{t("loginAudit.loading")}</p>
        )}
      </dialog>
    </section>
  );
}
