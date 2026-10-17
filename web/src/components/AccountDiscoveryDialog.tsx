import { useCallback, useEffect, useRef, useState } from "react";
import { useTranslation } from "react-i18next";
import { toggleLang } from "../i18n";
import { usePermissions } from "../auth/usePermissions";
import "./account-discovery.css";

type Finding = {
  id: string;
  username: string;
  uid: number;
  gid: number;
  home: string;
  shell: string;
  present: boolean;
  review: string;
  note: string;
  last_seen: string;
};
type Page = {
  results: Finding[];
  total: number;
  revision: number;
  last?: { observed: number; new: number; missing: number; at: string };
};
type Job = { id: string; state: string; stdout?: string; error_code?: string };
type Audit = {
  at: string;
  actor: { name: string };
  action: string;
  finding_id?: string;
  before?: string;
  after?: string;
  note?: string;
  summary?: { observed: number; new: number; missing: number };
};
const activeJob = (j: Job | null) => j && ["running", "pending_review"].includes(j.state);
export default function AccountDiscoveryDialog({
  assetId,
  assetName,
  accessToken,
  canConnect,
  onClose,
}: {
  assetId: string;
  assetName: string;
  accessToken: string;
  canConnect: boolean;
  onClose: () => void;
}) {
  const { t, i18n } = useTranslation();
  const { allows } = usePermissions();
  const [page, setPage] = useState<Page>({ results: [], total: 0, revision: 0 }),
    [offset, setOffset] = useState(0),
    [failed, setFailed] = useState(false),
    [busy, setBusy] = useState(false),
    [job, setJob] = useState<Job | null>(null),
    [reviewID, setReviewID] = useState("");
  const [editing, setEditing] = useState<Finding | null>(null),
    [review, setReview] = useState("unreviewed"),
    [note, setNote] = useState("");
  const [auditOpen, setAuditOpen] = useState(false),
    [audit, setAudit] = useState<{ results: Audit[]; total: number }>({ results: [], total: 0 }),
    [auditOffset, setAuditOffset] = useState(0);
  const [reload, setReload] = useState(0);
  const requestID = useRef("");
  const request = useCallback(
    (path: string, init?: RequestInit) => {
      const headers = new Headers(init?.headers);
      if (accessToken) headers.set("Authorization", `Bearer ${accessToken}`);
      return fetch(path, { ...init, headers });
    },
    [accessToken],
  );
  const base = `/api/v1/assets/${encodeURIComponent(assetId)}`;
  let failureCode = "";
  try {
    const code = JSON.parse(job?.stdout || "{}").error_code;
    if (
      [
        "unsupported_platform",
        "integrity_failed",
        "inventory_changed",
        "storage_full",
        "access_denied",
        "unavailable",
      ].includes(code)
    )
      failureCode = code;
  } catch {
    /* A failed job can have no structured result. */
  }
  useEffect(() => {
    const c = new AbortController();
    void request(`${base}/discovered-accounts?offset=${offset}&limit=20`, { signal: c.signal })
      .then(async (r) => {
        if (!r.ok) throw Error();
        const data = await r.json();
        if (!c.signal.aborted) {
          setPage(data);
          setFailed(false);
        }
      })
      .catch(() => {
        if (!c.signal.aborted) setFailed(true);
      });
    return () => c.abort();
  }, [base, offset, reload, request]);
  useEffect(() => {
    if (!auditOpen) return;
    const c = new AbortController();
    void request(`${base}/discovered-accounts/audit?offset=${auditOffset}&limit=20`, {
      signal: c.signal,
    })
      .then(async (r) => {
        if (!r.ok) throw Error();
        const data = await r.json();
        if (!c.signal.aborted) setAudit(data);
      })
      .catch(() => {
        if (!c.signal.aborted) setFailed(true);
      });
    return () => c.abort();
  }, [base, auditOpen, auditOffset, reload, request]);
  useEffect(() => {
    if (!activeJob(job)) return;
    const c = new AbortController();
    let timer: ReturnType<typeof setTimeout>;
    const poll = () => {
      void request(`/api/v1/ops/jobs/${job!.id}`, { signal: c.signal })
        .then(async (r) => {
          if (!r.ok) throw Error();
          const next = (await r.json()) as Job;
          if (!c.signal.aborted) {
            setJob(next);
            if (!activeJob(next)) {
              setReload((v) => v + 1);
            }
          }
        })
        .catch(() => {
          if (!c.signal.aborted) {
            setFailed(true);
            // A transient failure must not leave an active job stuck forever.
            timer = setTimeout(poll, 2000);
          }
        });
    };
    timer = setTimeout(poll, 750);
    return () => {
      clearTimeout(timer);
      c.abort();
    };
  }, [job, request]);
  useEffect(() => {
    const key = (e: KeyboardEvent) => {
      if (e.key === "Escape") onClose();
    };
    window.addEventListener("keydown", key);
    return () => window.removeEventListener("keydown", key);
  }, [onClose]);
  async function collect() {
    setBusy(true);
    setFailed(false);
    if (!requestID.current) requestID.current = crypto.randomUUID();
    try {
      const r = await request(`${base}/account-discovery/jobs`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          request_id: requestID.current,
          review_id: reviewID,
          timeout_seconds: 180,
        }),
      });
      if (!r.ok) throw Error();
      const result = await r.json();
      if (r.status === 202) {
        setReviewID(result.review_id);
        return;
      }
      setJob(result);
      setReviewID("");
      requestID.current = "";
      if (!activeJob(result)) setReload((v) => v + 1);
    } catch {
      setFailed(true);
    } finally {
      setBusy(false);
    }
  }
  async function saveReview() {
    if (!editing) return;
    setBusy(true);
    try {
      const r = await request(`${base}/discovered-accounts/${editing.id}`, {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ review, note, revision: page.revision }),
      });
      if (!r.ok) throw Error();
      setEditing(null);
      setReload((v) => v + 1);
      setFailed(false);
    } catch {
      setFailed(true);
    } finally {
      setBusy(false);
    }
  }
  return (
    <div className="asset-modal-backdrop">
      <section
        className="asset-modal account-discovery-dialog"
        role="dialog"
        aria-modal="true"
        aria-labelledby="account-discovery-title"
      >
        <header>
          <h2 id="account-discovery-title">{t("accountDiscovery.title", { name: assetName })}</h2>
          <div className="account-discovery-actions">
            <button type="button" className="button-secondary" onClick={() => void toggleLang()}>
              {t("sharing.language")}
            </button>
            <button type="button" className="button-secondary" onClick={onClose}>
              {t("audit.closeCommands")}
            </button>
          </div>
        </header>
        <p className="settings-help">{t("accountDiscovery.hint")}</p>
        <div className="account-discovery-actions">
          {allows("accounts.discover") && canConnect && (
            <button
              type="button"
              className="button-primary"
              disabled={busy || Boolean(activeJob(job))}
              onClick={() => void collect()}
            >
              {t(reviewID ? "accountDiscovery.retry" : "accountDiscovery.collect")}
            </button>
          )}
          <button
            type="button"
            className="button-secondary"
            onClick={() => setReload((v) => v + 1)}
          >
            {t("audit.refresh")}
          </button>
          <button
            type="button"
            className="button-secondary"
            onClick={() => setAuditOpen((v) => !v)}
          >
            {t("accountDiscovery.audit")}
          </button>
        </div>
        {failed && (
          <p className="asset-error" role="alert">
            {t("accountDiscovery.failed")}
          </p>
        )}
        {reviewID && <p role="status">{t("accountDiscovery.loginReview", { id: reviewID })}</p>}
        {job && (
          <p role="status">
            {t("accountDiscovery.job", { id: job.id })} · {t(`jobs.states.${job.state}`)}
          </p>
        )}
        {job && !["succeeded", "running", "pending_review"].includes(job.state) && (
          <p className="asset-error" role="alert">
            {t(
              failureCode ? `accountDiscovery.errors.${failureCode}` : "accountDiscovery.jobFailed",
            )}
          </p>
        )}
        {page.last && (
          <p>
            {t("accountDiscovery.summary", {
              count: page.last.observed,
              new: page.last.new,
              missing: page.last.missing,
            })}{" "}
            ·{" "}
            <time dateTime={page.last.at}>
              {new Date(page.last.at).toLocaleString(i18n.language)}
            </time>
          </p>
        )}
        <div className="account-discovery-table">
          <table>
            <thead>
              <tr>
                <th>{t("accountDiscovery.account")}</th>
                <th>{t("accountDiscovery.ids")}</th>
                <th>{t("accountDiscovery.presence")}</th>
                <th>{t("accountDiscovery.review")}</th>
                <th>{t("assets.actions")}</th>
              </tr>
            </thead>
            <tbody>
              {page.results.map((row) => (
                <tr key={row.id}>
                  <td>
                    <strong>{row.username}</strong>
                    {row.uid === 0 && <small>{t("accountDiscovery.uidZero")}</small>}
                    <details>
                      <summary>{t("accountDiscovery.paths")}</summary>
                      <p>{row.home || "—"}</p>
                      <p>{row.shell || "—"}</p>
                      <p>{row.note}</p>
                    </details>
                  </td>
                  <td>
                    {row.uid} / {row.gid}
                  </td>
                  <td>
                    {t(row.present ? "accountDiscovery.present" : "accountDiscovery.missing")}
                  </td>
                  <td>{t(`accountDiscovery.states.${row.review}`)}</td>
                  <td>
                    {allows("accounts.review") && (
                      <button
                        type="button"
                        className="button-text"
                        onClick={() => {
                          setEditing(row);
                          setReview(row.review);
                          setNote(row.note);
                        }}
                      >
                        {t("assets.edit")}
                      </button>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        {page.results.length === 0 && <p>{t("accountDiscovery.empty")}</p>}
        <div className="account-discovery-actions">
          <button
            type="button"
            className="button-secondary"
            disabled={offset === 0}
            onClick={() => setOffset((v) => Math.max(0, v - 20))}
          >
            {t("audit.previous")}
          </button>
          <span>
            {t("audit.showing", {
              from: page.total ? offset + 1 : 0,
              to: Math.min(page.total, offset + page.results.length),
              total: page.total,
            })}
          </span>
          <button
            type="button"
            className="button-secondary"
            disabled={offset + page.results.length >= page.total}
            onClick={() => setOffset((v) => v + 20)}
          >
            {t("audit.next")}
          </button>
        </div>
        {editing && (
          <form
            className="account-discovery-review"
            onSubmit={(e) => {
              e.preventDefault();
              void saveReview();
            }}
          >
            <h3>{editing.username}</h3>
            <label>
              {t("accountDiscovery.review")}
              <select
                aria-label={t("accountDiscovery.review")}
                value={review}
                onChange={(e) => setReview(e.target.value)}
              >
                {["unreviewed", "acknowledged", "ignored"].map((v) => (
                  <option key={v} value={v}>
                    {t(`accountDiscovery.states.${v}`)}
                  </option>
                ))}
              </select>
            </label>
            <label>
              {t("accountDiscovery.note")}
              <input
                aria-label={t("accountDiscovery.note")}
                value={note}
                maxLength={512}
                onChange={(e) => setNote(e.target.value)}
              />
            </label>
            <div className="account-discovery-actions">
              <button type="submit" className="button-primary" disabled={busy}>
                {t("assets.save")}
              </button>
              <button type="button" className="button-secondary" onClick={() => setEditing(null)}>
                {t("assets.cancel")}
              </button>
            </div>
          </form>
        )}
        {auditOpen && (
          <section aria-label={t("accountDiscovery.audit")}>
            <h3>{t("accountDiscovery.audit")}</h3>
            {audit.results.map((a, i) => (
              <p key={`${a.at}-${i}`}>
                <time dateTime={a.at}>{new Date(a.at).toLocaleString(i18n.language)}</time> ·{" "}
                {a.actor.name} ·{" "}
                {t(
                  a.action === "collected"
                    ? "accountDiscovery.collected"
                    : "accountDiscovery.reviewed",
                )}
                {a.summary &&
                  ` · ${t("accountDiscovery.summary", { count: a.summary.observed, new: a.summary.new, missing: a.summary.missing })}`}
                {a.after && ` · ${t(`accountDiscovery.states.${a.after}`)}`} {a.note}
              </p>
            ))}
            <div className="account-discovery-actions">
              <button
                type="button"
                className="button-secondary"
                disabled={auditOffset === 0}
                onClick={() => setAuditOffset((v) => Math.max(0, v - 20))}
              >
                {t("audit.previous")}
              </button>
              <button
                type="button"
                className="button-secondary"
                disabled={auditOffset + audit.results.length >= audit.total}
                onClick={() => setAuditOffset((v) => v + 20)}
              >
                {t("audit.next")}
              </button>
            </div>
          </section>
        )}
      </section>
    </div>
  );
}
