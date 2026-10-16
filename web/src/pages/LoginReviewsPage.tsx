import { useCallback, useEffect, useState } from "react";
import { useTranslation } from "react-i18next";
import { useAuth } from "../auth/AuthContext";
import { usePermissions } from "../auth/usePermissions";

type Review = {
  id: string;
  user_id: string;
  username: string;
  source_ip: string;
  auth_source: string;
  rule_name: string;
  rule_revision: number;
  state: string;
  created_at: string;
  expires_at: string;
  reviewed_by?: string;
  reviewed_at?: string;
  can_review: boolean;
};
type Audit = {
  id: string;
  username: string;
  source_ip: string;
  action: string;
  actor_id: string;
  at: string;
};
export default function LoginReviewsPage() {
  const { t, i18n } = useTranslation();
  const { accessToken } = useAuth();
  const { ready, allows } = usePermissions();
  const canManage = allows("reviews.platform_login.manage");
  const [filter, setFilter] = useState("pending");
  const [offset, setOffset] = useState(0);
  const [rows, setRows] = useState<Review[]>([]);
  const [total, setTotal] = useState(0);
  const [audit, setAudit] = useState<Audit[]>([]);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const [decision, setDecision] = useState<{ review: Review; approve: boolean } | null>(null);
  const request = useCallback(
    (path: string, init?: RequestInit) => {
      const headers = new Headers(init?.headers);
      if (accessToken) headers.set("Authorization", `Bearer ${accessToken}`);
      return fetch(path, { ...init, headers });
    },
    [accessToken],
  );
  const load = useCallback(
    async (signal?: AbortSignal) => {
      const responses = await Promise.all([
        request(`/api/v1/login-reviews?state=${filter}&offset=${offset}&limit=25`, { signal }),
        request("/api/v1/login-reviews/audit?limit=50&offset=0", { signal }),
      ]);
      if (responses.some((response) => !response.ok)) throw new Error("login reviews unavailable");
      const [page, events] = (await Promise.all(responses.map((response) => response.json()))) as [
        { results: Review[]; total: number },
        { results: Audit[] },
      ];
      if (!signal?.aborted) {
        setRows(page.results);
        setTotal(page.total);
        setAudit(events.results);
      }
    },
    [request, filter, offset],
  );
  useEffect(() => {
    if (!ready || !canManage) return;
    const c = new AbortController();
    let loading = false;
    const refresh = () => {
      if (c.signal.aborted || loading) return;
      loading = true;
      void load(c.signal)
        .catch(() => {
          if (!c.signal.aborted) setError("unavailable");
        })
        .finally(() => {
          loading = false;
        });
    };
    queueMicrotask(refresh);
    const timer = window.setInterval(refresh, 10000);
    return () => {
      c.abort();
      window.clearInterval(timer);
    };
  }, [ready, canManage, load]);
  async function resolve() {
    if (!decision) return;
    setBusy(true);
    setError("");
    try {
      const response = await request(
        `/api/v1/login-reviews/${decision.review.id}/${decision.approve ? "approve" : "deny"}`,
        { method: "POST" },
      );
      if (!response.ok) {
        const problem = (await response.json()) as { code?: string };
        const code = (problem.code || "").replace("login_review_", "");
        setError(
          ["state", "reviewer", "invalidated", "not_found"].includes(code) ? code : "unavailable",
        );
      }
      setDecision(null);
      await load();
    } catch {
      setError("unavailable");
    } finally {
      setBusy(false);
    }
  }
  const time = (value: string) => new Date(value).toLocaleString(i18n.language);
  if (!ready) return <p className="placeholder">{t("placeholder.skeleton")}</p>;
  if (!canManage)
    return (
      <section className="jobs-page">
        <h1>{t("platformReview.title")}</h1>
        <p>{t("platformReview.denied")}</p>
      </section>
    );
  return (
    <section className="jobs-page platform-reviews-page">
      <header className="jobs-heading">
        <div>
          <h1>{t("platformReview.title")}</h1>
          <p>{t("platformReview.description")}</p>
        </div>
        <button
          type="button"
          onClick={() => {
            setError("");
            void load().catch(() => setError("unavailable"));
          }}
        >
          {t("acl.refresh")}
        </button>
      </header>
      {error && (
        <p role="alert" className="login-error">
          {t(`platformReview.errors.${error}`)}
        </p>
      )}
      <div className="acl-tabs" role="group" aria-label={t("platformReview.filtersLabel")}>
        {["pending", "notified", ""].map((value) => (
          <button
            type="button"
            key={value}
            aria-pressed={filter === value}
            onClick={() => {
              setFilter(value);
              setOffset(0);
            }}
          >
            {t(`platformReview.filters.${value || "all"}`)}
          </button>
        ))}
      </div>
      <div className="jobs-table-scroll">
        <table className="jobs-table" aria-label={t("platformReview.requestsLabel")}>
          <thead>
            <tr>
              <th>{t("platformReview.user")}</th>
              <th>{t("acl.sourceLabel")}</th>
              <th>{t("platformReview.authSource")}</th>
              <th>{t("platformReview.policy")}</th>
              <th>{t("acl.at")}</th>
              <th>{t("platformReview.state")}</th>
              <th>{t("acl.operations")}</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((row) => (
              <tr key={row.id}>
                <td>
                  {row.username}
                  <small className="review-request-id">{row.id}</small>
                </td>
                <td>{row.source_ip}</td>
                <td>{t(`platformReview.sources.${row.auth_source}`)}</td>
                <td>{row.rule_name}</td>
                <td>
                  {time(row.created_at)}
                  {(row.state === "pending" || row.state === "approved") && (
                    <small className="review-request-id">
                      {t("platformReview.expires", {
                        time: time(
                          row.state === "approved" && row.reviewed_at
                            ? new Date(
                                Math.min(
                                  Date.parse(row.expires_at),
                                  Date.parse(row.reviewed_at) + 60_000,
                                ),
                              ).toISOString()
                            : row.expires_at,
                        ),
                      })}
                    </small>
                  )}
                </td>
                <td>{t(`platformReview.states.${row.state}`)}</td>
                <td>
                  {row.state === "pending" && (
                    <div className="acl-row-actions">
                      <button
                        type="button"
                        disabled={busy || !row.can_review}
                        onClick={() => setDecision({ review: row, approve: true })}
                      >
                        {t("platformReview.approve")}
                      </button>
                      <button
                        type="button"
                        disabled={busy || !row.can_review}
                        onClick={() => setDecision({ review: row, approve: false })}
                      >
                        {t("platformReview.reject")}
                      </button>
                    </div>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
        {rows.length === 0 && <p>{t("platformReview.empty")}</p>}
      </div>
      <div className="acl-row-actions">
        <button
          type="button"
          disabled={offset === 0}
          onClick={() => setOffset(Math.max(0, offset - 25))}
        >
          {t("acl.previous")}
        </button>
        <span>{t("platformReview.count", { count: total })}</span>
        <button
          type="button"
          disabled={offset + 25 >= total}
          onClick={() => setOffset(offset + 25)}
        >
          {t("acl.next")}
        </button>
      </div>
      <h2>{t("platformReview.auditTitle")}</h2>
      <p>{t("platformReview.retention")}</p>
      <div className="jobs-table-scroll">
        <table className="jobs-table">
          <thead>
            <tr>
              <th>{t("acl.at")}</th>
              <th>{t("platformReview.user")}</th>
              <th>{t("acl.sourceLabel")}</th>
              <th>{t("acl.action")}</th>
              <th>{t("platformReview.reviewer")}</th>
            </tr>
          </thead>
          <tbody>
            {audit.map((event) => (
              <tr key={event.id}>
                <td>{time(event.at)}</td>
                <td>{event.username}</td>
                <td>{event.source_ip}</td>
                <td>{t(`platformReview.states.${event.action}`)}</td>
                <td>{event.actor_id}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      {decision && (
        <div className="asset-modal-backdrop">
          <section
            className="asset-modal"
            role="dialog"
            aria-modal="true"
            aria-label={t(
              decision.approve ? "platformReview.approveTitle" : "platformReview.denyTitle",
            )}
          >
            <h2>
              {t(decision.approve ? "platformReview.approveTitle" : "platformReview.denyTitle")}
            </h2>
            <p>
              {t("platformReview.confirm", {
                user: decision.review.username,
                source: decision.review.source_ip,
              })}
            </p>
            <p>
              {t("platformReview.requestID")} <code>{decision.review.id}</code>
            </p>
            <p>{t("platformReview.confirmHint")}</p>
            <div className="asset-modal-actions">
              <button type="button" disabled={busy} onClick={() => setDecision(null)}>
                {t("acl.cancel")}
              </button>
              <button
                type="button"
                disabled={busy}
                onClick={() => {
                  void resolve();
                }}
              >
                {t(decision.approve ? "platformReview.approve" : "platformReview.reject")}
              </button>
            </div>
          </section>
        </div>
      )}
    </section>
  );
}
