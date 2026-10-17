import { useCallback, useEffect, useRef, useState } from "react";
import { Link, useParams } from "react-router-dom";
import { useTranslation } from "react-i18next";
import { useAuth } from "../auth/AuthContext";
import "../i18n/locales/features/notifications/register";
import "./rotation-plans.css";
import "./notifications.css";

type Detail = {
  id: string;
  kind: string;
  name: string;
  state: string;
  asset_id?: string;
  account?: string;
  owner?: string;
  command?: string;
  rule?: string;
  method?: string;
  at: string;
  expires_at?: string;
  can_review: boolean;
  review_id?: string;
  accounts?: number;
  open?: number;
  resolved?: number;
};
class SourceError extends Error {
  constructor(public code: string) {
    super(code);
  }
}
export default function NotificationSourcePage() {
  const { kind = "", id = "" } = useParams();
  return <SourceDetail key={kind + "/" + id} kind={kind} id={id} />;
}
function SourceDetail({ kind, id }: { kind: string; id: string }) {
  const { t, i18n } = useTranslation(),
    { accessToken } = useAuth();
  const [detail, setDetail] = useState<Detail | null>(null),
    [error, setError] = useState(""),
    [notice, setNotice] = useState(""),
    [busy, setBusy] = useState(false),
    [confirm, setConfirm] = useState<boolean | null>(null);
  const life = useRef<AbortController | null>(null),
    serial = useRef(0),
    reader = useRef<AbortController | null>(null),
    acting = useRef(false),
    pending = useRef(true),
    confirmation = useRef<HTMLButtonElement | null>(null);
  useEffect(() => {
    life.current = new AbortController();
    return () => life.current?.abort();
  }, []);
  const request = useCallback(
    async (path: string, method = "GET", body?: unknown, signal?: AbortSignal) => {
      const headers = new Headers();
      if (accessToken) headers.set("Authorization", `Bearer ${accessToken}`);
      if (body !== undefined) headers.set("Content-Type", "application/json");
      const signals = [AbortSignal.timeout(30_000)];
      if (life.current) signals.push(life.current.signal);
      if (signal) signals.push(signal);
      const response = await fetch(path, {
        method,
        headers,
        signal: AbortSignal.any(signals),
        ...(body === undefined ? {} : { body: JSON.stringify(body) }),
      });
      if (!response.ok) {
        const code =
          (
            {
              400: "invalid",
              403: "denied",
              404: "not_found",
              409: "conflict",
              429: "capacity",
            } as Record<number, string>
          )[response.status] || "unavailable";
        throw new SourceError(code);
      }
      return response;
    },
    [accessToken],
  );
  const load = useCallback(
    async (signal?: AbortSignal) => {
      const generation = ++serial.current;
      reader.current?.abort();
      const reading = new AbortController();
      reader.current = reading;
      const readSignal = signal ? AbortSignal.any([signal, reading.signal]) : reading.signal;
      try {
        const r = await request(
            `/api/v1/notifications/sources/${encodeURIComponent(kind)}/${encodeURIComponent(id)}`,
            "GET",
            undefined,
            readSignal,
          ),
          v = (await r.json()) as Detail;
        if (readSignal.aborted || life.current?.signal.aborted || generation !== serial.current)
          return;
        pending.current = v.state === "pending" || v.state === "pending_review";
        setDetail(v);
        setError("");
      } catch (e) {
        if (!readSignal.aborted && !life.current?.signal.aborted && generation === serial.current) {
          setDetail(null);
          setConfirm(null);
          pending.current = false;
          setError(e instanceof SourceError ? e.code : "unavailable");
        }
      } finally {
        if (reader.current === reading) reader.current = null;
      }
    },
    [kind, id, request],
  );
  useEffect(() => {
    const controller = new AbortController();
    pending.current = true;
    queueMicrotask(() => {
      if (!controller.signal.aborted) void load(controller.signal);
    });
    const timer = setInterval(() => {
      if (
        pending.current &&
        !reader.current &&
        !acting.current &&
        document.visibilityState !== "hidden"
      )
        void load(controller.signal);
    }, 5000);
    return () => {
      controller.abort();
      clearInterval(timer);
    };
  }, [load]);
  useEffect(() => {
    if (confirm !== null) confirmation.current?.focus();
  }, [confirm]);
  const decide = async (approve: boolean) => {
    if (busy || !detail?.can_review) return;
    acting.current = true;
    serial.current++;
    reader.current?.abort();
    reader.current = null;
    setBusy(true);
    setError("");
    try {
      const actionID = detail.review_id || id;
      const prefix =
        kind === "access-reviews"
          ? `/api/v1/access-reviews/${encodeURIComponent(id)}/`
          : kind === "command-reviews"
            ? `/api/v1/command-reviews/${encodeURIComponent(actionID)}/`
            : `/api/v1/ops/jobs/${encodeURIComponent(id)}/review`;
      const path = kind === "job-security" ? prefix : prefix + (approve ? "approve" : "deny");
      await request(path, "POST", kind === "job-security" ? { approve } : undefined);
      if (life.current?.signal.aborted) return;
      pending.current = false;
      setConfirm(null);
      setNotice("notifications.sourceDecisionSaved");
      setDetail((d) =>
        d ? { ...d, can_review: false, state: approve ? "approved" : "denied" } : d,
      );
      window.dispatchEvent(new Event("jms233-notifications"));
    } catch (e) {
      if (!life.current?.signal.aborted) {
        setConfirm(null);
        await load();
        setError(e instanceof SourceError ? e.code : "unavailable");
      }
    } finally {
      acting.current = false;
      if (!life.current?.signal.aborted) setBusy(false);
    }
  };
  const label = t(`notifications.sourceKinds.${kind}`, {
      defaultValue: t("notifications.sourceDetail"),
    }),
    state = (v: string) =>
      t(`notifications.states.${v}`, { defaultValue: t("notifications.updated") }),
    date = (v: string) => new Date(v).toLocaleString(i18n.language);
  return (
    <section className="rotation-page notifications-page" aria-busy={busy}>
      <header>
        <div>
          <h1>{label}</h1>
          <p>{t("notifications.sourceDetailHint")}</p>
        </div>
        <button type="button" disabled={busy} onClick={() => void load()}>
          {t("notifications.refresh")}
        </button>
      </header>
      <p>
        <Link to="/console/notifications">{t("notifications.backInbox")}</Link>
      </p>
      {error && (
        <p role="alert">
          {t(
            error === "not_found"
              ? "notifications.sourceUnavailable"
              : `notifications.errors.${error}`,
          )}
        </p>
      )}
      <p role="status">{notice && t(notice)}</p>
      {detail && (
        <>
          {detail.name && <h2>{detail.name}</h2>}
          <dl className="notification-source-fields">
            <dt>{t("notifications.state")}</dt>
            <dd>{state(detail.state)}</dd>
            <dt>{t("notifications.sourceID")}</dt>
            <dd>{detail.id}</dd>
            {detail.owner && (
              <>
                <dt>{t("notifications.sourceOwner")}</dt>
                <dd>{detail.owner}</dd>
              </>
            )}
            {detail.account && (
              <>
                <dt>{t("notifications.sourceAccount")}</dt>
                <dd>{detail.account}</dd>
              </>
            )}
            {detail.method && (
              <>
                <dt>{t("notifications.sourceMethod")}</dt>
                <dd>
                  {t(`notifications.methods.${detail.method}`, { defaultValue: detail.method })}
                </dd>
              </>
            )}
            {detail.rule && (
              <>
                <dt>{t("notifications.sourceRule")}</dt>
                <dd>{detail.rule}</dd>
              </>
            )}
            <dt>{t("notifications.at")}</dt>
            <dd>
              <time dateTime={detail.at}>{date(detail.at)}</time>
            </dd>
            {detail.expires_at &&
              (detail.state === "pending" || detail.state === "pending_review") && (
                <>
                  <dt>{t("notifications.sourceExpires")}</dt>
                  <dd>
                    <time dateTime={detail.expires_at}>{date(detail.expires_at)}</time>
                  </dd>
                </>
              )}
          </dl>
          {kind === "agent-events" && <p>{t("notifications.hostReported")}</p>}
          {kind === "account-risks" && (
            <>
              <p>
                {t("notifications.sourceRiskCounts", {
                  accounts: detail.accounts || 0,
                  open: detail.open || 0,
                  resolved: detail.resolved || 0,
                })}
              </p>
              <Link to="/console/account-risks">{t("notifications.openRisks")}</Link>
            </>
          )}
          {detail.command && (
            <>
              <h3>{t("notifications.sourceCommand")}</h3>
              <pre className="notification-command">{detail.command}</pre>
              <p>{t("notifications.sourceCommandHint")}</p>
            </>
          )}
          {detail.can_review && confirm === null && (
            <div className="rotation-actions">
              <button type="button" disabled={busy} onClick={() => setConfirm(true)}>
                {t("notifications.approve")}
              </button>
              <button type="button" disabled={busy} onClick={() => setConfirm(false)}>
                {t("notifications.deny")}
              </button>
            </div>
          )}
          {confirm !== null && detail.can_review && (
            <fieldset className="notification-confirm">
              <legend>{t(confirm ? "notifications.approve" : "notifications.deny")}</legend>
              <p>{t("notifications.sourceConfirm")}</p>
              <div className="rotation-actions">
                <button
                  ref={confirmation}
                  type="button"
                  disabled={busy}
                  onClick={() => void decide(confirm)}
                >
                  {t("notifications.confirmDecision")}
                </button>
                <button type="button" disabled={busy} onClick={() => setConfirm(null)}>
                  {t("notifications.cancel")}
                </button>
              </div>
            </fieldset>
          )}
        </>
      )}
    </section>
  );
}
