import { useEffect, useRef, useState } from "react";
import { useTranslation } from "react-i18next";

export type LoginReviewPending = { review_id: string; expires_at: string; state?: string };
export default function LoginReviewPanel({
  pending,
  onComplete,
  onCancel,
}: {
  pending: LoginReviewPending;
  onComplete: () => void;
  onCancel: () => void;
}) {
  const { t, i18n } = useTranslation();
  const [state, setState] = useState(pending.state || "pending");
  const [error, setError] = useState(false);
  const [cancelling, setCancelling] = useState(false);
  const [expiresAt, setExpiresAt] = useState(pending.expires_at);
  const stopped = useRef(false);
  const polling = useRef<AbortController | null>(null);
  useEffect(() => {
    const c = new AbortController();
    let inFlight = false;
    polling.current = c;
    stopped.current = false;
    async function recover() {
      const identity = await fetch("/api/v1/authentication/session/", { signal: c.signal });
      if (identity.ok && !c.signal.aborted && !stopped.current) {
        onComplete();
        return true;
      }
      return false;
    }
    async function poll() {
      if (c.signal.aborted || stopped.current || inFlight) return;
      inFlight = true;
      try {
        const response = await fetch("/api/v1/authentication/login-review/status", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: "{}",
          signal: c.signal,
        });
        if (!response.ok) throw new Error("review status unavailable");
        const current = (await response.json()) as {
          active: boolean;
          state?: string;
          expires_at?: string;
        };
        if (c.signal.aborted) return;
        if (!current.active) {
          if (!(await recover())) setState("expired");
          return;
        }
        if (current.expires_at) setExpiresAt(current.expires_at);
        const value = current.state || "invalidated";
        setState(value);
        setError(false);
        if (value === "consumed") {
          await recover();
          return;
        }
        if (value === "approved") {
          const finish = await fetch("/api/v1/authentication/login-review/complete", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: "{}",
            signal: c.signal,
          });
          const result = (await finish.json()) as { browser_session?: boolean; code?: string };
          if (c.signal.aborted) return;
          if (!finish.ok) {
            if (result.code === "login_review_invalidated") {
              setState("invalidated");
              return;
            }
            throw new Error("review completion failed");
          }
          if (!result.browser_session) throw new Error("browser session missing");
          if (!stopped.current) onComplete();
        }
      } catch {
        if (!c.signal.aborted) setError(true);
      } finally {
        inFlight = false;
      }
    }
    queueMicrotask(() => {
      if (!c.signal.aborted) void poll();
    });
    const timer = window.setInterval(() => {
      void poll();
    }, 2000);
    return () => {
      c.abort();
      window.clearInterval(timer);
    };
  }, [pending.review_id, onComplete]);
  async function cancel() {
    stopped.current = true;
    polling.current?.abort();
    setCancelling(true);
    setError(false);
    try {
      const response = await fetch("/api/v1/authentication/login-review/cancel", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: "{}",
      });
      if (!response.ok) throw new Error("review cancellation failed");
      onCancel();
    } catch {
      setError(true);
    } finally {
      setCancelling(false);
    }
  }
  const waiting = state === "pending" || state === "approved";
  return (
    <section className="login-review-panel" aria-label={t("platformReview.waitTitle")}>
      <h2>{t("platformReview.waitTitle")}</h2>
      <p role="status" aria-live="polite">
        {t(`platformReview.states.${state}`)}
      </p>
      <p>{t("platformReview.waitHint")}</p>
      <p>
        {t("platformReview.requestID")} <code>{pending.review_id}</code>
      </p>
      <p>
        {t("platformReview.expires", {
          time: new Date(expiresAt).toLocaleTimeString(i18n.language),
        })}
      </p>
      {error && (
        <p role="alert" className="login-error">
          {t("platformReview.error")}
        </p>
      )}
      <button
        type="button"
        disabled={cancelling}
        onClick={() => {
          void cancel();
        }}
      >
        {t(waiting ? "platformReview.cancel" : "platformReview.restart")}
      </button>
    </section>
  );
}
