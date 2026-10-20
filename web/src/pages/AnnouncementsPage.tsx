import { useCallback, useEffect, useRef, useState, type FormEvent } from "react";
import { useTranslation } from "react-i18next";
import { useAuth } from "../auth/AuthContext";
import "../i18n/locales/features/announcements/register";
import "./AnnouncementsPage.css";

type Text = { en: string; "zh-CN": string };
type Notice = {
  id: string;
  title: Text;
  body: Text;
  severity: "info" | "maintenance" | "security";
  published: boolean;
  pinned: boolean;
  starts_at?: string;
  ends_at?: string;
  revision: number;
  updated_at: string;
  read: boolean;
};
type Draft = {
  id: string;
  title: Text;
  body: Text;
  severity: Notice["severity"];
  published: boolean;
  pinned: boolean;
  starts_at: string;
  ends_at: string;
  revision: number;
};
type Page = { results: Notice[]; total: number; unread: number };
type Audit = { at: string; actor_id: string; action: string; notice_id: string; revision: number };
const fresh = (): Draft => ({
  id: "",
  title: { en: "", "zh-CN": "" },
  body: { en: "", "zh-CN": "" },
  severity: "info",
  published: false,
  pinned: false,
  starts_at: "",
  ends_at: "",
  revision: 0,
});
const nonce = () =>
  Array.from(crypto.getRandomValues(new Uint8Array(16)), (b) =>
    b.toString(16).padStart(2, "0"),
  ).join("");
const localDate = (value?: string) =>
  value
    ? new Date(Date.parse(value) - new Date(value).getTimezoneOffset() * 60000)
        .toISOString()
        .slice(0, 16)
    : "";

export default function AnnouncementsPage() {
  const { t, i18n } = useTranslation();
  const { accessToken } = useAuth();
  const [data, setData] = useState<Page>({ results: [], total: 0, unread: 0 });
  const [canManage, setCanManage] = useState(false);
  const [manage, setManage] = useState(false);
  const [offset, setOffset] = useState(0);
  const [draft, setDraft] = useState<Draft | null>(null);
  const [busy, setBusy] = useState(false);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [message, setMessage] = useState("");
  const [refresh, setRefresh] = useState(0);
  const [audit, setAudit] = useState<Audit[]>([]);
  const requestID = useRef(nonce());
  const deletions = useRef<Record<string, string>>({});
  const request = useCallback(
    async (path: string, method = "GET", body?: unknown, signal?: AbortSignal) => {
      const response = await fetch("/api/v1/announcements" + path, {
        method,
        signal,
        credentials: "same-origin",
        headers: {
          ...(accessToken ? { Authorization: `Bearer ${accessToken}` } : {}),
          ...(body === undefined ? {} : { "Content-Type": "application/json" }),
        },
        ...(body === undefined ? {} : { body: JSON.stringify(body) }),
      });
      if (!response.ok) {
        const value = await response.json().catch(() => ({}));
        throw Error(value.error_code || "unavailable");
      }
      return response.status === 204 ? null : response.json();
    },
    [accessToken],
  );
  useEffect(() => {
    const c = new AbortController();
    void request("/permissions", "GET", undefined, c.signal)
      .then((v) => {
        if (!c.signal.aborted) setCanManage(v.manage);
      })
      .catch((e) => {
        if (!c.signal.aborted) setError(e.message);
      });
    return () => c.abort();
  }, [request]);
  useEffect(() => {
    const c = new AbortController();
    queueMicrotask(() => {
      if (!c.signal.aborted) setLoading(true);
    });
    void request(`?manage=${manage}&offset=${offset}&limit=20`, "GET", undefined, c.signal)
      .then((v) => {
        if (!c.signal.aborted) {
          setData(v);
          setError("");
        }
      })
      .catch((e) => {
        if (!c.signal.aborted) setError(e.message);
      })
      .finally(() => {
        if (!c.signal.aborted) setLoading(false);
      });
    return () => c.abort();
  }, [request, manage, offset, refresh]);
  const text = (notice: Notice, field: "title" | "body") => {
    const preferred = i18n.language.startsWith("zh") ? "zh-CN" : "en";
    const language =
      notice.title[preferred] && notice.body[preferred]
        ? preferred
        : preferred === "en"
          ? "zh-CN"
          : "en";
    return notice[field][language];
  };
  const changed = (value: Draft) => {
    setDraft(value);
    requestID.current = nonce();
    setMessage("");
  };
  const edit = (value?: Notice) => {
    requestID.current = nonce();
    setDraft(
      value
        ? { ...value, starts_at: localDate(value.starts_at), ends_at: localDate(value.ends_at) }
        : fresh(),
    );
    setError("");
    setMessage("");
  };
  async function save(event: FormEvent) {
    event.preventDefault();
    if (!draft || busy) return;
    setBusy(true);
    setError("");
    try {
      await request(draft.id ? "/" + draft.id : "", draft.id ? "PUT" : "POST", {
        title: draft.title,
        body: draft.body,
        severity: draft.severity,
        published: draft.published,
        pinned: draft.pinned,
        revision: draft.revision,
        starts_at: draft.starts_at ? new Date(draft.starts_at).toISOString() : undefined,
        ends_at: draft.ends_at ? new Date(draft.ends_at).toISOString() : undefined,
        request_id: requestID.current,
      });
      setDraft(null);
      setMessage(t("announcements.saved"));
      setRefresh((v) => v + 1);
    } catch (e) {
      setError(e instanceof Error ? e.message : "unavailable");
    } finally {
      setBusy(false);
    }
  }
  async function remove(n: Notice) {
    if (busy || !window.confirm(t("announcements.confirmDelete"))) return;
    setBusy(true);
    setError("");
    const key = n.id + ":" + n.revision;
    deletions.current[key] ??= nonce();
    try {
      await request("/" + n.id, "DELETE", {
        revision: n.revision,
        request_id: deletions.current[key],
      });
      delete deletions.current[key];
      setMessage(t("announcements.removed"));
      setRefresh((v) => v + 1);
    } catch (e) {
      setError(e instanceof Error ? e.message : "unavailable");
    } finally {
      setBusy(false);
    }
  }
  async function read(n: Notice) {
    if (busy) return;
    setBusy(true);
    setError("");
    try {
      await request("/" + n.id + "/read", "POST", { revision: n.revision });
      setMessage(t("announcements.acknowledged"));
      setRefresh((v) => v + 1);
    } catch (e) {
      setError(e instanceof Error ? e.message : "unavailable");
    } finally {
      setBusy(false);
    }
  }
  return (
    <section className="announcements-page" aria-labelledby="announcements-title">
      <h1 id="announcements-title">{t("announcements.title")}</h1>
      <p>{t("announcements.description")}</p>
      <div className="announcements-toolbar">
        <span>{t("announcements.unreadCount", { count: data.unread })}</span>
        <button type="button" disabled={busy || loading} onClick={() => setRefresh((v) => v + 1)}>
          {t("announcements.refresh")}
        </button>
        {canManage && (
          <>
            <label>
              <input
                type="checkbox"
                checked={manage}
                disabled={busy}
                onChange={(e) => {
                  setManage(e.target.checked);
                  setOffset(0);
                  setDraft(null);
                }}
              />
              {t("announcements.manage")}
            </label>
            {manage && (
              <button type="button" disabled={busy} onClick={() => edit()}>
                {t("announcements.new")}
              </button>
            )}
          </>
        )}
      </div>
      {error && (
        <p role="alert">
          {t(`announcements.errors.${error}`, {
            defaultValue: t("announcements.errors.unavailable"),
          })}
        </p>
      )}
      {message && <p role="status">{message}</p>}
      {draft && canManage && manage && (
        <form
          className="announcement-editor"
          aria-label={t("announcements.edit")}
          onSubmit={(e) => void save(e)}
        >
          <p>{t("announcements.languageHint")}</p>
          {(["en", "zh-CN"] as const).map((lang) => (
            <div key={lang}>
              <label>
                {t(lang === "en" ? "announcements.titleEn" : "announcements.titleZh")}
                <input
                  maxLength={200}
                  value={draft.title[lang]}
                  disabled={busy}
                  onChange={(e) =>
                    changed({ ...draft, title: { ...draft.title, [lang]: e.target.value } })
                  }
                />
              </label>
              <label>
                {t(lang === "en" ? "announcements.bodyEn" : "announcements.bodyZh")}
                <textarea
                  rows={6}
                  maxLength={16000}
                  value={draft.body[lang]}
                  disabled={busy}
                  onChange={(e) =>
                    changed({ ...draft, body: { ...draft.body, [lang]: e.target.value } })
                  }
                />
              </label>
            </div>
          ))}
          <label>
            {t("announcements.severity")}
            <select
              value={draft.severity}
              disabled={busy}
              onChange={(e) =>
                changed({ ...draft, severity: e.target.value as Notice["severity"] })
              }
            >
              {(["info", "maintenance", "security"] as const).map((v) => (
                <option key={v} value={v}>
                  {t("announcements." + v)}
                </option>
              ))}
            </select>
          </label>
          <label>
            {t("announcements.starts")}
            <input
              type="datetime-local"
              value={draft.starts_at}
              disabled={busy}
              onChange={(e) => changed({ ...draft, starts_at: e.target.value })}
            />
          </label>
          <label>
            {t("announcements.ends")}
            <input
              type="datetime-local"
              value={draft.ends_at}
              disabled={busy}
              onChange={(e) => changed({ ...draft, ends_at: e.target.value })}
            />
          </label>
          <p>{t("announcements.timeHint")}</p>
          <label>
            <input
              type="checkbox"
              checked={draft.published}
              disabled={busy}
              onChange={(e) => changed({ ...draft, published: e.target.checked })}
            />
            {t("announcements.published")}
          </label>
          <label>
            <input
              type="checkbox"
              checked={draft.pinned}
              disabled={busy}
              onChange={(e) => changed({ ...draft, pinned: e.target.checked })}
            />
            {t("announcements.pinned")}
          </label>
          <div className="announcements-toolbar">
            <button type="submit" disabled={busy}>
              {t(busy ? "announcements.saving" : "announcements.save")}
            </button>
            <button type="button" disabled={busy} onClick={() => setDraft(null)}>
              {t("announcements.cancel")}
            </button>
          </div>
        </form>
      )}
      {loading ? (
        <p role="status">{t("announcements.loading")}</p>
      ) : data.results.length === 0 ? (
        <p>{t("announcements.empty")}</p>
      ) : (
        data.results.map((n) => (
          <article key={n.id} className="announcement-card" aria-labelledby={n.id + "-title"}>
            <header>
              <h2 id={n.id + "-title"}>{text(n, "title")}</h2>
              <span>{t("announcements." + n.severity)}</span>
              <span>{t(n.read ? "announcements.read" : "announcements.unread")}</span>
              {manage && (
                <span>{t(n.published ? "announcements.published" : "announcements.draft")}</span>
              )}
            </header>
            <p className="announcement-body">{text(n, "body")}</p>
            <small>
              {t("announcements.revision", { revision: n.revision })} · {t("announcements.updated")}
              : {new Date(n.updated_at).toLocaleString(i18n.language)}
            </small>
            <div className="announcements-toolbar">
              {!manage && !n.read && (
                <button type="button" disabled={busy} onClick={() => void read(n)}>
                  {t("announcements.markRead")}
                </button>
              )}
              {manage && canManage && (
                <>
                  <button type="button" disabled={busy} onClick={() => edit(n)}>
                    {t("announcements.edit")}
                  </button>
                  <button type="button" disabled={busy} onClick={() => void remove(n)}>
                    {t("announcements.delete")}
                  </button>
                </>
              )}
            </div>
          </article>
        ))
      )}
      <nav className="announcements-toolbar" aria-label={t("announcements.title")}>
        <button
          type="button"
          disabled={loading || busy || offset === 0}
          onClick={() => setOffset((v) => Math.max(0, v - 20))}
        >
          {t("announcements.previous")}
        </button>
        <span>
          {t("announcements.page", {
            offset: data.total ? offset + 1 : 0,
            end: Math.min(offset + 20, data.total),
            total: data.total,
          })}
        </span>
        <button
          type="button"
          disabled={loading || busy || offset + 20 >= data.total}
          onClick={() => setOffset((v) => v + 20)}
        >
          {t("announcements.next")}
        </button>
      </nav>
      {canManage && manage && (
        <details
          onToggle={(e) => {
            if (e.currentTarget.open)
              void request("/audit?limit=20")
                .then((v) => setAudit(v.results))
                .catch((e) => setError(e.message));
          }}
        >
          <summary>{t("announcements.audit")}</summary>
          {audit.map((a, i) => (
            <p key={a.at + i}>
              <time>{new Date(a.at).toLocaleString(i18n.language)}</time> ·{" "}
              <code>{a.actor_id}</code> · {t("announcements.actions." + a.action)} ·{" "}
              <code>{a.notice_id}</code> · {a.revision}
            </p>
          ))}
        </details>
      )}
    </section>
  );
}
