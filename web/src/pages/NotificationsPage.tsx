import { requestID as newRequestID } from "../utils/requestID";
import { useCallback, useEffect, useRef, useState } from "react";
import { useTranslation } from "react-i18next";
import { Link } from "react-router-dom";
import { useAuth } from "../auth/AuthContext";
import { usePermissions } from "../auth/usePermissions";
import NativeNotificationFields, {
  nativeChannel,
  type NativeChannel,
} from "../components/NativeNotificationFields";
import "../i18n/locales/features/notifications/register";
import "./rotation-plans.css";
import "./notifications.css";

type Page<T> = { results: T[]; total: number };
type Message = {
  id: string;
  topic: string;
  name: string;
  state: string;
  at: string;
  read_at?: string;
  link: string;
  source: { id: string };
};
type Delivery = {
  id: string;
  can_retry: boolean;
  user_id: string;
  channel: string;
  state: string;
  destination: string;
  revision: number;
  attempts: number;
  error_code?: string;
  created_at: string;
  next_attempt?: string;
};
type Preferences = {
  revision: number;
  language: string;
  detected_language: string;
  email: string;
  phone: string;
  email_verified: boolean;
  phone_verified: boolean;
  topics: Record<string, string[]>;
};
type SMTP = {
  enabled: boolean;
  host: string;
  port: number;
  mode: string;
  username: string;
  from: string;
  subject_prefix: string;
  ca: string;
  password_configured: boolean;
};
type HTTPChannel = NativeChannel;
type Settings = { revision: number; smtp: SMTP; webhook: HTTPChannel; sms: HTTPChannel };
type Audit = {
  at: string;
  actor: { name: string };
  action: string;
  user_id?: string;
  code?: string;
  delivery_id?: string;
};
type Health = {
  pending: number;
  uncertain: number;
  failed: number;
  source_gaps: string[];
  source_errors: string[];
};
type Tab = "inbox" | "preferences" | "deliveries" | "settings" | "audit";
const topics = ["approvals", "tickets", "jobs", "rotation", "security", "system"];
const channels = ["inbox", "email", "webhook", "sms"];
const codes = new Set([
  "invalid",
  "denied",
  "not_found",
  "conflict",
  "verification_required",
  "rate_limit",
  "capacity",
  "unavailable",
]);
class NotificationError extends Error {
  constructor(public code: string) {
    super(code);
  }
}

export default function NotificationsPage({ platform = false }: { platform?: boolean } = {}) {
  const { t, i18n } = useTranslation();
  const { accessToken } = useAuth();
  const { allows } = usePermissions();
  const [platformCaps, setPlatformCaps] = useState({ manage: false, audit: false });
  const manage = platform ? platformCaps.manage : allows("notifications.manage"),
    audit = platform ? platformCaps.audit : allows("notifications.audit");
  const [selectedTab, setTab] = useState<Tab>("inbox");
  const tab =
    (selectedTab === "settings" && !manage) || (selectedTab === "audit" && !audit)
      ? "inbox"
      : selectedTab;
  const [offset, setOffset] = useState(0),
    [total, setTotal] = useState(0),
    [unreadOnly, setUnreadOnly] = useState(false),
    [unread, setUnread] = useState(0);
  const [messages, setMessages] = useState<Message[]>([]),
    [deliveries, setDeliveries] = useState<Delivery[]>([]),
    [events, setEvents] = useState<Audit[]>([]);
  const [prefs, setPrefs] = useState<Preferences | null>(null),
    [settings, setSettings] = useState<Settings | null>(null),
    [health, setHealth] = useState<Health | null>(null);
  const [secrets, setSecrets] = useState<Record<string, string>>({}),
    [clear, setClear] = useState<Record<string, boolean>>({});
  const [contactCodes, setContactCodes] = useState({ email: "", sms: "" });
  const [confirm, setConfirm] = useState<Delivery | null>(null);
  const [busy, setBusy] = useState(false),
    [error, setError] = useState(""),
    [notice, setNotice] = useState(""),
    [version, setVersion] = useState(0);
  const [dirty, setDirty] = useState(false);
  const settingsOperation = useRef<{ body: string; id: string } | null>(null);
  const life = useRef<AbortController | null>(null),
    sequence = useRef(0),
    confirmFocus = useRef<HTMLButtonElement | null>(null);
  useEffect(() => {
    life.current = new AbortController();
    return () => {
      life.current?.abort();
    };
  }, []);
  const request = useCallback(
    async <T,>(path: string, method = "GET", body?: unknown, signal?: AbortSignal): Promise<T> => {
      const headers = new Headers();
      if (accessToken) headers.set("Authorization", `Bearer ${accessToken}`);
      if (body !== undefined) headers.set("Content-Type", "application/json");
      const signals = [AbortSignal.timeout(30_000)];
      if (life.current) signals.push(life.current.signal);
      if (signal) signals.push(signal);
      const response = await fetch(
        `/api/v1/${platform ? "platform-notifications" : "notifications"}/${path}`,
        {
          method,
          headers,
          signal: AbortSignal.any(signals),
          ...(body === undefined ? {} : { body: JSON.stringify(body) }),
        },
      );
      if (!response.ok) {
        const p = await response.json().catch(() => ({}));
        throw new NotificationError(
          response.status === 401 || response.status === 403
            ? "denied"
            : codes.has(p.error_code)
              ? p.error_code
              : "unavailable",
        );
      }
      return response.json() as Promise<T>;
    },
    [accessToken, platform],
  );
  const fail = useCallback((e: unknown) => {
    if (!life.current?.signal.aborted) {
      setError(e instanceof NotificationError ? e.code : "unavailable");
      if (e instanceof NotificationError && e.code === "denied") {
        setMessages([]);
        setDeliveries([]);
        setEvents([]);
        setSettings(null);
        setHealth(null);
        setSecrets({});
        setClear({});
        setConfirm(null);
        setPlatformCaps({ manage: false, audit: false });
      }
    }
  }, []);
  useEffect(() => {
    if (!platform) return;
    const controller = new AbortController();
    let running = false;
    const load = async () => {
      if (running || document.visibilityState === "hidden") return;
      running = true;
      try {
        const c = await request<{ manage: boolean; audit: boolean }>(
          "capabilities",
          "GET",
          undefined,
          controller.signal,
        );
        if (!controller.signal.aborted) {
          setPlatformCaps(c);
          if (!c.manage) {
            setSettings(null);
            setHealth(null);
            setSecrets({});
            setClear({});
          }
          if (!c.audit) setEvents([]);
        }
      } catch (e) {
        if (!controller.signal.aborted) fail(e);
      } finally {
        running = false;
      }
    };
    void load();
    const timer = setInterval(() => void load(), 10_000);
    return () => {
      controller.abort();
      clearInterval(timer);
    };
  }, [platform, request, fail, version]);
  useEffect(() => {
    const controller = new AbortController(),
      serial = ++sequence.current;
    if ((tab === "settings" && !manage) || (tab === "audit" && !audit)) return;
    const load = async () => {
      try {
        const path =
          tab === "inbox"
            ? `inbox?offset=${offset}&limit=20&unread=${unreadOnly}`
            : tab === "deliveries"
              ? `deliveries?offset=${offset}&limit=20`
              : tab === "audit"
                ? `audit?offset=${offset}&limit=20`
                : tab;
        if (tab === "preferences") {
          const p = await request<Preferences>(path, "GET", undefined, controller.signal);
          if (serial === sequence.current && !controller.signal.aborted) {
            setPrefs(p);
            setDirty(false);
            setTotal(0);
          }
        } else if (tab === "settings") {
          const [s, h] = await Promise.all([
            request<Settings>("settings", "GET", undefined, controller.signal),
            request<Health>("health", "GET", undefined, controller.signal),
          ]);
          if (serial === sequence.current && !controller.signal.aborted) {
            setSettings(s);
            setHealth(h);
            setSecrets({});
            setClear({});
            setDirty(false);
            setTotal(0);
          }
        } else {
          const p = await request<Page<Message | Delivery | Audit> & { unread?: number }>(
            path,
            "GET",
            undefined,
            controller.signal,
          );
          if (serial !== sequence.current || controller.signal.aborted) return;
          if (tab === "inbox") {
            setMessages(p.results as Message[]);
            setUnread(p.unread || 0);
          } else if (tab === "deliveries") setDeliveries(p.results as Delivery[]);
          else setEvents(p.results as Audit[]);
          setTotal(p.total);
        }
        if (!controller.signal.aborted) setError("");
      } catch (e) {
        if (!controller.signal.aborted) fail(e);
      }
    };
    void load();
    return () => controller.abort();
  }, [tab, offset, unreadOnly, version, manage, audit, request, fail]);
  useEffect(() => {
    if (confirm) confirmFocus.current?.focus();
  }, [confirm]);
  const act = async (fn: () => Promise<void>) => {
    if (busy) return;
    setBusy(true);
    setError("");
    setNotice("");
    try {
      await fn();
      if (!life.current?.signal.aborted) {
        setNotice("notifications.saved");
        window.dispatchEvent(new Event("jms233-notifications"));
      }
    } catch (e) {
      fail(e);
    } finally {
      if (!life.current?.signal.aborted) setBusy(false);
    }
  };
  const changeTab = (next: Tab) => {
    sequence.current++;
    setTab(next);
    setOffset(0);
    setNotice("");
    setError("");
    setConfirm(null);
  };
  const date = (value: string) => new Date(value).toLocaleString(i18n.language);
  const state = (value: string) =>
    t(`notifications.states.${value}`, { defaultValue: t("notifications.updated") });
  const title = (value: string) =>
    t(`notifications.topics.${value}`, { defaultValue: t("notifications.updated") });
  const editPrefs = (patch: Partial<Preferences>) => {
    setDirty(true);
    setPrefs((p) => (p ? { ...p, ...patch } : p));
  };
  const editSettings = (patch: Partial<Settings>) => {
    setDirty(true);
    setSettings((s) => (s ? { ...s, ...patch } : s));
  };
  const savePrefs = async () => {
    if (!prefs) return;
    const p = await request<Preferences>("preferences", "PUT", {
      revision: prefs.revision,
      language: prefs.language,
      email: prefs.email,
      phone: prefs.phone,
      topics: prefs.topics,
    });
    setPrefs(p);
    setDirty(false);
  };
  const retry = async (v: Delivery, ack: boolean) => {
    await request(`deliveries/${encodeURIComponent(v.id)}/retry`, "POST", {
      revision: v.revision,
      acknowledge_uncertain: ack,
    });
    setConfirm(null);
    setVersion((n) => n + 1);
  };
  return (
    <section className="rotation-page notifications-page" aria-busy={busy}>
      <header>
        <div>
          <h1>{t(platform ? "notifications.platformTitle" : "notifications.title")}</h1>
          <p>{t(platform ? "notifications.platformHint" : "notifications.hint")}</p>
        </div>
        <button type="button" disabled={busy} onClick={() => setVersion((n) => n + 1)}>
          {t("notifications.refresh")}
        </button>
      </header>
      <nav className="rotation-actions" aria-label={t("notifications.scopeSwitcher")}>
        <Link to="/console/notifications" aria-current={!platform ? "page" : undefined}>
          {t("notifications.organizationScope")}
        </Link>
        <Link to="/console/platform-notifications" aria-current={platform ? "page" : undefined}>
          {t("notifications.platformScope")}
        </Link>
      </nav>
      <nav className="rotation-actions" aria-label={t("notifications.views")}>
        {(
          [
            "inbox",
            "preferences",
            "deliveries",
            ...(manage ? ["settings"] : []),
            ...(audit ? ["audit"] : []),
          ] as Tab[]
        ).map((v) => (
          <button
            type="button"
            key={v}
            disabled={busy}
            aria-current={tab === v ? "page" : undefined}
            onClick={() => changeTab(v)}
          >
            {t(`notifications.tabs.${v}`)}
          </button>
        ))}
      </nav>
      <div role="status" className="notification-feedback">
        {notice && t(notice)}
      </div>
      {error && <p role="alert">{t(`notifications.errors.${error}`)}</p>}
      {tab === "inbox" && (
        <>
          <div className="rotation-actions">
            <label className="notification-check">
              <input
                type="checkbox"
                checked={unreadOnly}
                onChange={(e) => {
                  setUnreadOnly(e.target.checked);
                  setOffset(0);
                }}
              />
              {t("notifications.onlyUnread")}
            </label>
            <span>{t("notifications.unread", { count: unread })}</span>
            <button
              type="button"
              disabled={busy || !unread}
              onClick={() =>
                void act(async () => {
                  await request("read", "POST", { all: true });
                  setVersion((n) => n + 1);
                })
              }
            >
              {t("notifications.readAll")}
            </button>
          </div>
          <ul className="notification-inbox">
            {messages.map((v) => (
              <li key={v.id} className={v.read_at ? "" : "notification-unread"}>
                <div>
                  <strong>{title(v.topic)}</strong>
                  <span>{state(v.state)}</span>
                  {!v.read_at && <small>{t("notifications.new")}</small>}
                </div>
                {v.name && <h2>{v.name}</h2>}
                <time dateTime={v.at}>{date(v.at)}</time>
                <small>{v.source.id}</small>
                <div className="rotation-actions">
                  <Link
                    to={v.link}
                    onClick={() => {
                      void request("read", "POST", { id: v.id })
                        .then(() => window.dispatchEvent(new Event("jms233-notifications")))
                        .catch(() => undefined);
                    }}
                  >
                    {t("notifications.open")}
                  </Link>
                  {!v.read_at && (
                    <button
                      type="button"
                      disabled={busy}
                      onClick={() =>
                        void act(async () => {
                          await request("read", "POST", { id: v.id });
                          setVersion((n) => n + 1);
                        })
                      }
                    >
                      {t("notifications.read")}
                    </button>
                  )}
                </div>
              </li>
            ))}
          </ul>
        </>
      )}
      {tab === "preferences" && prefs && (
        <form
          onSubmit={(e) => {
            e.preventDefault();
            void act(savePrefs);
          }}
        >
          <h2>{t("notifications.tabs.preferences")}</h2>
          <p>
            {t(platform ? "notifications.platformPreferenceHint" : "notifications.preferenceHint")}
          </p>
          <label>
            {t("notifications.language")}
            <select
              aria-label={t("notifications.language")}
              value={prefs.language}
              onChange={(e) => editPrefs({ language: e.target.value })}
            >
              {["auto", "en", "zh-CN"].map((v) => (
                <option key={v} value={v}>
                  {t(`notifications.languages.${v}`)}
                </option>
              ))}
            </select>
          </label>
          <div className="notification-contacts">
            {(["email", "sms"] as const).map((channel) => {
              const email = channel === "email",
                value = email ? prefs.email : prefs.phone,
                verified = email ? prefs.email_verified : prefs.phone_verified;
              return (
                <fieldset key={channel}>
                  <legend>{t(`notifications.channels.${channel}`)}</legend>
                  <label>
                    {t(email ? "notifications.email" : "notifications.phone")}
                    <input
                      type={email ? "email" : "tel"}
                      value={value}
                      maxLength={email ? 254 : 16}
                      onChange={(e) => {
                        const topics = Object.fromEntries(
                          Object.entries(prefs.topics).map(([k, rows]) => [
                            k,
                            rows.filter((c) => c !== channel),
                          ]),
                        );
                        editPrefs(
                          email
                            ? { email: e.target.value, email_verified: false, topics }
                            : { phone: e.target.value, phone_verified: false, topics },
                        );
                      }}
                    />
                  </label>
                  <p>{t(verified ? "notifications.verified" : "notifications.unverified")}</p>
                  <div className="rotation-actions">
                    <button
                      type="button"
                      disabled={busy || !value || verified}
                      onClick={() =>
                        void act(async () => {
                          if (dirty) await savePrefs();
                          setPrefs(
                            await request<Preferences>("verification/request", "POST", { channel }),
                          );
                          setNotice("notifications.codeSent");
                        })
                      }
                    >
                      {t("notifications.sendCode")}
                    </button>
                    <label>
                      {t("notifications.code")}
                      <input
                        autoComplete="one-time-code"
                        inputMode="numeric"
                        pattern="[0-9]{6}"
                        maxLength={6}
                        value={contactCodes[channel]}
                        onChange={(e) =>
                          setContactCodes({ ...contactCodes, [channel]: e.target.value })
                        }
                      />
                    </label>
                    <button
                      type="button"
                      disabled={busy || contactCodes[channel].length !== 6 || verified || dirty}
                      onClick={() =>
                        void act(async () => {
                          setPrefs(
                            await request<Preferences>("verification/confirm", "POST", {
                              channel,
                              code: contactCodes[channel],
                            }),
                          );
                          setContactCodes((c) => ({ ...c, [channel]: "" }));
                        })
                      }
                    >
                      {t("notifications.verify")}
                    </button>
                  </div>
                </fieldset>
              );
            })}
          </div>
          <h3>{t("notifications.subscriptions")}</h3>
          <p>{t(platform ? "notifications.platformSourcesHint" : "notifications.sourcesHint")}</p>
          <div className="notification-topics">
            {topics.map((topic) => (
              <fieldset key={topic}>
                <legend>{title(topic)}</legend>
                {channels.map((channel) => (
                  <label key={channel} className="notification-check">
                    <input
                      type="checkbox"
                      checked={prefs.topics[topic]?.includes(channel) || false}
                      disabled={
                        (channel === "email" && !prefs.email_verified) ||
                        (channel === "sms" && !prefs.phone_verified)
                      }
                      onChange={(e) => {
                        const selected = prefs.topics[topic] || [];
                        editPrefs({
                          topics: {
                            ...prefs.topics,
                            [topic]: e.target.checked
                              ? [...selected, channel]
                              : selected.filter((c) => c !== channel),
                          },
                        });
                      }}
                    />
                    {t(`notifications.channels.${channel}`)}
                  </label>
                ))}
              </fieldset>
            ))}
          </div>
          <div className="rotation-actions">
            <button type="submit" disabled={busy}>
              {t("notifications.save")}
            </button>
            <button
              type="button"
              disabled={busy}
              onClick={() =>
                void act(async () => {
                  if (dirty) await savePrefs();
                  await request("test", "POST", { request_id: newRequestID() });
                })
              }
            >
              {t("notifications.test")}
            </button>
          </div>
        </form>
      )}
      {tab === "deliveries" && (
        <>
          <p>{t("notifications.deliveryHint")}</p>
          <div className="rotation-table">
            <table>
              <thead>
                <tr>
                  {["channel", "destination", "state", "attempts", "at", "action"].map((v) => (
                    <th scope="col" key={v}>
                      {t(`notifications.${v}`)}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {deliveries.map((v) => (
                  <tr key={v.id}>
                    <td>{t(`notifications.channels.${v.channel}`)}</td>
                    <td>
                      {v.destination}
                      <small>{v.user_id}</small>
                    </td>
                    <td>
                      {state(v.state)}
                      {v.error_code && (
                        <small>
                          {t(`notifications.deliveryCodes.${v.error_code}`, {
                            defaultValue: t("notifications.deliveryUnknown"),
                          })}
                        </small>
                      )}
                      <small>{v.id}</small>
                    </td>
                    <td>{v.attempts}</td>
                    <td>
                      {date(v.created_at)}
                      {v.next_attempt && <small>{date(v.next_attempt)}</small>}
                    </td>
                    <td>
                      {v.can_retry && (
                        <button type="button" disabled={busy} onClick={() => setConfirm(v)}>
                          {t("notifications.retry")}
                        </button>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          {confirm && (
            <fieldset className="notification-confirm">
              <legend>{t("notifications.retry")}</legend>
              <p>
                {t(
                  confirm.state === "uncertain"
                    ? "notifications.uncertainHint"
                    : "notifications.retryHint",
                )}
              </p>
              <p>{confirm.destination}</p>
              <div className="rotation-actions">
                <button
                  ref={confirmFocus}
                  type="button"
                  disabled={busy}
                  onClick={() => void act(() => retry(confirm, confirm.state === "uncertain"))}
                >
                  {t("notifications.confirmRetry")}
                </button>
                <button type="button" disabled={busy} onClick={() => setConfirm(null)}>
                  {t("notifications.cancel")}
                </button>
              </div>
            </fieldset>
          )}
        </>
      )}
      {tab === "settings" && manage && settings && (
        <form
          autoComplete="off"
          onSubmit={(e) => {
            e.preventDefault();
            void act(async () => {
              const fields: Record<string, string> = {};
              for (const [k, v] of Object.entries(secrets)) if (v) fields[k] = v;
              for (const [k, v] of Object.entries(clear)) if (v) fields[k] = "";
              const payload = { ...settings, ...fields };
              const body = JSON.stringify(payload);
              if (settingsOperation.current?.body !== body)
                settingsOperation.current = { body, id: newRequestID() };
              setSettings(
                await request<Settings>("settings", "PUT", {
                  ...payload,
                  request_id: settingsOperation.current.id,
                }),
              );
              settingsOperation.current = null;
              setSecrets({});
              setClear({});
              setDirty(false);
            });
          }}
        >
          <h2>{t("notifications.tabs.settings")}</h2>
          <p>{t("notifications.settingsHint")}</p>
          {health && (
            <p role="status">
              {t("notifications.health", {
                pending: health.pending,
                uncertain: health.uncertain,
                failed: health.failed,
              })}
              {health.source_gaps.length > 0 && (
                <strong>
                  {t("notifications.gaps", { sources: health.source_gaps.join(", ") })}
                </strong>
              )}
              {health.source_errors.length > 0 && (
                <strong>
                  {t("notifications.sourceErrors", { sources: health.source_errors.join(", ") })}
                </strong>
              )}
            </p>
          )}
          <fieldset>
            <legend>{t("notifications.channels.email")}</legend>
            <label className="notification-check">
              <input
                type="checkbox"
                checked={settings.smtp.enabled}
                onChange={(e) =>
                  editSettings({ smtp: { ...settings.smtp, enabled: e.target.checked } })
                }
              />
              {t("notifications.enabled")}
            </label>
            <div className="rotation-fields">
              {(["host", "port", "username", "from", "subject_prefix"] as const).map((key) => (
                <label key={key}>
                  {t(`notifications.smtp.${key}`)}
                  <input
                    type={key === "port" ? "number" : "text"}
                    min={key === "port" ? 1 : undefined}
                    max={key === "port" ? 65535 : undefined}
                    value={settings.smtp[key]}
                    maxLength={key === "port" ? undefined : 254}
                    onChange={(e) =>
                      editSettings({
                        smtp: {
                          ...settings.smtp,
                          [key]: key === "port" ? Number(e.target.value) : e.target.value,
                        },
                      })
                    }
                  />
                </label>
              ))}
              <label>
                {t("notifications.smtp.mode")}
                <select
                  aria-label={t("notifications.smtp.mode")}
                  value={settings.smtp.mode}
                  onChange={(e) =>
                    editSettings({ smtp: { ...settings.smtp, mode: e.target.value } })
                  }
                >
                  <option value="starttls">{t("notifications.smtp.starttls")}</option>
                  <option value="tls">{t("notifications.smtp.tls")}</option>
                </select>
              </label>
            </div>
            <Secret
              name="smtp_password"
              configured={settings.smtp.password_configured}
              value={secrets.smtp_password || ""}
              clear={clear.smtp_password || false}
              change={(v) => setSecrets((s) => ({ ...s, smtp_password: v }))}
              clearChange={(v) => setClear((s) => ({ ...s, smtp_password: v }))}
            />
            <label>
              {t("notifications.ca")}
              <textarea
                aria-label={t("notifications.ca")}
                rows={3}
                value={settings.smtp.ca}
                maxLength={65536}
                onChange={(e) => editSettings({ smtp: { ...settings.smtp, ca: e.target.value } })}
              />
            </label>
          </fieldset>
          {(["webhook", "sms"] as const).map((channel) => (
            <fieldset key={channel}>
              <legend>{t(`notifications.channels.${channel}`)}</legend>
              <p>
                {t(
                  channel === "sms" ? "notifications.smsContract" : "notifications.webhookContract",
                )}
              </p>
              <label className="notification-check">
                <input
                  type="checkbox"
                  checked={settings[channel].enabled}
                  onChange={(e) =>
                    editSettings({ [channel]: { ...settings[channel], enabled: e.target.checked } })
                  }
                />
                {t("notifications.enabled")}
              </label>
              <NativeNotificationFields
                channel={channel}
                value={settings[channel]}
                change={(v) => editSettings({ [channel]: v })}
                providerChange={() => {
                  setSecrets((s) => ({
                    ...s,
                    [`${channel}_bearer`]: "",
                    [`${channel}_secret`]: "",
                  }));
                  setClear((s) => ({
                    ...s,
                    [`${channel}_bearer`]: false,
                    [`${channel}_secret`]: false,
                  }));
                }}
              />
              {!nativeChannel(settings[channel]) && (
                <label>
                  {t("notifications.url")}
                  <input
                    type="url"
                    value={settings[channel].url}
                    maxLength={2048}
                    onChange={(e) =>
                      editSettings({ [channel]: { ...settings[channel], url: e.target.value } })
                    }
                  />
                </label>
              )}
              {(["bearer", "secret"] as const)
                .filter(
                  (kind) =>
                    !(channel === "sms" && nativeChannel(settings[channel]) && kind === "bearer"),
                )
                .map((kind) => (
                  <Secret
                    key={kind}
                    name={`${channel}_${kind}`}
                    configured={settings[channel][`${kind}_configured`]}
                    value={secrets[`${channel}_${kind}`] || ""}
                    clear={clear[`${channel}_${kind}`] || false}
                    change={(v) => setSecrets((s) => ({ ...s, [`${channel}_${kind}`]: v }))}
                    clearChange={(v) => setClear((s) => ({ ...s, [`${channel}_${kind}`]: v }))}
                  />
                ))}
              <label>
                {t("notifications.ca")}
                <textarea
                  aria-label={t("notifications.ca")}
                  rows={3}
                  value={settings[channel].ca}
                  maxLength={65536}
                  onChange={(e) =>
                    editSettings({ [channel]: { ...settings[channel], ca: e.target.value } })
                  }
                />
              </label>
            </fieldset>
          ))}
          <p>{t("notifications.secretHint")}</p>
          <button type="submit" disabled={busy}>
            {t("notifications.save")}
          </button>
        </form>
      )}
      {tab === "audit" && audit && (
        <div className="rotation-table">
          <table>
            <thead>
              <tr>
                {["at", "actor", "action", "delivery"].map((v) => (
                  <th scope="col" key={v}>
                    {t(`notifications.${v}`)}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {events.map((v, i) => (
                <tr key={`${v.at}-${i}`}>
                  <td>{date(v.at)}</td>
                  <td>
                    {v.actor.name}
                    <small>{v.user_id}</small>
                  </td>
                  <td>
                    {t(`notifications.auditActions.${v.action}`, { defaultValue: state(v.action) })}
                    <small>{v.code}</small>
                  </td>
                  <td>{v.delivery_id}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      {["inbox", "deliveries", "audit"].includes(tab) && (
        <>
          {total === 0 && <p>{t("notifications.empty")}</p>}
          <nav className="rotation-actions" aria-label={t("notifications.pagination")}>
            <button
              type="button"
              disabled={busy || offset === 0}
              onClick={() => setOffset((n) => Math.max(0, n - 20))}
            >
              {t("notifications.previous")}
            </button>
            <span>{t("notifications.count", { count: total })}</span>
            <button
              type="button"
              disabled={busy || offset + 20 >= total}
              onClick={() => setOffset((n) => n + 20)}
            >
              {t("notifications.next")}
            </button>
          </nav>
        </>
      )}
    </section>
  );
}

function Secret({
  name,
  configured,
  value,
  clear,
  change,
  clearChange,
}: {
  name: string;
  configured: boolean;
  value: string;
  clear: boolean;
  change: (v: string) => void;
  clearChange: (v: boolean) => void;
}) {
  const { t } = useTranslation();
  return (
    <div className="notification-secret">
      <label>
        {t(`notifications.secrets.${name}`)}
        <input
          type="password"
          autoComplete="new-password"
          value={value}
          maxLength={4096}
          disabled={clear}
          onChange={(e) => change(e.target.value)}
          placeholder={t(configured ? "notifications.secretSet" : "notifications.secretEmpty")}
        />
      </label>
      <label className="notification-check">
        <input type="checkbox" checked={clear} onChange={(e) => clearChange(e.target.checked)} />
        {t("notifications.clearSecret")}
      </label>
    </div>
  );
}
