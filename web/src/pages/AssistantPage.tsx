import { useCallback, useEffect, useRef, useState, type FormEvent } from "react";
import { useTranslation } from "react-i18next";
import { useAuth } from "../auth/AuthContext";
import { usePermissions } from "../auth/usePermissions";
import "../i18n/locales/features/assistant/register";
import "./AssistantPage.css";

type Settings = {
  endpoint: string;
  model: string;
  root_ca_pem?: string;
  max_completion_tokens: number;
  enabled: boolean;
  configured: boolean;
  revision: number;
};
type Turn = {
  id: string;
  status: string;
  message: string;
  reply?: string;
  model: string;
  at: string;
  prompt_tokens: number;
  completion_tokens: number;
};
type Conversation = {
  id: string;
  owner_id: string;
  title: string;
  revision: number;
  archived: boolean;
  updated_at: string;
  turns?: Turn[];
};
type Audit = {
  at: string;
  actor_id: string;
  action: string;
  conversation_id?: string;
  revision: number;
};
type Input = {
  conversation_id?: string;
  revision: number;
  request_id: string;
  message: string;
  locale: string;
  consent: boolean;
};
const nonce = () =>
  Array.from(crypto.getRandomValues(new Uint8Array(16)), (v) =>
    v.toString(16).padStart(2, "0"),
  ).join("");
const initialSettings: Settings = {
  endpoint: "",
  model: "",
  root_ca_pem: "",
  max_completion_tokens: 1024,
  enabled: false,
  configured: false,
  revision: 0,
};

export default function AssistantPage() {
  const { t, i18n } = useTranslation();
  const { accessToken } = useAuth();
  const { allows, ready, userID } = usePermissions();
  const canUse = allows("assistant.use"),
    canManage = allows("assistant.manage"),
    canAudit = allows("assistant.audit");
  const [selectedTab, setTab] = useState<"chat" | "settings" | "audit">("chat");
  const tab =
    selectedTab === "chat" && !canUse && !canAudit && canManage ? "settings" : selectedTab;
  const [config, setConfig] = useState<Settings>(initialSettings),
    [secret, setSecret] = useState(""),
    [clearSecret, setClearSecret] = useState(false);
  const [enabled, setEnabled] = useState(false),
    [rows, setRows] = useState<Conversation[]>([]),
    [total, setTotal] = useState(0),
    [offset, setOffset] = useState(0),
    [all, setAll] = useState(false),
    [archived, setArchived] = useState(false);
  const [conversation, setConversation] = useState<Conversation | null>(null),
    [message, setMessage] = useState(""),
    [consent, setConsent] = useState(false),
    [audit, setAudit] = useState<Audit[]>([]),
    [auditTotal, setAuditTotal] = useState(0),
    [auditOffset, setAuditOffset] = useState(0);
  const [busy, setBusy] = useState(false),
    [error, setError] = useState(""),
    [status, setStatus] = useState(""),
    [retry, setRetry] = useState(false);
  const active = useRef<AbortController | null>(null),
    sendActive = useRef<AbortController | null>(null),
    generation = useRef(0),
    pending = useRef<Input | null>(null),
    saveReceipt = useRef<{ hash: string; id: string } | null>(null),
    archives = useRef<Record<string, string>>({});
  const request = useCallback(
    async (path: string, method = "GET", body?: unknown, signal?: AbortSignal) => {
      const response = await fetch("/api/v1/assistant" + path, {
        method,
        credentials: "same-origin",
        signal,
        headers: {
          ...(accessToken ? { Authorization: "Bearer " + accessToken } : {}),
          ...(body === undefined ? {} : { "Content-Type": "application/json" }),
        },
        ...(body === undefined ? {} : { body: JSON.stringify(body) }),
      });
      if (!response.ok) {
        const problem = await response.json().catch(() => ({}));
        throw Error(problem.error_code ?? "assistant_unavailable");
      }
      return response.status === 204 ? null : response.json();
    },
    [accessToken],
  );
  const problem = (e: unknown) =>
    setError(e instanceof Error ? e.message : "assistant_unavailable");
  const load = useCallback(
    async (signal?: AbortSignal) => {
      const [caps, list, settings, events] = await Promise.all([
        request("/capabilities", "GET", undefined, signal),
        canUse || (all && canAudit)
          ? request(
              `/conversations?all=${all}&archived=${archived}&offset=${offset}&limit=20`,
              "GET",
              undefined,
              signal,
            )
          : Promise.resolve({ results: [], total: 0 }),
        canManage ? request("/settings", "GET", undefined, signal) : Promise.resolve(null),
        canAudit && tab === "audit"
          ? request(`/audit?offset=${auditOffset}&limit=20`, "GET", undefined, signal)
          : Promise.resolve(null),
      ]);
      if (signal?.aborted) return;
      setEnabled(caps.enabled);
      setRows(list.results);
      setTotal(list.total);
      if (settings) setConfig(settings);
      if (events) {
        setAudit(events.results);
        setAuditTotal(events.total);
      }
    },
    [request, canUse, canManage, canAudit, all, archived, offset, tab, auditOffset],
  );
  useEffect(() => {
    if (!ready || (!canUse && !canManage && !canAudit)) return;
    const c = new AbortController();
    active.current = c;
    void load(c.signal).catch((e) => {
      if (!c.signal.aborted) problem(e);
    });
    return () => c.abort();
  }, [ready, canUse, canManage, canAudit, load]);
  useEffect(
    () => () => {
      generation.current++;
      sendActive.current?.abort();
      active.current?.abort();
    },
    [],
  );
  const open = async (id: string) => {
    generation.current++;
    const version = generation.current;
    sendActive.current?.abort();
    const c = new AbortController();
    sendActive.current = c;
    setError("");
    setStatus("");
    setRetry(false);
    setBusy(false);
    pending.current = null;
    try {
      const out = await request(`/conversations/${id}?all=${all}`, "GET", undefined, c.signal);
      if (version === generation.current) {
        setConversation(out);
        setMessage("");
      }
    } catch (e) {
      if (!c.signal.aborted) problem(e);
    }
  };
  const fresh = () => {
    generation.current++;
    sendActive.current?.abort();
    setBusy(false);
    setConversation(null);
    setMessage("");
    setError("");
    setStatus("");
    setRetry(false);
    pending.current = null;
  };
  const send = async (replay = false) => {
    if (busy) return;
    setBusy(true);
    setError("");
    setStatus("");
    setRetry(false);
    const version = generation.current,
      c = new AbortController();
    sendActive.current = c;
    const input: Input =
      replay && pending.current
        ? pending.current
        : {
            ...(conversation ? { conversation_id: conversation.id } : {}),
            revision: conversation?.revision ?? 0,
            request_id: nonce(),
            message,
            locale: i18n.language.startsWith("zh") ? "zh-CN" : "en",
            consent,
          };
    pending.current = input;
    try {
      const out = await request(
        "/turns",
        "POST",
        input,
        AbortSignal.any([c.signal, AbortSignal.timeout(55000)]),
      );
      if (version !== generation.current) return;
      const room = await request(
        `/conversations/${out.conversation_id}?all=${all}`,
        "GET",
        undefined,
        c.signal,
      );
      if (version !== generation.current) return;
      setConversation(room);
      setStatus(out.turn.status);
      setMessage("");
      pending.current = null;
      await load(c.signal);
    } catch (e) {
      if (version === generation.current && !c.signal.aborted) {
        problem(e);
        setRetry(true);
      }
    } finally {
      if (version === generation.current) setBusy(false);
    }
  };
  const save = async (e: FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setError("");
    setStatus("");
    const input = {
      endpoint: config.endpoint,
      model: config.model,
      root_ca_pem: config.root_ca_pem ?? "",
      max_completion_tokens: config.max_completion_tokens,
      enabled: config.enabled,
      revision: config.revision,
      ...(clearSecret ? { secret: "" } : secret ? { secret } : {}),
    };
    const hash = JSON.stringify(input);
    if (saveReceipt.current?.hash !== hash) saveReceipt.current = { hash, id: nonce() };
    try {
      const out = await request("/settings", "PUT", {
        ...input,
        request_id: saveReceipt.current.id,
      });
      setConfig(out);
      setSecret("");
      setClearSecret(false);
      saveReceipt.current = null;
      setEnabled(out.enabled && out.configured);
      setStatus("saved");
    } catch (e) {
      problem(e);
    } finally {
      setBusy(false);
    }
  };
  const archive = async () => {
    if (!conversation || busy) return;
    const c = conversation,
      key = c.id + ":" + c.revision;
    archives.current[key] ??= nonce();
    setBusy(true);
    setError("");
    try {
      await request(`/conversations/${c.id}/archive`, "POST", {
        revision: c.revision,
        request_id: archives.current[key],
      });
      fresh();
      await load();
    } catch (e) {
      problem(e);
    } finally {
      setBusy(false);
    }
  };
  if (!ready) return null;
  if (!canUse && !canManage && !canAudit) return <p role="alert">{t("assistant.denied")}</p>;
  const own = !conversation || conversation.owner_id === userID;
  const waiting = conversation?.turns?.some((v) => v.status === "pending") ?? false;
  const errorKey = [
    "assistant_invalid",
    "assistant_denied",
    "assistant_conflict",
    "assistant_not_found",
    "assistant_capacity",
    "service_draining",
  ].includes(error)
    ? error
    : "assistant_unavailable";
  return (
    <section className="assistant-page">
      <header>
        <h1>{t("assistant.title")}</h1>
        <p>{t("assistant.description")}</p>
      </header>
      <nav aria-label={t("assistant.views")}>
        {(canUse || canAudit) && (
          <button type="button" aria-pressed={tab === "chat"} onClick={() => setTab("chat")}>
            {t("assistant.conversations")}
          </button>
        )}
        {canManage && (
          <button
            type="button"
            aria-pressed={tab === "settings"}
            onClick={() => setTab("settings")}
          >
            {t("assistant.settings")}
          </button>
        )}
        {canAudit && (
          <button type="button" aria-pressed={tab === "audit"} onClick={() => setTab("audit")}>
            {t("assistant.audit")}
          </button>
        )}
      </nav>
      {error && <p role="alert">{t("assistant.errors." + errorKey)}</p>}
      {status && <p role="status">{t("assistant.states." + status)}</p>}
      {tab === "settings" && canManage && (
        <form onSubmit={(e) => void save(e)} className="assistant-settings">
          <label>
            {t("assistant.endpoint")}
            <input
              required
              type="url"
              value={config.endpoint}
              placeholder={t("assistant.endpointExample")}
              onChange={(e) => setConfig({ ...config, endpoint: e.target.value })}
            />
          </label>
          <label>
            {t("assistant.model")}
            <input
              required
              maxLength={128}
              value={config.model}
              onChange={(e) => setConfig({ ...config, model: e.target.value })}
            />
          </label>
          <label>
            {t("assistant.secret")}
            <input
              type="password"
              autoComplete="new-password"
              value={secret}
              disabled={clearSecret}
              onChange={(e) => setSecret(e.target.value)}
            />
          </label>
          <p>{t(config.configured ? "assistant.secretConfigured" : "assistant.secretMissing")}</p>
          <label>
            <input
              type="checkbox"
              checked={clearSecret}
              onChange={(e) => setClearSecret(e.target.checked)}
            />
            {t("assistant.clearSecret")}
          </label>
          <details>
            <summary>{t("assistant.advanced")}</summary>
            <label>
              {t("assistant.ca")}
              <textarea
                rows={5}
                value={config.root_ca_pem ?? ""}
                onChange={(e) => setConfig({ ...config, root_ca_pem: e.target.value })}
              />
            </label>
            <label>
              {t("assistant.tokens")}
              <input
                type="number"
                min={64}
                max={8192}
                required
                value={config.max_completion_tokens}
                onChange={(e) =>
                  setConfig({ ...config, max_completion_tokens: Number(e.target.value) })
                }
              />
            </label>
          </details>
          <label>
            <input
              type="checkbox"
              checked={config.enabled}
              onChange={(e) => setConfig({ ...config, enabled: e.target.checked })}
            />
            {t("assistant.enable")}
          </label>
          <button type="submit" disabled={busy}>
            {t("assistant.save")}
          </button>
        </form>
      )}
      {tab === "chat" && (canUse || canAudit) && (
        <>
          {!enabled && <p role="status">{t("assistant.disabled")}</p>}
          <div className="assistant-workspace">
            <aside>
              {canUse && (
                <button type="button" onClick={fresh}>
                  {t("assistant.new")}
                </button>
              )}
              {canAudit && (
                <label>
                  <input
                    type="checkbox"
                    checked={all}
                    onChange={(e) => {
                      fresh();
                      setOffset(0);
                      setAll(e.target.checked);
                    }}
                  />
                  {t("assistant.all")}
                </label>
              )}
              <label>
                <input
                  type="checkbox"
                  checked={archived}
                  onChange={(e) => {
                    setOffset(0);
                    setArchived(e.target.checked);
                  }}
                />
                {t("assistant.archived")}
              </label>
              <ul>
                {rows.map((c) => (
                  <li key={c.id}>
                    <button
                      type="button"
                      aria-pressed={conversation?.id === c.id}
                      onClick={() => void open(c.id)}
                    >
                      {c.title}
                    </button>
                    <small>{new Date(c.updated_at).toLocaleString(i18n.language)}</small>
                  </li>
                ))}
              </ul>
              <div className="assistant-pages">
                <button
                  type="button"
                  disabled={offset === 0}
                  onClick={() => setOffset(Math.max(0, offset - 20))}
                >
                  {t("assistant.previous")}
                </button>
                <span>{t("assistant.total", { count: total })}</span>
                <button
                  type="button"
                  disabled={offset + 20 >= total}
                  onClick={() => setOffset(offset + 20)}
                >
                  {t("assistant.next")}
                </button>
              </div>
            </aside>
            <div className="assistant-conversation">
              <h2>{conversation?.title ?? t("assistant.new")}</h2>
              {conversation && (
                <div className="assistant-conversation-tools">
                  <button type="button" disabled={busy} onClick={() => void open(conversation.id)}>
                    {t("assistant.refresh")}
                  </button>
                  {own && canUse && !conversation.archived && (
                    <button type="button" disabled={busy || waiting} onClick={() => void archive()}>
                      {t("assistant.archive")}
                    </button>
                  )}
                </div>
              )}
              <div role="log" aria-label={t("assistant.messages")} aria-live="polite">
                {conversation?.turns?.map((turn) => (
                  <article key={turn.id}>
                    <h3>{t("assistant.you")}</h3>
                    <pre>{turn.message}</pre>
                    <h3>{t("assistant.answer")}</h3>
                    {turn.reply ? (
                      <pre>{turn.reply}</pre>
                    ) : (
                      <p>{t("assistant.states." + turn.status)}</p>
                    )}
                    <small>
                      {turn.model} · {new Date(turn.at).toLocaleString(i18n.language)} ·{" "}
                      {t("assistant.usage", {
                        input: turn.prompt_tokens,
                        output: turn.completion_tokens,
                      })}
                    </small>
                  </article>
                ))}
              </div>
              {own && canUse && !conversation?.archived && (
                <form
                  onSubmit={(e) => {
                    e.preventDefault();
                    void send();
                  }}
                >
                  <label>
                    {t("assistant.message")}
                    <textarea
                      required
                      rows={4}
                      maxLength={12000}
                      value={message}
                      disabled={busy}
                      onChange={(e) => {
                        setMessage(e.target.value);
                        setRetry(false);
                      }}
                    />
                  </label>
                  <label>
                    <input
                      type="checkbox"
                      checked={consent}
                      onChange={(e) => setConsent(e.target.checked)}
                    />
                    {t("assistant.consent")}
                  </label>
                  <button
                    type="submit"
                    disabled={busy || !enabled || waiting || !consent || !message.trim()}
                  >
                    {t(busy ? "assistant.sending" : "assistant.send")}
                  </button>
                  {retry && (
                    <button type="button" disabled={busy} onClick={() => void send(true)}>
                      {t("assistant.retry")}
                    </button>
                  )}
                </form>
              )}
            </div>
          </div>
        </>
      )}
      {tab === "audit" && canAudit && (
        <div className="assistant-audit">
          <table>
            <caption>{t("assistant.audit")}</caption>
            <thead>
              <tr>
                {["time", "actor", "action", "revision"].map((k) => (
                  <th key={k} scope="col">
                    {t("assistant." + k)}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {audit.map((a, i) => (
                <tr key={a.at + ":" + i}>
                  <td>{new Date(a.at).toLocaleString(i18n.language)}</td>
                  <td>{a.actor_id}</td>
                  <td>{t("assistant.actions." + a.action)}</td>
                  <td>{a.revision}</td>
                </tr>
              ))}
            </tbody>
          </table>
          <div className="assistant-pages">
            <button
              type="button"
              disabled={auditOffset === 0}
              onClick={() => setAuditOffset(Math.max(0, auditOffset - 20))}
            >
              {t("assistant.previous")}
            </button>
            <span>{t("assistant.total", { count: auditTotal })}</span>
            <button
              type="button"
              disabled={auditOffset + 20 >= auditTotal}
              onClick={() => setAuditOffset(auditOffset + 20)}
            >
              {t("assistant.next")}
            </button>
          </div>
        </div>
      )}
    </section>
  );
}
