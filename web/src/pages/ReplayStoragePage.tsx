import { useCallback, useEffect, useRef, useState, type FormEvent } from "react";
import { useTranslation } from "react-i18next";
import { useAuth } from "../auth/AuthContext";
import { usePermissions } from "../auth/usePermissions";
import "../i18n/locales/features/replay-storage/register";
import "./LabelsPage.css";
import "./ReplayStoragePage.css";

type Provider = "local" | "s3" | "oss" | "cos" | "obs" | "sftp" | "postgres";
type Cloud = {
  provider: string;
  endpoint: string;
  region: string;
  bucket: string;
  path_style: boolean;
  access_key_id: string;
  secret_access_key: string;
  session_token: string;
  root_ca_pem: string;
};
type Config = {
  provider: Provider;
  enabled: boolean;
  prefix: string;
  revision: number;
  cloud?: Cloud;
  sftp_asset_id?: string;
  sftp_directory?: string;
  has_secret?: boolean;
  has_session_token?: boolean;
};
type Draft = Config & { clear_session_token: boolean };
type Ref = { kind: "terminal" | "desktop"; session_id: string };
type Record = Ref & {
  status: "queued" | "stored" | "failed";
  config_revision: number;
  size: number;
  attempts: number;
  error_code?: string;
  queued_at: string;
  next_attempt?: string;
  stored_at?: string;
  verified_at?: string;
  local_evicted_at?: string;
};
type Audit = { at: string; actor_id: string; action: string; revision: number; ref?: Ref };
type Page<T> = { results: T[]; total: number };
type Settings = { config: Config; postgres_available: boolean };
type Target = {
  id: string;
  name: string;
  username: string;
  protocol?: string;
  accounts?: { id: string; username: string }[];
};
type Action = "archive" | "retry" | "verify" | "evict";
const base = "settings/replay-storage";
const providers: Provider[] = ["local", "s3", "oss", "cos", "obs", "sftp", "postgres"];
const cloudFields = [
  "endpoint",
  "region",
  "bucket",
  "access_key_id",
  "secret_access_key",
  "session_token",
] as const;
const nonce = () =>
  Array.from(crypto.getRandomValues(new Uint8Array(16)), (n) =>
    n.toString(16).padStart(2, "0"),
  ).join("");
const emptyCloud = (provider: string): Cloud => ({
  provider,
  endpoint: "",
  region: "",
  bucket: "",
  path_style: false,
  access_key_id: "",
  secret_access_key: "",
  session_token: "",
  root_ca_pem: "",
});
const isCloud = (provider: Provider) =>
  provider === "s3" || provider === "oss" || provider === "cos" || provider === "obs";
const draftFor = (config: Config): Draft => ({
  ...config,
  ...(config.cloud
    ? {
        cloud: {
          ...emptyCloud(config.provider),
          ...config.cloud,
          secret_access_key: "",
          session_token: "",
        },
      }
    : {}),
  clear_session_token: false,
});

export default function ReplayStoragePage() {
  const { t, i18n } = useTranslation();
  const { accessToken } = useAuth();
  const { allows, ready } = usePermissions();
  const canView = allows("replay_storage.view"),
    canManage = allows("replay_storage.manage"),
    canArchive = allows("replay_storage.archive"),
    canVerify = allows("replay_storage.verify"),
    canEvict = allows("replay_storage.evict"),
    canAudit = allows("replay_storage.audit");
  const [settings, setSettings] = useState<Settings | null>(null),
    [draft, setDraft] = useState<Draft | null>(null),
    [records, setRecords] = useState<Page<Record>>({ results: [], total: 0 }),
    [audit, setAudit] = useState<Page<Audit>>({ results: [], total: 0 });
  const [targets, setTargets] = useState<Target[]>([]),
    [selection, setSelection] = useState<Ref>({ kind: "terminal", session_id: "" });
  const [busy, setBusy] = useState(false),
    [loading, setLoading] = useState(false),
    [error, setError] = useState(""),
    [message, setMessage] = useState(""),
    [refresh, setRefresh] = useState(0),
    [offset, setOffset] = useState(0),
    [auditOffset, setAuditOffset] = useState(0),
    [auditOpen, setAuditOpen] = useState(false);
  const busyRef = useRef(false),
    saveNonce = useRef(nonce()),
    mutations = useRef<Map<string, string>>(new Map());
  const request = useCallback(
    async <T,>(path: string, method = "GET", body?: unknown, signal?: AbortSignal): Promise<T> => {
      const response = await fetch("/api/v1/" + path, {
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
        const data = await response.json().catch(() => ({}));
        throw Error(
          typeof data.error_code === "string" ? data.error_code : "replay_storage_unavailable",
        );
      }
      return response.json() as Promise<T>;
    },
    [accessToken],
  );
  useEffect(() => {
    if (!ready || !canView) return;
    const controller = new AbortController();
    setLoading(true);
    void Promise.all([
      request<Settings>(base, "GET", undefined, controller.signal),
      request<Page<Record>>(
        `${base}/records?offset=${offset}&limit=20`,
        "GET",
        undefined,
        controller.signal,
      ),
    ])
      .then(([s, r]) => {
        if (!controller.signal.aborted) {
          setSettings(s);
          setRecords(r);
        }
      })
      .catch((e: unknown) => {
        if (!controller.signal.aborted)
          setError(e instanceof Error ? e.message : "replay_storage_unavailable");
      })
      .finally(() => {
        if (!controller.signal.aborted) setLoading(false);
      });
    return () => controller.abort();
  }, [request, ready, canView, canManage, offset, refresh]);
  useEffect(() => {
    if (!auditOpen || !canAudit || !canView) return;
    const c = new AbortController();
    void request<Page<Audit>>(
      `${base}/audit?offset=${auditOffset}&limit=20`,
      "GET",
      undefined,
      c.signal,
    )
      .then((v) => {
        if (!c.signal.aborted) setAudit(v);
      })
      .catch((e: unknown) => {
        if (!c.signal.aborted)
          setError(e instanceof Error ? e.message : "replay_storage_unavailable");
      });
    return () => c.abort();
  }, [request, auditOpen, canAudit, canView, auditOffset, refresh]);
  useEffect(() => {
    if (draft?.provider !== "sftp" || !canManage) return;
    const c = new AbortController();
    void request<Target[]>("assets", "GET", undefined, c.signal)
      .then((v) => {
        if (!c.signal.aborted) setTargets(v.filter((a) => !a.protocol || a.protocol === "ssh"));
      })
      .catch(() => {
        if (!c.signal.aborted) setTargets([]);
      });
    return () => c.abort();
  }, [request, draft?.provider, canManage]);
  const change = (next: Draft) => {
    setDraft(next);
    saveNonce.current = nonce();
  };
  const selectProvider = (provider: Provider) => {
    if (!draft) return;
    change({
      provider,
      enabled: provider !== "local",
      prefix: provider === "local" ? "" : draft.prefix || "recordings",
      revision: draft.revision,
      clear_session_token: false,
      ...(isCloud(provider) ? { cloud: emptyCloud(provider) } : {}),
      ...(provider === "sftp" ? { sftp_asset_id: "", sftp_directory: "recordings" } : {}),
    });
  };
  async function save(event: FormEvent) {
    event.preventDefault();
    if (!draft || busyRef.current) return;
    busyRef.current = true;
    setBusy(true);
    setError("");
    setMessage("");
    try {
      const config = await request<Config>(base, "PUT", {
        ...draft,
        request_id: saveNonce.current,
      });
      setSettings((s) => (s ? { ...s, config } : null));
      setDraft(null);
      setMessage(t("replayStorage.saved"));
      setRefresh((v) => v + 1);
    } catch (e) {
      setError(e instanceof Error ? e.message : "replay_storage_unavailable");
    } finally {
      busyRef.current = false;
      setBusy(false);
    }
  }
  async function mutate(ref: Ref, action: Action) {
    if (busyRef.current) return;
    if (!/^[A-Za-z0-9_-]{16,128}$/.test(ref.session_id)) {
      setError("replay_storage_invalid");
      return;
    }
    if (action === "evict" && !window.confirm(t("replayStorage.confirmEvict"))) return;
    const key = action + ":" + ref.kind + ":" + ref.session_id;
    let id = mutations.current.get(key);
    if (!id) {
      id = nonce();
      mutations.current.set(key, id);
    }
    busyRef.current = true;
    setBusy(true);
    setError("");
    setMessage("");
    try {
      await request<Record>(
        `${base}/records/${ref.kind}/${encodeURIComponent(ref.session_id)}/${action}`,
        "POST",
        { request_id: id },
      );
      mutations.current.delete(key);
      setMessage(t("replayStorage.actionSaved"));
      setRefresh((v) => v + 1);
    } catch (e) {
      setError(e instanceof Error ? e.message : "replay_storage_unavailable");
    } finally {
      busyRef.current = false;
      setBusy(false);
    }
  }
  const date = (value?: string) =>
    value ? new Date(value).toLocaleString(i18n.language) : t("replayStorage.none");
  const pagination = (position: number, total: number, update: (offset: number) => void) => (
    <div className="labels-toolbar">
      <button
        type="button"
        disabled={busy || position === 0}
        onClick={() => update(Math.max(0, position - 20))}
      >
        {t("replayStorage.previous")}
      </button>
      <span>{t("replayStorage.count", { count: total })}</span>
      <button
        type="button"
        disabled={busy || position + 20 >= total}
        onClick={() => update(position + 20)}
      >
        {t("replayStorage.next")}
      </button>
    </div>
  );
  return (
    <section className="labels-page replay-storage-page" aria-busy={loading || busy}>
      <h1>{t("replayStorage.title")}</h1>
      <p>{t("replayStorage.description")}</p>
      {error && (
        <p role="alert">
          {t(`replayStorage.errors.${error}`, {
            defaultValue: t("replayStorage.errors.replay_storage_unavailable"),
          })}
        </p>
      )}
      {message && <p role="status">{message}</p>}
      {ready && !canView ? (
        <p>{t("replayStorage.denied")}</p>
      ) : (
        <>
          <div className="labels-toolbar">
            <button
              type="button"
              disabled={busy || !ready}
              onClick={() => {
                setDraft(null);
                setError("");
                setRefresh((v) => v + 1);
              }}
            >
              {t("replayStorage.refresh")}
            </button>
          </div>
          {settings && (
            <article className="labels-editor" aria-label={t("replayStorage.configuration")}>
              <h2>{t("replayStorage.configuration")}</h2>
              <p>
                {t(`replayStorage.providers.${settings.config.provider}`)} ·{" "}
                {t(settings.config.enabled ? "replayStorage.enabled" : "replayStorage.disabled")} ·{" "}
                {t("replayStorage.revision", { revision: settings.config.revision })}
              </p>
              <p>{t("replayStorage.backupHint")}</p>
              {canManage && !draft && (
                <button
                  type="button"
                  disabled={busy}
                  onClick={() => {
                    setDraft(draftFor(settings.config));
                    saveNonce.current = nonce();
                    setError("");
                    setMessage("");
                  }}
                >
                  {t("replayStorage.edit")}
                </button>
              )}
            </article>
          )}
          {canManage && draft && (
            <form
              className="labels-editor replay-storage-form"
              onSubmit={(e) => {
                void save(e);
              }}
            >
              <fieldset disabled={busy}>
                <label>
                  {t("replayStorage.provider")}
                  <select
                    value={draft.provider}
                    onChange={(e) => selectProvider(e.target.value as Provider)}
                  >
                    {providers.map((p) => (
                      <option
                        key={p}
                        value={p}
                        disabled={p === "postgres" && !settings?.postgres_available}
                      >
                        {t(`replayStorage.providers.${p}`)}
                      </option>
                    ))}
                  </select>
                </label>
                {draft.provider !== "local" && (
                  <>
                    <label className="replay-storage-check">
                      <input
                        type="checkbox"
                        checked={draft.enabled}
                        onChange={(e) => change({ ...draft, enabled: e.target.checked })}
                      />
                      {t("replayStorage.enabled")}
                    </label>
                    <label>
                      {t("replayStorage.prefix")}
                      <input
                        value={draft.prefix}
                        maxLength={256}
                        required
                        onChange={(e) => change({ ...draft, prefix: e.target.value })}
                      />
                    </label>
                  </>
                )}
                {isCloud(draft.provider) && draft.cloud && (
                  <>
                    <div className="replay-storage-grid">
                      {cloudFields.map((key) => (
                        <label key={key}>
                          {t(`replayStorage.fields.${key}`)}
                          <input
                            value={draft.cloud?.[key] || ""}
                            type={
                              key === "secret_access_key" || key === "session_token"
                                ? "password"
                                : "text"
                            }
                            autoComplete={
                              key === "secret_access_key" || key === "session_token"
                                ? "new-password"
                                : "off"
                            }
                            required={key !== "secret_access_key" && key !== "session_token"}
                            maxLength={
                              key === "session_token"
                                ? 16384
                                : key === "secret_access_key"
                                  ? 8192
                                  : 2048
                            }
                            onChange={(e) =>
                              change({
                                ...draft,
                                cloud: { ...draft.cloud!, [key]: e.target.value },
                              })
                            }
                          />
                        </label>
                      ))}
                    </div>
                    <p>{t("replayStorage.secretHint")}</p>
                    <label className="replay-storage-check">
                      <input
                        type="checkbox"
                        checked={draft.clear_session_token}
                        onChange={(e) =>
                          change({ ...draft, clear_session_token: e.target.checked })
                        }
                      />
                      {t("replayStorage.clearToken")}
                    </label>
                    <details>
                      <summary>{t("replayStorage.advanced")}</summary>
                      {draft.provider === "s3" && (
                        <label className="replay-storage-check">
                          <input
                            type="checkbox"
                            checked={draft.cloud.path_style}
                            onChange={(e) =>
                              change({
                                ...draft,
                                cloud: { ...draft.cloud!, path_style: e.target.checked },
                              })
                            }
                          />
                          {t("replayStorage.pathStyle")}
                        </label>
                      )}
                      <label>
                        {t("replayStorage.rootCA")}
                        <textarea
                          rows={5}
                          value={draft.cloud.root_ca_pem || ""}
                          maxLength={65536}
                          onChange={(e) =>
                            change({
                              ...draft,
                              cloud: { ...draft.cloud!, root_ca_pem: e.target.value },
                            })
                          }
                        />
                      </label>
                    </details>
                  </>
                )}
                {draft.provider === "sftp" && (
                  <>
                    <p>{t("replayStorage.sftpHint")}</p>
                    <label>
                      {t("replayStorage.sftpAsset")}
                      <input
                        list="replay-storage-targets"
                        required
                        value={draft.sftp_asset_id || ""}
                        maxLength={128}
                        onChange={(e) => change({ ...draft, sftp_asset_id: e.target.value })}
                      />
                      <datalist id="replay-storage-targets">
                        {targets
                          .flatMap((a) => [
                            { id: a.id, label: `${a.name} · ${a.username}` },
                            ...(a.accounts || []).map((account) => ({
                              id: account.id,
                              label: `${a.name} · ${account.username}`,
                            })),
                          ])
                          .map((a) => (
                            <option key={a.id} value={a.id}>
                              {a.label}
                            </option>
                          ))}
                      </datalist>
                    </label>
                    <label>
                      {t("replayStorage.sftpDirectory")}
                      <input
                        required
                        value={draft.sftp_directory || ""}
                        maxLength={256}
                        onChange={(e) => change({ ...draft, sftp_directory: e.target.value })}
                      />
                    </label>
                  </>
                )}
                {draft.provider === "postgres" && <p>{t("replayStorage.postgresHint")}</p>}
                <div className="labels-toolbar">
                  <button type="submit">{t("replayStorage.save")}</button>
                  <button type="button" onClick={() => setDraft(null)}>
                    {t("replayStorage.cancel")}
                  </button>
                </div>
              </fieldset>
            </form>
          )}
          {canArchive && (
            <form
              className="labels-bindings"
              onSubmit={(e) => {
                e.preventDefault();
                void mutate(selection, "archive");
              }}
            >
              <h2>{t("replayStorage.archiveExisting")}</h2>
              <fieldset disabled={busy}>
                <div className="replay-storage-grid">
                  <label>
                    {t("replayStorage.kind")}
                    <select
                      value={selection.kind}
                      onChange={(e) =>
                        setSelection({ ...selection, kind: e.target.value as Ref["kind"] })
                      }
                    >
                      <option value="terminal">{t("replayStorage.kinds.terminal")}</option>
                      <option value="desktop">{t("replayStorage.kinds.desktop")}</option>
                    </select>
                  </label>
                  <label>
                    {t("replayStorage.sessionID")}
                    <input
                      required
                      minLength={16}
                      maxLength={128}
                      pattern="[A-Za-z0-9_-]{16,128}"
                      value={selection.session_id}
                      onChange={(e) => setSelection({ ...selection, session_id: e.target.value })}
                    />
                  </label>
                </div>
                <button type="submit">{t("replayStorage.actions.archive")}</button>
              </fieldset>
            </form>
          )}
          <h2>{t("replayStorage.records")}</h2>
          {records.results.length === 0 && <p>{t("replayStorage.empty")}</p>}
          <div className="labels-catalog">
            {records.results.map((r) => (
              <article key={r.kind + ":" + r.session_id} aria-label={r.session_id}>
                <h3>{t(`replayStorage.kinds.${r.kind}`)}</h3>
                <code>{r.session_id}</code>
                <p>
                  {t(`replayStorage.status.${r.status}`)} ·{" "}
                  {t("replayStorage.revision", { revision: r.config_revision })}
                </p>
                <dl>
                  <dt>{t("replayStorage.size")}</dt>
                  <dd>
                    {t("replayStorage.mib", {
                      size: (r.size / 1048576).toLocaleString(i18n.language, {
                        maximumFractionDigits: 2,
                      }),
                    })}
                  </dd>
                  <dt>{t("replayStorage.attempts")}</dt>
                  <dd>{r.attempts}</dd>
                  <dt>{t("replayStorage.verified")}</dt>
                  <dd>{date(r.verified_at)}</dd>
                  <dt>{t("replayStorage.localCopy")}</dt>
                  <dd>
                    {t(r.local_evicted_at ? "replayStorage.removed" : "replayStorage.retained")}
                  </dd>
                </dl>
                {r.error_code && <p>{t(`replayStorage.failures.${r.error_code}`)}</p>}
                <div className="labels-toolbar">
                  {canArchive && r.status === "failed" && (
                    <button
                      type="button"
                      disabled={busy}
                      onClick={() => {
                        void mutate(r, "retry");
                      }}
                    >
                      {t("replayStorage.actions.retry")}
                    </button>
                  )}
                  {canVerify && (
                    <button
                      type="button"
                      disabled={busy || r.status !== "stored"}
                      onClick={() => {
                        void mutate(r, "verify");
                      }}
                    >
                      {t("replayStorage.actions.verify")}
                    </button>
                  )}
                  {canEvict && (
                    <button
                      type="button"
                      disabled={busy || r.status !== "stored" || !!r.local_evicted_at}
                      onClick={() => {
                        void mutate(r, "evict");
                      }}
                    >
                      {t("replayStorage.actions.evict")}
                    </button>
                  )}
                </div>
              </article>
            ))}
          </div>
          {pagination(offset, records.total, setOffset)}
          {canAudit && (
            <section>
              <label className="replay-storage-check">
                <input
                  type="checkbox"
                  checked={auditOpen}
                  onChange={(e) => setAuditOpen(e.target.checked)}
                />
                {t("replayStorage.audit")}
              </label>
              {auditOpen && (
                <>
                  <ol className="labels-audit">
                    {audit.results.map((a, index) => (
                      <li key={a.at + ":" + index}>
                        {date(a.at)} · {t(`replayStorage.auditActions.${a.action}`)} ·{" "}
                        <code>{a.actor_id}</code>
                        {a.ref && (
                          <>
                            {" "}
                            ·{" "}
                            <code>
                              {t(`replayStorage.kinds.${a.ref.kind}`)} / {a.ref.session_id}
                            </code>
                          </>
                        )}
                      </li>
                    ))}
                  </ol>
                  {pagination(auditOffset, audit.total, setAuditOffset)}
                </>
              )}
            </section>
          )}
        </>
      )}
    </section>
  );
}
