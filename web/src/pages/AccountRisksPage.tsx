import { useCallback, useEffect, useRef, useState, type FormEvent } from "react";
import { useTranslation } from "react-i18next";
import { Link } from "react-router-dom";
import { useAuth } from "../auth/AuthContext";
import { usePermissions } from "../auth/usePermissions";
import "../i18n/locales/features/account-risks/register";
import "./account-risks.css";

type Ref = { asset_id: string; account_id: string; asset_name: string; username: string };
type Finding = Ref & {
  id: string;
  kind: string;
  severity: string;
  reasons: string[];
  credential_type: string;
  state: string;
  revision: number;
  source_version: string;
  policy_revision: number;
  note: string;
  first_seen: string;
  last_seen: string;
  last_used_at?: string;
  rotated_at: string;
  occurrences: number;
  peers: Ref[];
  peer_count: number;
  outdated: boolean;
};
type Policy = {
  revision: number;
  enabled: boolean;
  interval_hours: number;
  min_password_length: number;
  max_credential_age_days: number;
  unused_account_days: number;
  resolved_retention_days: number;
  audit_retention_days: number;
  include_disabled: boolean;
  checks: string[];
  owner: { id: string; name: string };
  next_run?: string;
  last_error?: string;
};
type Scan = {
  id: string;
  request_id: string;
  state: string;
  error_code?: string;
  actor: { id: string; name: string };
  started_at: string;
  accounts: number;
  open: number;
  resolved: number;
};
type Audit = {
  at: string;
  actor: { name: string };
  action: string;
  finding_id?: string;
  scan_id?: string;
  after?: string;
};
type Page<T> = { results: T[]; total: number };
const kinds = [
  "weak_password",
  "duplicate_password",
  "reused_key",
  "stale_credential",
  "unused_account",
  "rotation_disabled",
  "pending_credential",
];
const states = ["open", "confirmed", "ignored", "resolved"];
const errorCodes = new Set([
  "invalid",
  "denied",
  "not_found",
  "conflict",
  "busy",
  "capacity",
  "unavailable",
]);
class RiskError extends Error {
  constructor(readonly code: string) {
    super(code);
  }
}
const emptyPage = <T,>(): Page<T> => ({ results: [], total: 0 });

export default function AccountRisksPage() {
  const { t, i18n } = useTranslation();
  const { accessToken } = useAuth();
  const { ready, allows } = usePermissions();
  const canView = allows("accounts.risks.view");
  const canScan = allows("accounts.risks.scan") && allows("assets.manage");
  const canPolicy = allows("accounts.risks.manage") && allows("assets.manage");
  const canReview = allows("accounts.risks.manage");
  const canExport = allows("accounts.risks.export");
  const canHistory = allows("assets.view_all") || allows("assets.manage");
  const lifetime = useRef<AbortController | null>(null);
  const dirty = useRef(false);
  const pendingRequest = useRef<{ request_id: string; revision: number } | null>(null);
  const [findings, setFindings] = useState<Page<Finding>>(emptyPage);
  const [policy, setPolicy] = useState<Policy | null>(null);
  const [draft, setDraft] = useState<Policy | null>(null);
  const [scans, setScans] = useState<Page<Scan>>(emptyPage);
  const [audit, setAudit] = useState<Page<Audit>>(emptyPage);
  const [historyError, setHistoryError] = useState(false);
  const [offset, setOffset] = useState(0),
    [scanOffset, setScanOffset] = useState(0),
    [auditOffset, setAuditOffset] = useState(0);
  const [filters, setFilters] = useState({ state: "open", kind: "", q: "" });
  const [filterDraft, setFilterDraft] = useState(filters);
  const [busy, setBusy] = useState(false),
    [scanning, setScanning] = useState(false);
  const [error, setError] = useState("");
  const [message, setMessage] = useState<{ key: string; values?: Record<string, number> } | null>(
    null,
  );
  const [lastRequest, setLastRequest] = useState("");
  const [selected, setSelected] = useState<Finding | null>(null);
  const [note, setNote] = useState("");
  useEffect(() => {
    lifetime.current = new AbortController();
    return () => lifetime.current?.abort();
  }, []);
  const request = useCallback(
    async (url: string, init?: RequestInit) => {
      const headers = new Headers(init?.headers);
      if (accessToken) headers.set("Authorization", `Bearer ${accessToken}`);
      if (init?.body) headers.set("Content-Type", "application/json");
      const signals = [AbortSignal.timeout(65_000)];
      if (lifetime.current) signals.push(lifetime.current.signal);
      if (init?.signal) signals.push(init.signal);
      const response = await fetch(url, { ...init, headers, signal: AbortSignal.any(signals) });
      if (!response.ok) {
        let code = response.status === 403 ? "denied" : "unavailable";
        try {
          code = (await response.json()).error_code || code;
        } catch {
          /* Status fallback. */
        }
        throw new RiskError(errorCodes.has(code) ? code : "unavailable");
      }
      return response;
    },
    [accessToken],
  );
  const query = new URLSearchParams({ ...filters, offset: String(offset), limit: "50" }).toString();
  const loadHistory = useCallback(
    async (signal?: AbortSignal) => {
      if (!canHistory) return;
      try {
        const [s, a] = await Promise.all([
          request(`/api/v1/accounts/risks/scans?offset=${scanOffset}&limit=10`, { signal }).then(
            (r) => r.json(),
          ),
          request(`/api/v1/accounts/risks/audit?offset=${auditOffset}&limit=10`, { signal }).then(
            (r) => r.json(),
          ),
        ]);
        if (!signal?.aborted && !lifetime.current?.signal.aborted) {
          setScans(s);
          setAudit(a);
          setHistoryError(false);
        }
      } catch {
        if (!signal?.aborted && !lifetime.current?.signal.aborted) setHistoryError(true);
      }
    },
    [request, canHistory, scanOffset, auditOffset],
  );
  const load = useCallback(
    async (signal?: AbortSignal) => {
      if (!canView) return;
      try {
        const [rows, nextPolicy] = await Promise.all([
          request(`/api/v1/accounts/risks?${query}`, { signal }).then((r) => r.json()),
          request("/api/v1/accounts/risks/policy", { signal }).then((r) => r.json()),
        ]);
        if (signal?.aborted || lifetime.current?.signal.aborted) return;
        setFindings(rows);
        setPolicy(nextPolicy);
        if (!dirty.current) setDraft(nextPolicy);
      } catch (e) {
        if (!signal?.aborted && !lifetime.current?.signal.aborted)
          setError(e instanceof RiskError ? e.code : "unavailable");
      }
    },
    [request, canView, query],
  );
  useEffect(() => {
    const controller = new AbortController();
    queueMicrotask(() => {
      if (!controller.signal.aborted) {
        void load(controller.signal);
        void loadHistory(controller.signal);
      }
    });
    return () => controller.abort();
  }, [load, loadHistory]);
  useEffect(() => {
    if (!scanning || !canHistory) return;
    const controller = new AbortController();
    let timer: ReturnType<typeof setTimeout>;
    const poll = async () => {
      await loadHistory(controller.signal);
      if (!controller.signal.aborted) timer = setTimeout(() => void poll(), 2000);
    };
    void poll();
    return () => {
      controller.abort();
      clearTimeout(timer);
    };
  }, [scanning, canHistory, loadHistory]);
  const fail = (e: unknown) => setError(e instanceof RiskError ? e.code : "unavailable");
  const date = (value?: string) =>
    value && !value.startsWith("0001-") ? new Date(value).toLocaleString(i18n.language) : "—";
  async function scan() {
    if (!policy) return;
    setBusy(true);
    setScanning(true);
    setError("");
    setMessage(null);
    const input = pendingRequest.current || {
      revision: policy.revision,
      request_id: crypto.randomUUID(),
    };
    pendingRequest.current = input;
    setLastRequest(input.request_id);
    try {
      const result: Scan = await (
        await request("/api/v1/accounts/risks/scans", {
          method: "POST",
          body: JSON.stringify(input),
        })
      ).json();
      if (lifetime.current?.signal.aborted) return;
      pendingRequest.current = null;
      if (result.state === "succeeded")
        setMessage({
          key: "scanDone",
          values: { accounts: result.accounts, open: result.open, resolved: result.resolved },
        });
      else
        setError(
          result.error_code && errorCodes.has(result.error_code)
            ? result.error_code
            : "unavailable",
        );
      await Promise.all([load(), loadHistory()]);
    } catch (e) {
      if (!lifetime.current?.signal.aborted) {
        fail(e);
        if (
          e instanceof RiskError &&
          ["invalid", "denied", "conflict", "capacity", "busy"].includes(e.code)
        )
          pendingRequest.current = null;
        await loadHistory();
      }
    } finally {
      if (!lifetime.current?.signal.aborted) {
        setBusy(false);
        setScanning(false);
      }
    }
  }
  async function savePolicy(e: FormEvent) {
    e.preventDefault();
    if (!draft) return;
    setBusy(true);
    setError("");
    setMessage(null);
    try {
      const next: Policy = await (
        await request("/api/v1/accounts/risks/policy", {
          method: "PUT",
          body: JSON.stringify(draft),
        })
      ).json();
      if (lifetime.current?.signal.aborted) return;
      dirty.current = false;
      setDraft(next);
      setPolicy(next);
      setMessage({ key: "saved" });
      await Promise.all([load(), loadHistory()]);
    } catch (e) {
      if (!lifetime.current?.signal.aborted) fail(e);
    } finally {
      if (!lifetime.current?.signal.aborted) setBusy(false);
    }
  }
  async function review(action: string) {
    if (!selected) return;
    setBusy(true);
    setError("");
    setMessage(null);
    try {
      const next: Finding = await (
        await request(`/api/v1/accounts/risks/${encodeURIComponent(selected.id)}/review`, {
          method: "POST",
          body: JSON.stringify({ action, revision: selected.revision, note }),
        })
      ).json();
      if (lifetime.current?.signal.aborted) return;
      setSelected({ ...next, peers: selected.peers, peer_count: selected.peer_count });
      setMessage({ key: "reviewed" });
      await Promise.all([load(), loadHistory()]);
    } catch (e) {
      if (!lifetime.current?.signal.aborted) fail(e);
    } finally {
      if (!lifetime.current?.signal.aborted) setBusy(false);
    }
  }
  async function cancel(id: string) {
    setError("");
    try {
      await request(`/api/v1/accounts/risks/scans/${encodeURIComponent(id)}`, { method: "DELETE" });
      setMessage({ key: "cancelling" });
      await loadHistory();
    } catch (e) {
      if (!lifetime.current?.signal.aborted) fail(e);
    }
  }
  async function exportCSV() {
    setBusy(true);
    setError("");
    try {
      const response = await request(`/api/v1/accounts/risks/export?${query}`);
      const blob = await response.blob();
      if (lifetime.current?.signal.aborted) return;
      const url = URL.createObjectURL(blob),
        link = document.createElement("a");
      link.href = url;
      link.download = "account-risks.csv";
      link.click();
      setTimeout(() => URL.revokeObjectURL(url), 1000);
    } catch (e) {
      if (!lifetime.current?.signal.aborted) fail(e);
    } finally {
      if (!lifetime.current?.signal.aborted) setBusy(false);
    }
  }
  function changePolicy<K extends keyof Policy>(key: K, value: Policy[K]) {
    dirty.current = true;
    setDraft((p) => (p ? { ...p, [key]: value } : p));
  }
  if (!ready) return <p role="status">{t("placeholder.skeleton")}</p>;
  if (!canView) return <p role="alert">{t("accountRisks.noView")}</p>;
  return (
    <section className="account-risks-page" aria-labelledby="account-risks-title">
      <header>
        <div>
          <h1 id="account-risks-title">{t("accountRisks.title")}</h1>
          <p className="settings-help">{t("accountRisks.hint")}</p>
        </div>
        <div className="risk-actions">
          <button
            type="button"
            disabled={busy}
            onClick={() => {
              setError("");
              void Promise.all([load(), loadHistory()]);
            }}
          >
            {t("accountRisks.refresh")}
          </button>
          {canScan && (
            <button
              type="button"
              className="button-primary"
              disabled={busy || !policy}
              onClick={() => void scan()}
            >
              {t("accountRisks.scan")}
            </button>
          )}
          {canExport && (
            <button type="button" disabled={busy} onClick={() => void exportCSV()}>
              {t("accountRisks.export")}
            </button>
          )}
        </div>
      </header>
      <p className="settings-help">{t("accountRisks.coverage")}</p>
      {error && (
        <p id="risk-page-error" role="alert" className="asset-error">
          {t(`accountRisks.errors.${error}`)}
        </p>
      )}
      {scanning && <p role="status">{t("accountRisks.scanning")}</p>}
      {message && <p role="status">{t(`accountRisks.${message.key}`, message.values)}</p>}
      {lastRequest && (
        <p className="settings-help">
          {t("accountRisks.request")}: <code>{lastRequest}</code>
        </p>
      )}
      <form
        className="risk-filters"
        onSubmit={(e) => {
          e.preventDefault();
          setFilters(filterDraft);
          setOffset(0);
        }}
      >
        <label>
          {t("accountRisks.search")}
          <input
            value={filterDraft.q}
            maxLength={128}
            onChange={(e) => setFilterDraft({ ...filterDraft, q: e.target.value })}
          />
        </label>
        <label>
          {t("accountRisks.state")}
          <select
            value={filterDraft.state}
            onChange={(e) => setFilterDraft({ ...filterDraft, state: e.target.value })}
          >
            <option value="">{t("accountRisks.all")}</option>
            {states.map((s) => (
              <option key={s} value={s}>
                {t(`accountRisks.states.${s}`)}
              </option>
            ))}
          </select>
        </label>
        <label>
          {t("accountRisks.kind")}
          <select
            value={filterDraft.kind}
            onChange={(e) => setFilterDraft({ ...filterDraft, kind: e.target.value })}
          >
            <option value="">{t("accountRisks.all")}</option>
            {kinds.map((k) => (
              <option key={k} value={k}>
                {t(`accountRisks.kinds.${k}`)}
              </option>
            ))}
          </select>
        </label>
        <button type="submit" disabled={busy}>
          {t("accountRisks.apply")}
        </button>
      </form>
      <p>{t("accountRisks.total", { count: findings.total })}</p>
      <div className="risk-table">
        <table>
          <thead>
            <tr>
              {["account", "risk", "severity", "state", "observed", "details"].map((key) => (
                <th key={key} scope="col">
                  {t(`accountRisks.${key}`)}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {findings.results.map((f) => (
              <tr key={f.id}>
                <td>
                  {f.asset_name}
                  <strong>{f.username}</strong>
                </td>
                <td>
                  {t(`accountRisks.kinds.${f.kind}`)}
                  {f.outdated && <small>{t("accountRisks.outdated")}</small>}
                </td>
                <td>
                  <span className={`risk-level risk-level-${f.severity}`}>
                    {t(`accountRisks.levels.${f.severity}`)}
                  </span>
                </td>
                <td>{t(`accountRisks.states.${f.state}`)}</td>
                <td>{date(f.last_seen)}</td>
                <td>
                  <button
                    type="button"
                    onClick={() => {
                      setSelected(f);
                      setNote(f.note);
                      setError("");
                    }}
                  >
                    {t("accountRisks.details")}
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      {!findings.results.length && <p>{t("accountRisks.empty")}</p>}
      <RiskPages offset={offset} limit={50} total={findings.total} setOffset={setOffset} />
      {draft && (
        <details className="risk-policy">
          <summary>{t("accountRisks.policy")}</summary>
          <p className="settings-help">{t("accountRisks.policyHint")}</p>
          <p>
            {policy?.enabled
              ? t("accountRisks.nextRun") + ": " + date(policy.next_run)
              : t("accountRisks.notScheduled")}
            {policy?.owner.name && (
              <>
                {" "}
                · {t("accountRisks.owner")}: {policy.owner.name}
              </>
            )}
          </p>
          {policy?.last_error && (
            <p role="alert">
              {t("accountRisks.lastError")}:{" "}
              {t(
                `accountRisks.errors.${errorCodes.has(policy.last_error) ? policy.last_error : "unavailable"}`,
              )}
            </p>
          )}
          <form onSubmit={savePolicy} aria-describedby={error ? "risk-page-error" : undefined}>
            <fieldset disabled={!canPolicy || busy}>
              <label className="risk-check">
                <input
                  type="checkbox"
                  checked={draft.enabled}
                  disabled={!canScan}
                  onChange={(e) => changePolicy("enabled", e.target.checked)}
                />
                {t("accountRisks.enabled")}
              </label>
              {!canScan && <p className="settings-help">{t("accountRisks.schedulePermission")}</p>}
              <div className="risk-policy-fields">
                {(
                  [
                    ["interval_hours", "hours", 1, 720],
                    ["min_password_length", "minLength", 8, 128],
                    ["max_credential_age_days", "maxAge", 1, 3650],
                    ["unused_account_days", "unused", 1, 3650],
                  ] as const
                ).map(([key, label, min, max]) => (
                  <label key={key}>
                    {t(`accountRisks.${label}`)}
                    <input
                      type="number"
                      required
                      min={min}
                      max={max}
                      value={draft[key]}
                      onChange={(e) => changePolicy(key, Number(e.target.value))}
                    />
                  </label>
                ))}
              </div>
              <label className="risk-check">
                <input
                  type="checkbox"
                  checked={draft.include_disabled}
                  onChange={(e) => changePolicy("include_disabled", e.target.checked)}
                />
                {t("accountRisks.includeDisabled")}
              </label>
              <fieldset>
                <legend>{t("accountRisks.checks")}</legend>
                <div className="risk-checks">
                  {kinds.map((k) => (
                    <label key={k} className="risk-check">
                      <input
                        type="checkbox"
                        checked={draft.checks.includes(k)}
                        onChange={(e) =>
                          changePolicy(
                            "checks",
                            e.target.checked
                              ? [...draft.checks, k]
                              : draft.checks.filter((v) => v !== k),
                          )
                        }
                      />
                      {t(`accountRisks.kinds.${k}`)}
                    </label>
                  ))}
                </div>
              </fieldset>
              <details>
                <summary>{t("accountRisks.retention")}</summary>
                <div className="risk-policy-fields">
                  <label>
                    {t("accountRisks.resolvedDays")}
                    <input
                      type="number"
                      required
                      min={1}
                      max={3650}
                      value={draft.resolved_retention_days}
                      onChange={(e) =>
                        changePolicy("resolved_retention_days", Number(e.target.value))
                      }
                    />
                  </label>
                  <label>
                    {t("accountRisks.auditDays")}
                    <input
                      type="number"
                      required
                      min={30}
                      max={3650}
                      value={draft.audit_retention_days}
                      onChange={(e) => changePolicy("audit_retention_days", Number(e.target.value))}
                    />
                  </label>
                </div>
              </details>
              <button type="submit" disabled={!draft.checks.length}>
                {t("accountRisks.save")}
              </button>
              {!draft.checks.length && <p role="status">{t("accountRisks.chooseCheck")}</p>}
            </fieldset>
          </form>
        </details>
      )}
      {canHistory && (
        <>
          <details className="risk-history">
            <summary>{t("accountRisks.history")}</summary>
            {historyError && <p role="alert">{t("accountRisks.historyUnavailable")}</p>}
            <div className="risk-table">
              <table>
                <thead>
                  <tr>
                    {[
                      "started",
                      "operator",
                      "result",
                      "accounts",
                      "openCount",
                      "resolvedCount",
                    ].map((key) => (
                      <th key={key} scope="col">
                        {t(`accountRisks.${key}`)}
                      </th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {scans.results.map((s) => (
                    <tr key={s.id}>
                      <td>
                        {date(s.started_at)}
                        <small>
                          <code>{s.request_id}</code>
                        </small>
                      </td>
                      <td>{s.actor.name}</td>
                      <td>
                        {t(`accountRisks.scanStates.${s.state}`)}
                        {s.error_code && (
                          <small>
                            {t(
                              `accountRisks.errors.${errorCodes.has(s.error_code) ? s.error_code : "unavailable"}`,
                            )}
                          </small>
                        )}
                        {s.state === "running" && canScan && (
                          <button type="button" onClick={() => void cancel(s.id)}>
                            {t("accountRisks.cancel")}
                          </button>
                        )}
                      </td>
                      <td>{s.accounts}</td>
                      <td>{s.open}</td>
                      <td>{s.resolved}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            <RiskPages
              offset={scanOffset}
              limit={10}
              total={scans.total}
              setOffset={setScanOffset}
            />
          </details>
          <details className="risk-history">
            <summary>{t("accountRisks.audit")}</summary>
            <ul>
              {audit.results.map((a, i) => (
                <li key={a.at + i}>
                  {date(a.at)} · {a.actor.name} · {t(`accountRisks.actions.${a.action}`)}{" "}
                  <code>{a.finding_id || a.scan_id || ""}</code>
                </li>
              ))}
            </ul>
            <RiskPages
              offset={auditOffset}
              limit={10}
              total={audit.total}
              setOffset={setAuditOffset}
            />
          </details>
        </>
      )}
      {selected && (
        <RiskDialog
          finding={selected}
          note={note}
          setNote={setNote}
          busy={busy}
          canReview={canReview}
          error={error}
          onClose={() => setSelected(null)}
          review={(action) => void review(action)}
        />
      )}
    </section>
  );
}
function RiskPages({
  offset,
  limit,
  total,
  setOffset,
}: {
  offset: number;
  limit: number;
  total: number;
  setOffset: (v: number) => void;
}) {
  const { t } = useTranslation();
  return (
    <nav className="risk-pages">
      <button
        type="button"
        disabled={!offset}
        onClick={() => setOffset(Math.max(0, offset - limit))}
      >
        {t("accountRisks.previous")}
      </button>
      <span>
        {t("accountRisks.showing", {
          from: total ? offset + 1 : 0,
          to: Math.min(total, offset + limit),
          total,
        })}
      </span>
      <button
        type="button"
        disabled={offset + limit >= total}
        onClick={() => setOffset(offset + limit)}
      >
        {t("accountRisks.next")}
      </button>
    </nav>
  );
}
function RiskDialog({
  finding: f,
  note,
  setNote,
  busy,
  canReview,
  error,
  onClose,
  review,
}: {
  finding: Finding;
  note: string;
  setNote: (v: string) => void;
  busy: boolean;
  canReview: boolean;
  error: string;
  onClose: () => void;
  review: (action: string) => void;
}) {
  const { t, i18n } = useTranslation();
  const dialog = useRef<HTMLDialogElement>(null),
    close = useRef<HTMLButtonElement>(null);
  useEffect(() => {
    const previous = document.activeElement,
      el = dialog.current;
    el?.showModal();
    close.current?.focus();
    return () => {
      el?.close();
      if (previous instanceof HTMLElement) previous.focus();
    };
  }, []);
  const date = (value?: string) =>
    value && !value.startsWith("0001-") ? new Date(value).toLocaleString(i18n.language) : "—";
  return (
    <dialog
      ref={dialog}
      className="risk-dialog"
      aria-labelledby="risk-detail-title"
      aria-describedby="risk-detail-help"
      onCancel={(e) => {
        e.preventDefault();
        onClose();
      }}
    >
      <header>
        <h2 id="risk-detail-title">
          {t(`accountRisks.kinds.${f.kind}`)} · {f.username}
        </h2>
        <button ref={close} type="button" onClick={onClose}>
          {t("accountRisks.close")}
        </button>
      </header>
      <p>
        {f.asset_name} · {f.username}
      </p>
      <p id="risk-detail-help" className="settings-help">
        {t("accountRisks.resolvedHint")}
      </p>
      {f.outdated && <p role="status">{t("accountRisks.outdated")}</p>}
      {error && (
        <p id="risk-detail-error" role="alert" className="asset-error">
          {t(`accountRisks.errors.${error}`)}
        </p>
      )}
      <h3>{t("accountRisks.reasonTitle")}</h3>
      <ul>
        {f.reasons.map((r) => (
          <li key={r}>{t(`accountRisks.reasons.${r}`)}</li>
        ))}
      </ul>
      <dl>
        {(
          [
            ["firstSeen", f.first_seen],
            ["lastSeen", f.last_seen],
            ["lastUsed", f.last_used_at],
            ["rotated", f.rotated_at],
          ] as const
        ).map(([key, at]) => (
          <div key={key}>
            <dt>{t(`accountRisks.${key}`)}</dt>
            <dd>{date(at)}</dd>
          </div>
        ))}
      </dl>
      <p role="status">
        {t("accountRisks.occurrences")}: {f.occurrences} · {t(`accountRisks.states.${f.state}`)}
      </p>
      {f.peer_count > 0 && (
        <section>
          <h3>{t("accountRisks.peers")}</h3>
          <p>{t("accountRisks.peerCount", { count: f.peer_count })}</p>
          {f.peer_count > f.peers.length && (
            <p>{t("accountRisks.peersLimit", { count: f.peers.length })}</p>
          )}
          <ul>
            {f.peers.map((p) => (
              <li key={p.account_id}>
                {p.asset_name} · {p.username}
              </li>
            ))}
          </ul>
        </section>
      )}
      <Link
        to={`/console?asset_id=${encodeURIComponent(f.asset_id)}&account_id=${encodeURIComponent(f.account_id)}`}
      >
        {t("accountRisks.manage")}
      </Link>
      {canReview && (
        <fieldset
          disabled={busy || f.outdated || f.state === "resolved"}
          aria-describedby={error ? "risk-detail-error" : "risk-detail-help"}
        >
          <label>
            {t("accountRisks.note")}
            <textarea maxLength={2048} value={note} onChange={(e) => setNote(e.target.value)} />
          </label>
          <div className="risk-actions">
            {(["confirm", "ignore", "reopen"] as const).map((action) => (
              <button type="button" key={action} onClick={() => review(action)}>
                {t(`accountRisks.${action}`)}
              </button>
            ))}
          </div>
        </fieldset>
      )}
    </dialog>
  );
}
