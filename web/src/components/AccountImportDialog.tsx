import { requestID as newRequestID } from "../utils/requestID";
import { useCallback, useEffect, useRef, useState } from "react";
import { useTranslation } from "react-i18next";
import { toggleLang } from "../i18n";
import "./account-import.css";

type Row = {
  line: number;
  action: string;
  asset_id: string;
  asset_name: string;
  account_id: string;
  username: string;
  credential_type: string;
  key_fingerprint?: string;
  active: boolean;
  credential_replaced: boolean;
  version?: string;
};
type Issue = { line: number; field?: string; code: string };
type Preview = {
  request_id: string;
  rows: Row[];
  issues: Issue[];
  preview_token?: string;
  expires_at?: string;
  committed: boolean;
};
type Receipt = {
  request_id: string;
  rows: Row[];
  actor: { id: string; name: string };
  created_at: string;
};
type History = {
  request_id: string;
  actor: { id: string; name: string };
  created_at: string;
  count: number;
  created: number;
  updated: number;
};
type Payload = { format: string; content: string; request_id: string };
class ImportError extends Error {
  constructor(readonly code: string) {
    super(code);
  }
}
const knownErrors = new Set([
  "invalid",
  "denied",
  "not_found",
  "conflict",
  "expired",
  "capacity",
  "unavailable",
  "file_size",
  "file_format",
]);

export default function AccountImportDialog({
  accessToken,
  hosts,
  onChanged,
  onClose,
}: {
  accessToken: string;
  hosts: { id: string; name: string; protocol?: string; parent_asset_id?: string }[];
  onChanged: () => void;
  onClose: () => void;
}) {
  const { t, i18n } = useTranslation();
  const dialog = useRef<HTMLDialogElement>(null),
    fileInput = useRef<HTMLInputElement>(null),
    reader = useRef<FileReader | null>(null),
    payload = useRef<Payload | null>(null),
    pending = useRef<AbortController | null>(null),
    mounted = useRef(true),
    lifetime = useRef<AbortController | null>(null);
  const [filename, setFilename] = useState(""),
    [busy, setBusy] = useState(false),
    [error, setError] = useState(""),
    [preview, setPreview] = useState<Preview | null>(null),
    [receipt, setReceipt] = useState<Receipt | null>(null),
    [rowOffset, setRowOffset] = useState(0),
    [issueLimit, setIssueLimit] = useState(50);
  const [history, setHistory] = useState<{ results: History[]; total: number }>({
      results: [],
      total: 0,
    }),
    [historyError, setHistoryError] = useState(false),
    [historyOffset, setHistoryOffset] = useState(0),
    [hostQuery, setHostQuery] = useState("");
  useEffect(() => {
    mounted.current = true;
    lifetime.current = new AbortController();
    const previous = document.activeElement;
    const element = dialog.current;
    element?.showModal();
    fileInput.current?.focus();
    return () => {
      mounted.current = false;
      lifetime.current?.abort();
      pending.current?.abort();
      reader.current?.abort();
      reader.current = null;
      payload.current = null;
      element?.close();
      if (previous instanceof HTMLElement) previous.focus();
    };
  }, []);
  const request = useCallback(
    async (path: string, init?: RequestInit) => {
      const headers = new Headers(init?.headers);
      if (accessToken) headers.set("Authorization", `Bearer ${accessToken}`);
      const signals = [AbortSignal.timeout(60_000)];
      if (init?.signal) signals.push(init.signal);
      if (lifetime.current) signals.push(lifetime.current.signal);
      const response = await fetch(path, { ...init, headers, signal: AbortSignal.any(signals) });
      if (!response.ok) {
        let code =
          response.status === 403
            ? "denied"
            : response.status === 404
              ? "not_found"
              : "unavailable";
        try {
          code = (await response.json()).error_code || code;
        } catch {
          /* Use the status fallback. */
        }
        throw new ImportError(knownErrors.has(code) ? code : "unavailable");
      }
      return response;
    },
    [accessToken],
  );
  const fail = (e: unknown) => setError(e instanceof ImportError ? e.code : "unavailable");
  const loadHistory = useCallback(
    async (signal?: AbortSignal) => {
      try {
        const response = await request(
          `/api/v1/accounts/imports?offset=${historyOffset}&limit=10`,
          { signal },
        );
        const data = await response.json();
        if (!Array.isArray(data.results) || !Number.isSafeInteger(data.total)) throw Error();
        if (mounted.current && !signal?.aborted) {
          setHistory(data);
          setHistoryError(false);
        }
      } catch {
        if (mounted.current && !signal?.aborted) {
          setHistory({ results: [], total: 0 });
          setHistoryError(true);
        }
      }
    },
    [request, historyOffset],
  );
  useEffect(() => {
    const controller = new AbortController();
    queueMicrotask(() => {
      if (!controller.signal.aborted) void loadHistory(controller.signal);
    });
    return () => controller.abort();
  }, [loadHistory]);
  function clearFile(resetInput = true) {
    payload.current = null;
    reader.current?.abort();
    reader.current = null;
    if (resetInput && fileInput.current) fileInput.current.value = "";
    setFilename("");
    setPreview(null);
    setRowOffset(0);
  }
  function chooseFile(file: File | undefined) {
    clearFile(false);
    setError("");
    setReceipt(null);
    if (!file) return;
    const format = file.name.split(".").at(-1)?.toLowerCase();
    if (format !== "csv" && format !== "xlsx") {
      setError("file_format");
      return;
    }
    if (!file.size || file.size > 10 * 1024 * 1024) {
      setError("file_size");
      return;
    }
    const id = newRequestID(),
      r = new FileReader();
    reader.current = r;
    setBusy(true);
    setFilename(file.name);
    r.onload = () => {
      if (mounted.current && reader.current === r) {
        const value = typeof r.result === "string" ? r.result : "";
        payload.current = { format, content: value.slice(value.indexOf(",") + 1), request_id: id };
        reader.current = null;
        setBusy(false);
      }
    };
    r.onerror = () => {
      if (mounted.current && reader.current === r) {
        reader.current = null;
        setFilename("");
        setBusy(false);
        setError("file_format");
      }
    };
    r.readAsDataURL(file);
  }
  async function run(mode: "preview" | "commit") {
    const value = payload.current;
    if (!value) return;
    setBusy(true);
    setError("");
    pending.current?.abort();
    const controller = new AbortController();
    pending.current = controller;
    try {
      const response = await request(
        `/api/v1/accounts/imports${mode === "preview" ? "/preview" : ""}`,
        {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          signal: AbortSignal.any([controller.signal, AbortSignal.timeout(60_000)]),
          body: JSON.stringify({
            ...value,
            ...(mode === "commit" ? { preview_token: preview?.preview_token } : {}),
          }),
        },
      );
      const result = await response.json();
      if (!mounted.current || controller.signal.aborted) return;
      setRowOffset(0);
      setIssueLimit(50);
      if (mode === "preview") {
        if (!Array.isArray(result.rows) || !Array.isArray(result.issues)) throw Error();
        setPreview(result);
        setReceipt(null);
      } else {
        if (!Array.isArray(result.rows) || !result.request_id) throw Error();
        setReceipt(result);
        clearFile();
        onChanged();
        void loadHistory();
      }
    } catch (e) {
      if (mounted.current && !controller.signal.aborted) {
        fail(e);
        if (e instanceof ImportError && (e.code === "conflict" || e.code === "expired"))
          setPreview(null);
      }
    } finally {
      if (mounted.current) setBusy(false);
    }
  }
  async function template(format: "csv" | "xlsx") {
    setBusy(true);
    setError("");
    try {
      const data = await (
        await request(`/api/v1/accounts/imports/template?format=${format}`)
      ).json();
      if (!mounted.current) return;
      const decoded = atob(data.content),
        bytes = Uint8Array.from(decoded, (c) => c.charCodeAt(0));
      const url = URL.createObjectURL(
        new Blob([bytes], {
          type:
            format === "csv"
              ? "text/csv;charset=utf-8"
              : "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        }),
      );
      const link = document.createElement("a");
      link.href = url;
      link.download = `accounts-template.${format}`;
      link.click();
      setTimeout(() => URL.revokeObjectURL(url), 1000);
    } catch (e) {
      if (mounted.current) fail(e);
    } finally {
      if (mounted.current) setBusy(false);
    }
  }
  async function showReceipt(id: string, actor: string) {
    setBusy(true);
    setError("");
    try {
      const response = await request(
        `/api/v1/accounts/imports/${encodeURIComponent(id)}?actor_id=${encodeURIComponent(actor)}`,
      );
      const result = await response.json();
      if (mounted.current) {
        setReceipt(result);
        setPreview(null);
        setRowOffset(0);
      }
    } catch (e) {
      if (mounted.current) fail(e);
    } finally {
      if (mounted.current) setBusy(false);
    }
  }
  const rows = preview?.rows || receipt?.rows || [];
  return (
    <dialog
      ref={dialog}
      className="account-import-dialog"
      aria-labelledby="account-import-title"
      aria-describedby="account-import-hint"
      onCancel={(e) => {
        e.preventDefault();
        onClose();
      }}
    >
      <header>
        <h2 id="account-import-title">{t("accountImport.title")}</h2>
        <div className="account-import-actions">
          <button type="button" onClick={() => void toggleLang()}>
            {t("sharing.language")}
          </button>
          <button type="button" onClick={onClose}>
            {t("audit.closeCommands")}
          </button>
        </div>
      </header>
      <p id="account-import-hint" className="settings-help">
        {t("accountImport.hint")}
      </p>
      <div className="account-import-actions">
        {(["csv", "xlsx"] as const).map((format) => (
          <button
            type="button"
            key={format}
            className="button-secondary"
            disabled={busy}
            onClick={() => void template(format)}
          >
            {t("accountImport.template", { format: format.toUpperCase() })}
          </button>
        ))}
      </div>
      <details>
        <summary>{t("accountImport.hostIDs")}</summary>
        <label>
          {t("accountImport.searchHost")}
          <input value={hostQuery} onChange={(e) => setHostQuery(e.target.value)} />
        </label>
        <ul className="account-import-hosts">
          {hosts
            .filter(
              (h) =>
                !h.parent_asset_id &&
                (!h.protocol || h.protocol === "ssh") &&
                (h.name.toLowerCase().includes(hostQuery.toLowerCase()) ||
                  h.id.includes(hostQuery)),
            )
            .slice(0, 20)
            .map((h) => (
              <li key={h.id}>
                <span>{h.name}</span>
                <input
                  readOnly
                  aria-label={t("accountImport.hostID", { name: h.name })}
                  value={h.id}
                  onFocus={(e) => e.target.select()}
                />
              </li>
            ))}
        </ul>
      </details>
      <form
        onSubmit={(e) => {
          e.preventDefault();
          void run("preview");
        }}
        aria-busy={busy}
      >
        <label htmlFor="account-import-file">{t("accountImport.file")}</label>
        <input
          ref={fileInput}
          id="account-import-file"
          type="file"
          accept=".csv,.xlsx"
          disabled={busy}
          required
          aria-describedby={`account-import-file-help${error ? " account-import-error" : ""}${preview?.issues.length ? " account-import-issues" : ""}`}
          aria-invalid={
            error === "file_size" || error === "file_format" || !!preview?.issues.length
          }
          onChange={(e) => chooseFile(e.target.files?.[0])}
        />
        <p id="account-import-file-help" className="settings-help">
          {t("accountImport.fileHint")}
        </p>
        <div className="account-import-actions">
          <button type="submit" className="button-secondary" disabled={busy || !filename}>
            {t("accountImport.preview")}
          </button>
          <button
            type="button"
            className="button-primary"
            disabled={busy || !preview?.preview_token || preview.issues.length > 0 || !filename}
            onClick={() => void run("commit")}
          >
            {t("accountImport.commit", { count: preview?.rows.length || 0 })}
          </button>
          <button
            type="button"
            disabled={busy || !filename}
            onClick={() => {
              clearFile();
              setError("");
            }}
          >
            {t("accountImport.clear")}
          </button>
        </div>
      </form>
      {busy && <p role="status">{t("accountImport.working")}</p>}
      {error && (
        <p id="account-import-error" className="asset-error" role="alert">
          {t(`accountImport.errors.${error}`)}
        </p>
      )}
      {preview && (
        <p role="status">
          {preview.committed
            ? t("accountImport.alreadyCommitted")
            : t("accountImport.reviewHint", { count: preview.rows.length })}
        </p>
      )}
      {!!preview?.issues.length && (
        <section id="account-import-issues" role="alert">
          <h3>{t("accountImport.issues", { count: preview.issues.length })}</h3>
          <ul>
            {preview.issues.slice(0, issueLimit).map((issue, i) => (
              <li key={i}>
                {t("accountImport.issue", {
                  line: issue.line || "—",
                  field: issue.field || "—",
                  message: t(`accountImport.codes.${issue.code}`, {
                    defaultValue: t("accountImport.errors.invalid"),
                  }),
                })}
              </li>
            ))}
          </ul>
          {issueLimit < preview.issues.length && (
            <button type="button" onClick={() => setIssueLimit((v) => v + 50)}>
              {t("accountImport.moreIssues")}
            </button>
          )}
        </section>
      )}
      {receipt && (
        <p role="status">
          {t("accountImport.completed", { count: receipt.rows.length })}{" "}
          <code>{receipt.request_id}</code>
        </p>
      )}
      {rows.length > 0 && (
        <>
          <div className="account-import-table">
            <table>
              <thead>
                <tr>
                  <th>{t("accountImport.row")}</th>
                  <th>{t("accountImport.action")}</th>
                  <th>{t("accountImport.host")}</th>
                  <th>{t("managedAccounts.username")}</th>
                  <th>{t("managedAccounts.credentialType")}</th>
                  <th>{t("managedAccounts.status")}</th>
                </tr>
              </thead>
              <tbody>
                {rows.slice(rowOffset, rowOffset + 25).map((row) => (
                  <tr key={row.line + row.account_id}>
                    <td>{row.line}</td>
                    <td>{t(`accountImport.actions.${row.action}`)}</td>
                    <td>
                      {row.asset_name}
                      <small>{row.asset_id}</small>
                    </td>
                    <td>{row.username}</td>
                    <td>
                      {t(
                        row.credential_type === "ssh_key"
                          ? "managedAccounts.key"
                          : "managedAccounts.password",
                      )}
                      <small>
                        {t(
                          row.credential_replaced
                            ? "accountImport.replaced"
                            : "accountImport.retained",
                        )}
                      </small>
                      {row.key_fingerprint && <code>{row.key_fingerprint}</code>}
                    </td>
                    <td>
                      {t(row.active ? "managedAccounts.enabled" : "managedAccounts.disabled")}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <div className="account-import-actions">
            <button
              type="button"
              disabled={!rowOffset}
              onClick={() => setRowOffset((v) => Math.max(0, v - 25))}
            >
              {t("managedAccounts.previous")}
            </button>
            <span>
              {t("managedAccounts.showing", {
                from: rowOffset + 1,
                to: Math.min(rows.length, rowOffset + 25),
                total: rows.length,
              })}
            </span>
            <button
              type="button"
              disabled={rowOffset + 25 >= rows.length}
              onClick={() => setRowOffset((v) => v + 25)}
            >
              {t("managedAccounts.next")}
            </button>
          </div>
        </>
      )}
      <section>
        <h3>{t("accountImport.history")}</h3>
        <button
          type="button"
          className="button-secondary"
          disabled={busy}
          onClick={() => void loadHistory()}
        >
          {t("audit.refresh")}
        </button>
        {historyError && (
          <p role="alert" className="asset-error">
            {t("accountImport.errors.unavailable")}
          </p>
        )}
        <ul className="account-import-history">
          {history.results.map((h) => (
            <li key={h.actor.id + h.request_id}>
              <div>
                <code>{h.request_id}</code>
                <small>
                  {h.actor.name} · {new Date(h.created_at).toLocaleString(i18n.language)}
                </small>
                <span>
                  {t("accountImport.historyCounts", { created: h.created, updated: h.updated })}
                </span>
              </div>
              <button
                type="button"
                disabled={busy}
                onClick={() => void showReceipt(h.request_id, h.actor.id)}
              >
                {t("accountImport.receipt")}
              </button>
            </li>
          ))}
        </ul>
        <div className="account-import-actions">
          <button
            type="button"
            disabled={busy || !historyOffset}
            onClick={() => setHistoryOffset((v) => Math.max(0, v - 10))}
          >
            {t("managedAccounts.previous")}
          </button>
          <button
            type="button"
            disabled={busy || historyOffset + 10 >= history.total}
            onClick={() => setHistoryOffset((v) => v + 10)}
          >
            {t("managedAccounts.next")}
          </button>
        </div>
      </section>
    </dialog>
  );
}
