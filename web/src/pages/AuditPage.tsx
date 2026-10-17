import { lazy, Suspense, useCallback, useEffect, useState, type FormEvent } from "react";
import { useTranslation } from "react-i18next";
import { useAuth } from "../auth/AuthContext";
import { usePermissions } from "../auth/usePermissions";

const RDPDesktopAudit = lazy(() => import("../components/RDPDesktopAudit"));
const SessionReplayDialog = lazy(() => import("../components/SessionReplayDialog"));
const SessionCommandsDialog = lazy(() => import("../components/SessionCommandsDialog"));
const SessionMonitorDialog = lazy(() => import("../components/SessionMonitorDialog"));
const pageSize = 50;

type SessionRecord = {
  kubernetes?: { namespace: string; pod: string; container: string; pod_uid: string };
  session_id: string;
  asset_id: string;
  asset_name: string;
  operator?: string;
  operator_id?: string;
  username: string;
  started_at: string;
  ended_at?: string;
  status: "active" | "ended" | "interrupted";
  end_reason?: string;
  replay_available: boolean;
};

type SessionPage = {
  results: SessionRecord[];
  total: number;
  active_total: number;
};

type FileTransfer = {
  id: string;
  actor: string;
  asset_id: string;
  action: "upload" | "download" | "mkdir" | "delete";
  path: string;
  bytes: number;
  success: boolean;
  error_code?: string;
  at: string;
};

type FileTransferPage = { results: FileTransfer[]; total: number };

const reasons: Record<string, string> = {
  idle_timeout: "audit.idleTimeout",
  duration_limit: "audit.durationLimit",
  closed_by_client: "audit.endReason.closedByClient",
  disconnected: "audit.endReason.disconnected",
  server_shutdown: "audit.endReason.serverShutdown",
  terminal_io_error: "audit.endReason.terminalIOError",
  ticket_expired: "audit.endReason.ticketExpired",
  websocket_handshake_failed: "audit.endReason.websocketFailed",
};

function formatTime(value: string | undefined, locale: string) {
  if (!value) return "—";
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? "—" : date.toLocaleString(locale);
}

function formatBytes(bytes: number) {
  if (!Number.isFinite(bytes) || bytes < 0) return "—";
  if (bytes < 1024) return `${bytes} B`;
  const units = ["KB", "MB", "GB", "TB"];
  let value = bytes / 1024;
  let unit = 0;
  while (value >= 1024 && unit < units.length - 1) {
    value /= 1024;
    unit++;
  }
  return `${value.toFixed(value < 10 ? 1 : 0)} ${units[unit]}`;
}

export default function AuditPage() {
  const { allows, userID } = usePermissions();
  const { t, i18n } = useTranslation();
  const { accessToken, setAccessToken } = useAuth();
  const [tokenDraft, setTokenDraft] = useState("");
  const [tokenRequired, setTokenRequired] = useState(false);
  const [tokenRejected, setTokenRejected] = useState(false);
  const [sessions, setSessions] = useState<SessionRecord[]>([]);
  const [total, setTotal] = useState(0);
  const [activeTotal, setActiveTotal] = useState(0);
  const [offset, setOffset] = useState(0);
  const [loading, setLoading] = useState(true);
  const [loadFailed, setLoadFailed] = useState(false);
  const [stoppingID, setStoppingID] = useState("");
  const [pendingStop, setPendingStop] = useState<SessionRecord | null>(null);
  const [selectedReplay, setSelectedReplay] = useState<SessionRecord | null>(null);
  const [selectedCommands, setSelectedCommands] = useState<SessionRecord | null>(null);
  const [selectedMonitor, setSelectedMonitor] = useState<SessionRecord | null>(null);
  const [desktopOpen, setDesktopOpen] = useState(false);
  const [activeTab, setActiveTab] = useState<"sessions" | "files">("sessions");
  const [fileTransfers, setFileTransfers] = useState<FileTransfer[]>([]);
  const [fileTransferTotal, setFileTransferTotal] = useState(0);
  const [transfersLoading, setTransfersLoading] = useState(false);

  const request = useCallback(
    (url: string, init?: RequestInit) => {
      const headers = new Headers(init?.headers);
      if (accessToken) headers.set("Authorization", `Bearer ${accessToken}`);
      return fetch(url, { ...init, headers });
    },
    [accessToken],
  );

  const loadSessions = useCallback(async () => {
    setLoading(true);
    try {
      const response = await request(`/api/v1/sessions?limit=${pageSize}&offset=${offset}`);
      if (response.status === 401) {
        setTokenRequired(true);
        setTokenRejected(Boolean(accessToken));
        setSessions([]);
        setTotal(0);
        setActiveTotal(0);
        setLoadFailed(false);
        return;
      }
      if (!response.ok) throw new Error("session list request failed");
      const result = (await response.json()) as SessionPage;
      setSessions(result.results);
      setTotal(result.total);
      setActiveTotal(result.active_total);
      setTokenRequired(false);
      setTokenRejected(false);
      setLoadFailed(false);
    } catch {
      setLoadFailed(true);
    } finally {
      setLoading(false);
    }
  }, [accessToken, offset, request]);

  const loadFileTransfers = useCallback(async () => {
    setTransfersLoading(true);
    try {
      const response = await request("/api/v1/file-transfers?limit=200&offset=0");
      if (response.status === 401) {
        setTokenRequired(true);
        setTokenRejected(Boolean(accessToken));
        setFileTransfers([]);
        setFileTransferTotal(0);
        setLoadFailed(false);
        return;
      }
      if (!response.ok) throw new Error("file transfer audit request failed");
      const result = (await response.json()) as FileTransferPage;
      setFileTransfers(result.results);
      setFileTransferTotal(result.total);
      setTokenRequired(false);
      setTokenRejected(false);
      setLoadFailed(false);
    } catch {
      setLoadFailed(true);
    } finally {
      setTransfersLoading(false);
    }
  }, [accessToken, request]);

  useEffect(() => {
    if (activeTab === "sessions") {
      // The API returns all sessions to administrators and only owned sessions to operators.
      // eslint-disable-next-line react/set-state-in-effect
      void loadSessions();
      const timer = window.setInterval(() => void loadSessions(), 10_000);
      return () => window.clearInterval(timer);
    }
    // eslint-disable-next-line react/set-state-in-effect
    void loadFileTransfers();
  }, [activeTab, loadFileTransfers, loadSessions]);

  const activeCount = activeTotal;

  function applyToken(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setAccessToken(tokenDraft.trim());
    setTokenRejected(false);
  }

  async function confirmStopSession() {
    if (!pendingStop) return;
    const session = pendingStop;
    setStoppingID(session.session_id);
    try {
      const response = await request(`/api/v1/sessions/${encodeURIComponent(session.session_id)}`, {
        method: "DELETE",
      });
      if (!response.ok) throw new Error("session stop failed");
      setPendingStop(null);
      await loadSessions();
    } catch {
      setLoadFailed(true);
    } finally {
      setStoppingID("");
    }
  }

  function statusLabel(status: SessionRecord["status"]) {
    return t(`audit.status.${status}`);
  }

  return (
    <section className="session-audit">
      <div className="session-audit-heading">
        <div>
          <h2>{t("audit.title")}</h2>
          <p>{t("audit.subtitle")}</p>
        </div>
        <div className="session-audit-summary">
          <span>
            <strong>{activeTab === "sessions" ? total : fileTransferTotal}</strong>{" "}
            {t(activeTab === "sessions" ? "audit.total" : "audit.fileTotal")}
          </span>
          {activeTab === "sessions" && (
            <span className="session-active-count">
              <i />
              {activeCount} {t("audit.active")}
            </span>
          )}
          <button
            type="button"
            className="button-secondary"
            onClick={() => void (activeTab === "sessions" ? loadSessions() : loadFileTransfers())}
            disabled={activeTab === "sessions" ? loading : transfersLoading}
          >
            {(activeTab === "sessions" ? loading : transfersLoading) ? "…" : t("audit.refresh")}
          </button>
        </div>
      </div>

      <div className="audit-tabs" role="tablist" aria-label={t("audit.title")}>
        <button
          type="button"
          role="tab"
          aria-selected={activeTab === "sessions"}
          className={activeTab === "sessions" ? "active" : ""}
          onClick={() => setActiveTab("sessions")}
        >
          {t("audit.sessionsTab")}
        </button>
        <button
          type="button"
          role="tab"
          aria-selected={activeTab === "files"}
          className={activeTab === "files" ? "active" : ""}
          onClick={() => setActiveTab("files")}
        >
          {t("audit.filesTab")}
        </button>
      </div>

      <details onToggle={(e) => setDesktopOpen(e.currentTarget.open)}>
        <summary>{t("rdp.audit")}</summary>
        {desktopOpen && (
          <Suspense fallback={null}>
            <RDPDesktopAudit />
          </Suspense>
        )}
      </details>
      {tokenRequired && (
        <form className="asset-token-panel" onSubmit={applyToken}>
          <div>
            <strong>{t("audit.tokenRequired")}</strong>
            {tokenRejected && <p role="alert">{t("audit.tokenRejected")}</p>}
          </div>
          <label>
            <span>{t("audit.tokenLabel")}</span>
            <input
              type="password"
              value={tokenDraft}
              onChange={(event) => setTokenDraft(event.target.value)}
              autoComplete="current-password"
            />
          </label>
          <button type="submit" className="button-primary">
            {t("audit.tokenApply")}
          </button>
        </form>
      )}

      {loadFailed && (
        <p className="asset-error" role="alert">
          {t("audit.loadError")}
        </p>
      )}
      {activeTab === "sessions" && (
        <>
          <div className="session-table-wrap">
            <table className="session-table">
              <thead>
                <tr>
                  <th>{t("audit.asset")}</th>
                  <th>{t("audit.account")}</th>
                  <th>{t("audit.operator")}</th>
                  <th>{t("audit.statusLabel")}</th>
                  <th>{t("audit.started")}</th>
                  <th>{t("audit.ended")}</th>
                  <th>{t("audit.reason")}</th>
                  <th>{t("audit.actions")}</th>
                </tr>
              </thead>
              <tbody>
                {sessions.map((session) => (
                  <tr key={session.session_id}>
                    <td>
                      <strong>{session.asset_name || session.asset_id}</strong>
                      <small>{session.asset_id}</small>
                      {session.kubernetes && (
                        <small>
                          {session.kubernetes.namespace} / {session.kubernetes.pod} /{" "}
                          {session.kubernetes.container}
                        </small>
                      )}
                    </td>
                    <td>{session.username || "—"}</td>
                    <td>{session.operator || "—"}</td>
                    <td>
                      <span className={`session-state ${session.status}`}>
                        <i />
                        {statusLabel(session.status)}
                      </span>
                    </td>
                    <td>{formatTime(session.started_at, i18n.language)}</td>
                    <td>{formatTime(session.ended_at, i18n.language)}</td>
                    <td>
                      {session.end_reason
                        ? t(reasons[session.end_reason] ?? "audit.endReason.other")
                        : "—"}
                    </td>
                    <td>
                      <div className="session-actions">
                        {session.status === "active" &&
                          (session.operator_id === userID ||
                            allows("audit.sessions.monitor_all")) && (
                            <button
                              type="button"
                              className="button-text"
                              onClick={() => setSelectedMonitor(session)}
                            >
                              {t("audit.monitor")}
                            </button>
                          )}
                        {session.status === "active" &&
                          (session.operator_id === userID ||
                            allows("audit.sessions.terminate_all")) && (
                            <button
                              type="button"
                              className="button-text danger"
                              disabled={stoppingID === session.session_id}
                              onClick={() => setPendingStop(session)}
                            >
                              {stoppingID === session.session_id ? "…" : t("audit.stop")}
                            </button>
                          )}
                        {session.replay_available &&
                          (session.operator_id === userID || allows("audit.replays.view_all")) && (
                            <button
                              type="button"
                              className="button-text"
                              onClick={() => setSelectedReplay(session)}
                            >
                              {t("audit.replay")}
                            </button>
                          )}
                        {(session.operator_id === userID || allows("audit.commands.view_all")) && (
                          <button
                            type="button"
                            className="button-text"
                            onClick={() => setSelectedCommands(session)}
                          >
                            {t("audit.commands")}
                          </button>
                        )}
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
            {!loading && sessions.length === 0 && !tokenRequired && !loadFailed && (
              <div className="session-empty">
                <strong>{t("audit.empty")}</strong>
                <span>{t("audit.emptyHint")}</span>
              </div>
            )}
          </div>

          <div className="session-pagination">
            <span>
              {t("audit.showing", {
                from: total === 0 ? 0 : offset + 1,
                to: Math.min(offset + sessions.length, total),
                total,
              })}
            </span>
            <div>
              <button
                type="button"
                className="button-secondary"
                disabled={offset === 0 || loading}
                onClick={() => setOffset(Math.max(0, offset - pageSize))}
              >
                {t("audit.previous")}
              </button>
              <button
                type="button"
                className="button-secondary"
                disabled={offset + pageSize >= total || loading}
                onClick={() => setOffset(offset + pageSize)}
              >
                {t("audit.next")}
              </button>
            </div>
          </div>
        </>
      )}

      {activeTab === "files" && (
        <div className="session-table-wrap">
          <table className="session-table file-transfer-table">
            <thead>
              <tr>
                <th>{t("audit.asset")}</th>
                <th>{t("audit.operator")}</th>
                <th>{t("audit.fileAction")}</th>
                <th>{t("audit.filePath")}</th>
                <th>{t("audit.fileBytes")}</th>
                <th>{t("audit.fileResult")}</th>
                <th>{t("audit.started")}</th>
              </tr>
            </thead>
            <tbody>
              {fileTransfers.map((entry) => (
                <tr key={entry.id}>
                  <td>
                    <strong>{entry.asset_id}</strong>
                  </td>
                  <td>{entry.actor}</td>
                  <td>{t(`audit.fileActions.${entry.action}`)}</td>
                  <td className="file-transfer-path" title={entry.path}>
                    {entry.path}
                  </td>
                  <td>{formatBytes(entry.bytes)}</td>
                  <td>
                    <span className={`session-state ${entry.success ? "ended" : "interrupted"}`}>
                      <i />
                      {t(
                        entry.success
                          ? "audit.fileSuccess"
                          : `audit.fileErrors.${entry.error_code ?? "other"}`,
                      )}
                    </span>
                  </td>
                  <td>{formatTime(entry.at, i18n.language)}</td>
                </tr>
              ))}
            </tbody>
          </table>
          {!transfersLoading && fileTransfers.length === 0 && !tokenRequired && !loadFailed && (
            <div className="session-empty">
              <strong>{t("audit.fileEmpty")}</strong>
              <span>{t("audit.fileEmptyHint")}</span>
            </div>
          )}
        </div>
      )}

      {selectedReplay && (
        <Suspense
          fallback={
            <div className="ssh-terminal-backdrop">
              <div className="replay-loading">{t("audit.loadingReplay")}</div>
            </div>
          }
        >
          <SessionReplayDialog
            session={selectedReplay}
            accessToken={accessToken}
            onClose={() => setSelectedReplay(null)}
          />
        </Suspense>
      )}
      {selectedMonitor && (
        <Suspense
          fallback={
            <div className="ssh-terminal-backdrop">
              <div className="replay-loading">{t("terminal.connecting")}</div>
            </div>
          }
        >
          <SessionMonitorDialog
            session={selectedMonitor}
            accessToken={accessToken}
            viewerID={userID}
            onClose={() => setSelectedMonitor(null)}
          />
        </Suspense>
      )}
      {selectedCommands && (
        <Suspense
          fallback={
            <div className="ssh-terminal-backdrop">
              <div className="replay-loading">{t("audit.commandLoading")}</div>
            </div>
          }
        >
          <SessionCommandsDialog
            sessionID={selectedCommands.session_id}
            assetName={selectedCommands.asset_name || selectedCommands.asset_id}
            status={selectedCommands.status}
            accessToken={accessToken}
            onClose={() => setSelectedCommands(null)}
          />
        </Suspense>
      )}
      {pendingStop && (
        <div
          className="asset-modal-backdrop session-stop-backdrop"
          role="presentation"
          onMouseDown={(event) => {
            if (event.target === event.currentTarget) setPendingStop(null);
          }}
        >
          <section
            className="asset-modal session-stop-dialog"
            role="alertdialog"
            aria-modal="true"
            aria-labelledby="session-stop-title"
            aria-describedby="session-stop-description"
          >
            <h3 id="session-stop-title">{t("audit.stopTitle")}</h3>
            <p id="session-stop-description">
              {t("audit.stopConfirm", { name: pendingStop.asset_name })}
            </p>
            <div className="asset-modal-actions">
              <button
                type="button"
                className="button-secondary"
                disabled={stoppingID === pendingStop.session_id}
                onClick={() => setPendingStop(null)}
              >
                {t("audit.stopCancel")}
              </button>
              <button
                type="button"
                className="button-stop"
                disabled={stoppingID === pendingStop.session_id}
                onClick={() => void confirmStopSession()}
              >
                {stoppingID === pendingStop.session_id ? t("audit.stopping") : t("audit.stop")}
              </button>
            </div>
          </section>
        </div>
      )}
    </section>
  );
}
