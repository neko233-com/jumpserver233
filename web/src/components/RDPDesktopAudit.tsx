import { lazy, Suspense, useCallback, useEffect, useRef, useState } from "react";
import { useTranslation } from "react-i18next";
import { useAuth } from "../auth/AuthContext";
import { usePermissions } from "../auth/usePermissions";
import "./rdp.css";
const DesktopMonitorDialog = lazy(() => import("./DesktopMonitorDialog"));
const DesktopMonitorActivityDialog = lazy(() => import("./DesktopMonitorActivityDialog"));
type Frame = { index: number; at_ms: number; width: number; height: number };
type Record = {
  session_id: string;
  asset_name: string;
  operator: string;
  operator_id: string;
  started_at: string;
  status: string;
  end_reason: string;
  inputs: number;
  frames?: Frame[];
};
export default function RDPDesktopAudit() {
  const { t, i18n } = useTranslation();
  const { accessToken } = useAuth();
  const { allows, userID } = usePermissions();
  const [rows, setRows] = useState<Record[]>([]),
    [selected, setSelected] = useState<Record | null>(null);
  const [position, setPosition] = useState(0),
    [failed, setFailed] = useState(false),
    [source, setSource] = useState("");
  const [playing, setPlaying] = useState(false);
  const [monitor, setMonitor] = useState<Record | null>(null),
    [activity, setActivity] = useState<Record | null>(null);
  const generation = useRef(0);
  const request = useCallback(
    (path: string, init?: RequestInit) => {
      const headers = new Headers(init?.headers);
      if (accessToken) headers.set("Authorization", `Bearer ${accessToken}`);
      return fetch(path, { ...init, headers });
    },
    [accessToken],
  );
  const load = useCallback(async () => {
    try {
      const r = await request("/api/v1/desktop-sessions");
      if (!r.ok) throw new Error();
      setRows((await r.json()).results);
      setFailed(false);
    } catch {
      setFailed(true);
    }
  }, [request]);
  useEffect(() => {
    const timer = setTimeout(() => void load(), 0);
    return () => clearTimeout(timer);
  }, [load]);
  const replay = async (id: string) => {
    try {
      const r = await request(`/api/v1/desktop-sessions/${id}`);
      if (!r.ok) throw new Error();
      const value = (await r.json()) as Record;
      setPosition(0);
      setPlaying(false);
      setSelected(value);
    } catch {
      setFailed(true);
    }
  };
  useEffect(() => {
    if (!selected || !selected.frames?.[position]) return;
    let active = true,
      objectURL = "";
    const controller = new AbortController();
    const current = ++generation.current;
    void request(`/api/v1/desktop-sessions/${selected.session_id}/frames/${position}`, {
      signal: controller.signal,
    })
      .then(async (r) => {
        if (!r.ok) throw new Error();
        const blob = await r.blob();
        if (active && current === generation.current) {
          objectURL = URL.createObjectURL(blob);
          setSource(objectURL);
        }
      })
      .catch(() => {
        if (active) setFailed(true);
      });
    return () => {
      active = false;
      controller.abort();
      if (objectURL) URL.revokeObjectURL(objectURL);
    };
  }, [selected, position, request]);
  useEffect(() => {
    if (!playing || !selected?.frames) return;
    const frames = selected.frames;
    if (position >= frames.length - 1) return;
    const delay = Math.max(
      100,
      Math.min(5000, frames[position + 1].at_ms - frames[position].at_ms),
    );
    const timer = setTimeout(() => setPosition((p) => p + 1), delay);
    return () => clearTimeout(timer);
  }, [playing, position, selected]);
  return (
    <section className="rdp-audit" aria-label={t("rdp.audit")}>
      <header className="asset-toolbar">
        <h2>{t("rdp.audit")}</h2>
        <button className="button-secondary" onClick={() => void load()}>
          {t("audit.refresh")}
        </button>
      </header>
      <p>{t("rdp.recordingHint")}</p>
      {failed && (
        <p role="alert" className="asset-error">
          {t("rdp.auditFailed")}
        </p>
      )}
      <div className="rdp-table-wrap">
        <table>
          <thead>
            <tr>
              <th>{t("audit.asset")}</th>
              <th>{t("audit.operator")}</th>
              <th>{t("audit.started")}</th>
              <th>{t("audit.statusLabel")}</th>
              <th>{t("assets.actions")}</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((row) => (
              <tr key={row.session_id}>
                <td>{row.asset_name}</td>
                <td>{row.operator}</td>
                <td>{new Date(row.started_at).toLocaleString(i18n.language)}</td>
                <td>
                  {t(
                    `audit.status.${["active", "ended", "interrupted"].includes(row.status) ? row.status : "interrupted"}`,
                  )}
                  {row.end_reason && (
                    <small className="settings-help">
                      {t(
                        row.end_reason === "idle_timeout"
                          ? "audit.idleTimeout"
                          : row.end_reason === "duration_limit"
                            ? "audit.durationLimit"
                            : "audit.endReason.other",
                      )}
                    </small>
                  )}
                </td>
                <td>
                  {row.status === "active" &&
                    (row.operator_id === userID || allows("audit.desktops.monitor_all")) && (
                      <button
                        className="button-secondary button-small"
                        onClick={() => setMonitor(row)}
                      >
                        {t("audit.monitor")}
                      </button>
                    )}
                  {(row.operator_id === userID || allows("audit.sessions.view_all")) && (
                    <button
                      className="button-secondary button-small"
                      onClick={() => setActivity(row)}
                    >
                      {t("desktopMonitor.events")}
                    </button>
                  )}
                  {(row.operator_id === userID ||
                    (row.status !== "active" && allows("audit.replays.view_all"))) && (
                    <button
                      className="button-secondary button-small"
                      onClick={() => void replay(row.session_id)}
                    >
                      {t("audit.replay")}
                    </button>
                  )}
                  {row.status === "active" &&
                    (row.operator_id === userID || allows("audit.sessions.terminate_all")) && (
                      <button
                        className="button-secondary button-small"
                        onClick={async () => {
                          const r = await request(`/api/v1/desktop-sessions/${row.session_id}`, {
                            method: "DELETE",
                          });
                          if (!r.ok) setFailed(true);
                          else void load();
                        }}
                      >
                        {t("rdp.stop")}
                      </button>
                    )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
        {rows.length === 0 && <p>{t("rdp.noSessions")}</p>}
      </div>
      <Suspense fallback={null}>
        {monitor && (
          <DesktopMonitorDialog
            sessionID={monitor.session_id}
            assetName={monitor.asset_name}
            accessToken={accessToken}
            onClose={() => setMonitor(null)}
          />
        )}
        {activity && (
          <DesktopMonitorActivityDialog
            sessionID={activity.session_id}
            assetName={activity.asset_name}
            accessToken={accessToken}
            onClose={() => setActivity(null)}
          />
        )}
      </Suspense>
      {selected && (
        <div className="ssh-terminal-backdrop" role="presentation">
          <section
            className="ssh-terminal-dialog rdp-dialog"
            role="dialog"
            aria-modal="true"
            aria-label={t("rdp.replay")}
          >
            <header className="ssh-terminal-header">
              <h2>
                {selected.asset_name} · {t("rdp.replay")}
              </h2>
              <button
                className="button-secondary"
                onClick={() => {
                  setSelected(null);
                  setPlaying(false);
                  setSource("");
                }}
              >
                {t("terminal.close")}
              </button>
            </header>
            <div className="rdp-replay">
              {source && <img src={source} alt={t("rdp.replayFrame")} />}
              <label>
                {t("rdp.timeline")} ·{" "}
                {((selected.frames?.[position]?.at_ms ?? 0) / 1000).toFixed(1)}s
                <input
                  type="range"
                  min={0}
                  max={Math.max(0, (selected.frames?.length ?? 1) - 1)}
                  value={position}
                  onChange={(e) => {
                    setPlaying(false);
                    setPosition(Number(e.target.value));
                  }}
                />
              </label>
              <button
                className="button-secondary"
                disabled={position >= (selected.frames?.length ?? 0) - 1}
                onClick={() => setPlaying((v) => !v)}
              >
                {t(playing ? "rdp.pause" : "rdp.play")}
              </button>
            </div>
          </section>
        </div>
      )}
    </section>
  );
}
