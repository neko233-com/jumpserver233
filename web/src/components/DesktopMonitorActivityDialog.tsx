import { useEffect, useState } from "react";
import { useTranslation } from "react-i18next";
type Event = { event: string; at: string; viewer: string; monitor_id: string };
export default function DesktopMonitorActivityDialog({
  sessionID,
  assetName,
  accessToken,
  onClose,
}: {
  sessionID: string;
  assetName: string;
  accessToken: string;
  onClose: () => void;
}) {
  const { t, i18n } = useTranslation();
  const [rows, setRows] = useState<Event[]>([]),
    [offset, setOffset] = useState(0),
    [total, setTotal] = useState(0),
    [reload, setReload] = useState(0),
    [failed, setFailed] = useState(false);
  useEffect(() => {
    const controller = new AbortController();
    void fetch(
      `/api/v1/desktop-sessions/${encodeURIComponent(sessionID)}/monitor-events?offset=${offset}&limit=20`,
      {
        signal: controller.signal,
        headers: accessToken ? { Authorization: `Bearer ${accessToken}` } : {},
      },
    )
      .then(async (r) => {
        if (!r.ok) throw Error("Desktop monitor audit unavailable");
        const value = (await r.json()) as { results: Event[]; total: number };
        if (!controller.signal.aborted) {
          setRows(value.results);
          setTotal(value.total);
          setFailed(false);
        }
      })
      .catch(() => {
        if (!controller.signal.aborted) setFailed(true);
      });
    return () => controller.abort();
  }, [sessionID, accessToken, offset, reload]);
  useEffect(() => {
    const key = (e: KeyboardEvent) => {
      if (e.key === "Escape") onClose();
    };
    window.addEventListener("keydown", key);
    return () => window.removeEventListener("keydown", key);
  }, [onClose]);
  return (
    <div className="ssh-terminal-backdrop" role="presentation">
      <section
        className="asset-modal command-audit-dialog"
        role="dialog"
        aria-modal="true"
        aria-label={t("desktopMonitor.events")}
      >
        <h2>
          {assetName} · {t("desktopMonitor.events")}
        </h2>
        <button type="button" className="button-secondary" onClick={() => setReload((v) => v + 1)}>
          {t("audit.refresh")}
        </button>
        {failed && <p role="alert">{t("desktopMonitor.auditFailed")}</p>}
        {rows.map((row, index) => (
          <p key={`${row.monitor_id}-${row.event}-${index}`}>
            <time dateTime={row.at}>{new Date(row.at).toLocaleString(i18n.language)}</time> ·{" "}
            <strong>{row.viewer}</strong> ·{" "}
            {t(row.event === "monitor_started" ? "desktopMonitor.started" : "desktopMonitor.ended")}
          </p>
        ))}
        {!failed && total === 0 && <p>{t("desktopMonitor.empty")}</p>}
        <p>
          {t("audit.showing", {
            from: total === 0 ? 0 : offset + 1,
            to: Math.min(total, offset + rows.length),
            total,
          })}
        </p>
        <div className="session-share-row">
          <button
            type="button"
            className="button-secondary"
            disabled={offset === 0}
            onClick={() => setOffset((v) => Math.max(0, v - 20))}
          >
            {t("audit.previous")}
          </button>
          <button
            type="button"
            className="button-secondary"
            disabled={offset + rows.length >= total}
            onClick={() => setOffset((v) => v + 20)}
          >
            {t("audit.next")}
          </button>
          <button type="button" className="button-secondary" onClick={onClose}>
            {t("audit.closeCommands")}
          </button>
        </div>
      </section>
    </div>
  );
}
