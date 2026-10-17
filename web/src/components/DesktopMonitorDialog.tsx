import { useEffect, useRef, useState } from "react";
import { useTranslation } from "react-i18next";
import { toggleLang } from "../i18n";
import { createDesktopFrameRenderer } from "./desktopFrameRenderer";
import "./rdp.css";

export default function DesktopMonitorDialog({
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
  const { t } = useTranslation();
  const canvas = useRef<HTMLCanvasElement>(null);
  const [state, setState] = useState("connecting"),
    [viewer, setViewer] = useState("");
  useEffect(() => {
    let active = true,
      socket: WebSocket | null = null;
    const controller = new AbortController();
    const renderer = createDesktopFrameRenderer(
      () => canvas.current,
      () => {
        if (active) setState("connected");
      },
      () => {
        if (active) {
          setState("failed");
          socket?.close();
        }
      },
    );
    const start = setTimeout(async () => {
      try {
        const r = await fetch(`/api/v1/desktop-sessions/${encodeURIComponent(sessionID)}/monitor`, {
          method: "POST",
          signal: controller.signal,
          headers: accessToken ? { Authorization: `Bearer ${accessToken}` } : {},
        });
        if (!r.ok) throw Error("Desktop monitor unavailable");
        const created = (await r.json()) as { websocket_url: string; ticket: string };
        if (!active) return;
        const url = new URL(created.websocket_url, window.location.href);
        if (
          url.origin !== window.location.origin ||
          url.pathname !== `/ws/desktop/${sessionID}/monitor`
        )
          throw Error("Invalid desktop monitor URL");
        url.protocol = window.location.protocol === "https:" ? "wss:" : "ws:";
        socket = new WebSocket(url, [
          "jms233-desktop-monitor-v1",
          `jms233-desktop-monitor-ticket.${created.ticket}`,
        ]);
        socket.binaryType = "arraybuffer";
        socket.onmessage = (event) => {
          if (!active) return;
          if (typeof event.data === "string") {
            try {
              const value = JSON.parse(event.data);
              if (value.type !== "ready" || !value.read_only || value.clipboard)
                throw Error("Invalid monitor state");
              setViewer(String(value.viewer_id));
            } catch {
              setState("failed");
              socket?.close();
            }
          } else renderer.push(event.data as ArrayBuffer);
        };
        socket.onclose = () => {
          if (active) setState((old) => (old === "failed" ? old : "closed"));
        };
        socket.onerror = () => {
          if (active) setState("failed");
        };
      } catch {
        if (active) setState("failed");
      }
    }, 0);
    return () => {
      active = false;
      clearTimeout(start);
      controller.abort();
      renderer.dispose();
      socket?.close();
    };
  }, [sessionID, accessToken]);
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
        className="ssh-terminal-dialog rdp-dialog"
        role="dialog"
        aria-modal="true"
        aria-labelledby="desktop-monitor-title"
      >
        <header className="ssh-terminal-header">
          <div>
            <h2 id="desktop-monitor-title">{t("desktopMonitor.title", { name: assetName })}</h2>
            <span role="status">{t(`terminal.${state}`)}</span>
          </div>
          <button type="button" className="lang-switch" onClick={() => void toggleLang()}>
            {t("sharing.language")}
          </button>
          <button type="button" className="button-secondary" onClick={onClose}>
            {t("desktopMonitor.close")}
          </button>
        </header>
        <p className="rdp-hint">{t("desktopMonitor.hint")}</p>
        {state === "failed" && (
          <p className="asset-error" role="alert">
            {t("audit.monitorFailed")}
          </p>
        )}
        <div className="rdp-viewport session-monitor-surface">
          <canvas ref={canvas} role="img" aria-label={t("desktopMonitor.screen")} />
          <div className="session-monitor-watermark" aria-hidden="true">
            JMS {viewer} · {sessionID}
          </div>
        </div>
      </section>
    </div>
  );
}
