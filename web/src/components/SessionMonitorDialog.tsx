import { useEffect, useRef, useState } from "react";
import { Terminal } from "@xterm/xterm";
import { useTranslation } from "react-i18next";
import "@xterm/xterm/css/xterm.css";

type Props = {
  session: { session_id: string; asset_name: string; operator?: string };
  accessToken: string;
  viewerID: string;
  onClose: () => void;
};

export default function SessionMonitorDialog({ session, accessToken, viewerID, onClose }: Props) {
  const { t } = useTranslation();
  const hostRef = useRef<HTMLDivElement>(null);
  const [state, setState] = useState<"connecting" | "connected" | "closed" | "failed">(
    "connecting",
  );

  useEffect(() => {
    const host = hostRef.current;
    if (!host) return;
    let active = true;
    let socket: WebSocket | null = null;
    let queuedBytes = 0;
    const controller = new AbortController();
    const terminal = new Terminal({
      disableStdin: true,
      cursorBlink: false,
      fontFamily: "Cascadia Code, Consolas, monospace",
      fontSize: 13,
      scrollback: 5000,
      theme: { background: "#080d14", foreground: "#dbe7f5" },
    });
    terminal.open(host);
    // Keep StrictMode's discarded mount from issuing a second live ticket.
    const start = window.setTimeout(() => {
      void (async () => {
        try {
          const response = await fetch(
            `/api/v1/sessions/${encodeURIComponent(session.session_id)}/monitor`,
            {
              method: "POST",
              headers: accessToken ? { Authorization: `Bearer ${accessToken}` } : {},
              signal: controller.signal,
            },
          );
          if (!response.ok) throw new Error("monitor unavailable");
          const result = (await response.json()) as { ticket: string; websocket_url: string };
          if (!active) return;
          if (!result.ticket || !result.websocket_url.startsWith("/ws/"))
            throw new Error("invalid monitor response");
          const url = new URL(result.websocket_url, window.location.href);
          if (url.origin !== window.location.origin) throw new Error("invalid monitor origin");
          url.protocol = url.protocol === "https:" ? "wss:" : "ws:";
          socket = new WebSocket(url, ["jms233-monitor-v1", `jms233-ticket.${result.ticket}`]);
          socket.binaryType = "arraybuffer";
          socket.onopen = () => {
            if (active) setState("connected");
          };
          socket.onerror = () => {
            if (active) setState("failed");
          };
          socket.onclose = () => {
            if (active) setState((value) => (value === "failed" ? value : "closed"));
          };
          socket.onmessage = (event: MessageEvent<ArrayBuffer | string>) => {
            if (!active) return;
            if (event.data instanceof ArrayBuffer) {
              const bytes = new Uint8Array(event.data);
              queuedBytes += bytes.byteLength;
              if (queuedBytes > 512 * 1024) {
                setState("failed");
                socket?.close();
                return;
              }
              terminal.write(bytes, () => {
                queuedBytes -= bytes.byteLength;
              });
            } else {
              try {
                const message = JSON.parse(event.data) as {
                  type: string;
                  cols: number;
                  rows: number;
                };
                if (
                  message.type === "resize" &&
                  Number.isInteger(message.cols) &&
                  Number.isInteger(message.rows) &&
                  message.cols >= 2 &&
                  message.cols <= 500 &&
                  message.rows >= 2 &&
                  message.rows <= 500
                )
                  terminal.resize(message.cols, message.rows);
              } catch {
                setState("failed");
                socket?.close();
              }
            }
          };
        } catch {
          if (active) setState("failed");
        }
      })();
    }, 0);
    return () => {
      active = false;
      window.clearTimeout(start);
      controller.abort();
      socket?.close();
      terminal.dispose();
    };
  }, [accessToken, session.session_id]);

  useEffect(() => {
    const keydown = (event: KeyboardEvent) => {
      if (event.key === "Escape") onClose();
    };
    window.addEventListener("keydown", keydown);
    return () => window.removeEventListener("keydown", keydown);
  }, [onClose]);

  return (
    <div
      className="ssh-terminal-backdrop"
      role="presentation"
      onMouseDown={(event) => {
        if (event.target === event.currentTarget) onClose();
      }}
    >
      <section
        className="ssh-terminal-dialog"
        role="dialog"
        aria-modal="true"
        aria-labelledby="session-monitor-title"
      >
        <header className="ssh-terminal-header">
          <div>
            <h2 id="session-monitor-title">
              {t("audit.monitorTitle", { name: session.asset_name })}
            </h2>
            <span className={`ssh-terminal-status ${state}`} role="status">
              {t(`terminal.${state}`)}
            </span>
          </div>
          <button type="button" className="button-secondary" onClick={onClose}>
            {t("terminal.close")}
          </button>
        </header>
        <p className="session-monitor-notice">{t("audit.monitorHint")}</p>
        {state === "failed" && (
          <p className="ssh-terminal-error" role="alert">
            {t("audit.monitorFailed")}
          </p>
        )}
        <div className="session-monitor-surface">
          <div className="ssh-terminal-host" ref={hostRef} aria-label={t("audit.monitorOutput")} />
          <div className="session-monitor-watermark" aria-hidden="true">
            {viewerID} · {session.session_id}
          </div>
        </div>
      </section>
    </div>
  );
}
