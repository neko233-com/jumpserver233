import { lazy, Suspense, useEffect, useRef, useState } from "react";
import { BrandMark } from "../branding/BrandingContext";
import { Terminal } from "@xterm/xterm";
import "../i18n/locales/features/workspaces/register";
import { useTranslation } from "react-i18next";
import { toggleLang } from "../i18n";
import "@xterm/xterm/css/xterm.css";
import Icon from "./ui/Icon";
const SessionSharePanel = lazy(() => import("./SessionSharePanel"));

type Props = {
  protocol?: "ssh" | "telnet";
  kubernetesSelection?: { namespace: string; pod: string; container: string };
  assetId: string;
  assetName: string;
  accessToken: string;
  onClose: () => void;
};

type CreatedSession = {
  watermark?: string;
  session_id: string;
  websocket_url: string;
  ticket: string;
};

type ConnectionState = "connecting" | "review" | "connected" | "failed" | "closed";

export default function SSHTerminalDialog({
  assetId,
  assetName,
  accessToken,
  onClose,
  kubernetesSelection,
  protocol,
}: Props) {
  const { t } = useTranslation();
  const translations = useRef(t);
  useEffect(() => {
    translations.current = t;
  }, [t]);
  const terminalPrefix = kubernetesSelection
    ? "kubernetes"
    : protocol === "telnet"
      ? "telnet"
      : "terminal";
  const hostRef = useRef<HTMLDivElement>(null);
  const terminalRef = useRef<Terminal | null>(null);
  const closeButtonRef = useRef<HTMLButtonElement>(null);
  const fitRef = useRef<(() => void) | null>(null);
  const [fontSize, setFontSize] = useState(14);
  const [expanded, setExpanded] = useState(false);
  const [attempt, setAttempt] = useState(0);
  const [state, setState] = useState<ConnectionState>("connecting");
  const [watermark, setWatermark] = useState("");
  const [currentID, setCurrentID] = useState("");
  const [showSharing, setShowSharing] = useState(false);
  const [controlBlocked, setControlBlocked] = useState(false);

  useEffect(() => {
    const host = hostRef.current;
    if (!host) return;

    let active = true;
    let sessionId = "";
    let socket: WebSocket | null = null;
    let previousSize = "";
    const controller = new AbortController();
    const terminal = new Terminal({
      cursorBlink: true,
      fontFamily: "Cascadia Code, Consolas, monospace",
      fontSize: 14,
      lineHeight: 1.2,
      theme: {
        background: "#080d14",
        foreground: "#dbe7f5",
        cursor: "#5ee1a0",
        selectionBackground: "rgba(94, 225, 160, 0.28)",
      },
    });
    terminal.open(host);
    terminal.attachCustomKeyEventHandler((event) => {
      if (event.ctrlKey && event.shiftKey && event.code === "Space") {
        event.preventDefault();
        closeButtonRef.current?.focus();
        return false;
      }
      return true;
    });
    terminalRef.current = terminal;
    terminal.focus();

    const sendResize = () => {
      if (!active || !host.clientWidth || !host.clientHeight) return;
      const style = window.getComputedStyle(host);
      const horizontalPadding =
        Number.parseFloat(style.paddingLeft) + Number.parseFloat(style.paddingRight);
      const verticalPadding =
        Number.parseFloat(style.paddingTop) + Number.parseFloat(style.paddingBottom);
      const contentWidth = host.clientWidth - horizontalPadding;
      const contentHeight = host.clientHeight - verticalPadding;
      const sizeInPixels = terminal.options.fontSize || 14;
      const screen = host.querySelector<HTMLElement>(".xterm-screen");
      const cellWidth = screen?.clientWidth
        ? screen.clientWidth / terminal.cols
        : sizeInPixels * 0.62;
      const cellHeight = screen?.clientHeight
        ? screen.clientHeight / terminal.rows
        : sizeInPixels * 1.2;
      const cols = Math.max(24, Math.min(500, Math.floor(contentWidth / cellWidth)));
      const rows = Math.max(8, Math.min(500, Math.floor(contentHeight / cellHeight)));
      const size = `${cols}x${rows}`;
      if (size === previousSize) return;
      previousSize = size;
      terminal.resize(cols, rows);
      if (socket?.readyState === WebSocket.OPEN) {
        socket.send(JSON.stringify({ type: "resize", cols, rows }));
      }
    };
    fitRef.current = sendResize;
    let resizeFrame = 0;
    const observer = new ResizeObserver(() => {
      if (resizeFrame) return;
      resizeFrame = requestAnimationFrame(() => {
        resizeFrame = 0;
        sendResize();
      });
    });
    observer.observe(host);
    const inputSubscription = terminal.onData((data) => {
      if (socket?.readyState === WebSocket.OPEN) socket.send(new TextEncoder().encode(data));
    });

    const authHeaders = new Headers({ "Content-Type": "application/json" });
    if (accessToken) authHeaders.set("Authorization", `Bearer ${accessToken}`);

    const startTimer = window.setTimeout(() => {
      void startSession();
    }, 0);

    async function startSession() {
      try {
        sendResize();
        const response = await fetch(
          kubernetesSelection
            ? `/api/v1/assets/${encodeURIComponent(assetId)}/kubernetes/sessions`
            : protocol === "telnet"
              ? `/api/v1/assets/${encodeURIComponent(assetId)}/telnet/sessions`
              : "/api/v1/sessions",
          {
            method: "POST",
            headers: authHeaders,
            body: JSON.stringify(
              kubernetesSelection
                ? { ...kubernetesSelection, cols: terminal.cols, rows: terminal.rows }
                : protocol === "telnet"
                  ? { cols: terminal.cols, rows: terminal.rows }
                  : { asset_id: assetId, cols: terminal.cols, rows: terminal.rows },
            ),
            signal: controller.signal,
          },
        );
        if (response.status === 202) {
          const pending = (await response.json()) as { review_id?: string };
          if (!pending.review_id) throw new Error("invalid access review response");
          setState("review");
          terminal.write(`\r\n${translations.current(`${terminalPrefix}.loginReviewPending`)}\r\n`);
          while (active) {
            await new Promise((resolve) => window.setTimeout(resolve, 2_000));
            if (!active) return;
            const statusResponse = await fetch(
              `/api/v1/access-reviews/${encodeURIComponent(pending.review_id)}`,
              {
                headers: authHeaders,
                signal: controller.signal,
              },
            );
            if (!statusResponse.ok) throw new Error("access review status request failed");
            const review = (await statusResponse.json()) as { state?: string };
            if (review.state === "pending") continue;
            if (review.state === "approved") {
              terminal.write(
                `\r\n${translations.current(`${terminalPrefix}.loginReviewApproved`)}\r\n`,
              );
              setState("connecting");
              await startSession();
              return;
            }
            terminal.write(
              `\r\n${review.state === "denied" ? translations.current(`${terminalPrefix}.loginReviewDenied`) : translations.current(`${terminalPrefix}.loginReviewExpired`)}\r\n`,
            );
            setState("failed");
            return;
          }
          return;
        }
        if (!response.ok) throw new Error("session creation failed");
        const session = (await response.json()) as CreatedSession;
        if (active) setWatermark(session.watermark || "");
        if (!session.session_id || !session.ticket || !session.websocket_url.startsWith("/ws/")) {
          throw new Error("incomplete session response");
        }
        sessionId = session.session_id;
        if (active) setCurrentID(session.session_id);
        if (!active) {
          void closeSession(sessionId);
          return;
        }
        const socketProtocol = window.location.protocol === "https:" ? "wss:" : "ws:";
        const endpoint = `${socketProtocol}//${window.location.host}${session.websocket_url}`;
        socket = new WebSocket(endpoint, [
          "jms233-terminal-v1",
          `jms233-ticket.${session.ticket}`,
          "jms233-share-control-v1",
        ]);
        socket.binaryType = "arraybuffer";
        socket.onopen = () => {
          if (!active) return;
          setState("connected");
          terminal.clear();
          sendResize();
          terminal.focus();
        };
        socket.onmessage = (event) => {
          if (!active) return;
          if (event.data instanceof ArrayBuffer) terminal.write(new Uint8Array(event.data));
          else if (event.data instanceof Blob)
            void event.data.arrayBuffer().then((data) => {
              if (active) terminal.write(new Uint8Array(data));
            });
          else if (typeof event.data === "string") {
            try {
              const notice = JSON.parse(event.data) as {
                type?: string;
                rule_name?: string;
                directory_required?: boolean;
                controller?: string;
              };
              if (notice.type === "share_control_required" || notice.type === "share_controller") {
                const blocked = notice.type === "share_control_required" || !!notice.controller;
                setControlBlocked(blocked);
                terminal.options.disableStdin = blocked;
                if (terminal.textarea) terminal.textarea.readOnly = blocked;
              }
              if (notice.type === "command_blocked") {
                const message = notice.rule_name
                  ? translations.current("terminal.commandBlockedRule", { rule: notice.rule_name })
                  : translations.current("terminal.commandBlocked");
                terminal.write(`\r\n${message}\r\n`);
                if (notice.directory_required)
                  terminal.write(
                    `\r\n${translations.current("directoryPolicy.terminalNotice")}\r\n`,
                  );
              } else if (notice.type === "command_review_pending") {
                const message = notice.rule_name
                  ? translations.current("terminal.commandReviewPendingRule", {
                      rule: notice.rule_name,
                    })
                  : translations.current("terminal.commandReviewPending");
                terminal.write(`\r\n${message}\r\n`);
              } else if (notice.type === "command_review_approved") {
                terminal.write(`\r\n${translations.current("terminal.commandReviewApproved")}\r\n`);
              } else if (notice.type === "command_review_denied") {
                terminal.write(`\r\n${translations.current("terminal.commandReviewDenied")}\r\n`);
              } else if (notice.type === "command_review_timed_out") {
                terminal.write(`\r\n${translations.current("terminal.commandReviewTimedOut")}\r\n`);
              }
            } catch {
              // Ignore unsupported text frames; terminal data uses binary frames.
            }
          }
        };
        socket.onerror = () => {
          if (active) setState("failed");
        };
        socket.onclose = () => {
          if (active)
            setState((current) =>
              current === "connected" ? "closed" : current === "connecting" ? "failed" : current,
            );
        };
      } catch {
        if (active && !controller.signal.aborted) setState("failed");
      }
    }

    function closeSession(id: string) {
      const headers = new Headers();
      if (accessToken) headers.set("Authorization", `Bearer ${accessToken}`);
      return fetch(`/api/v1/sessions/${encodeURIComponent(id)}`, {
        method: "DELETE",
        headers,
      }).catch(() => undefined);
    }

    return () => {
      active = false;
      window.clearTimeout(startTimer);
      controller.abort();
      observer.disconnect();
      cancelAnimationFrame(resizeFrame);
      inputSubscription.dispose();
      socket?.close(1000, "terminal closed");
      terminal.dispose();
      if (terminalRef.current === terminal) {
        terminalRef.current = null;
        fitRef.current = null;
      }
      if (sessionId) void closeSession(sessionId);
    };
  }, [accessToken, assetId, kubernetesSelection, terminalPrefix, protocol, attempt]);

  useEffect(() => {
    if (terminalRef.current) terminalRef.current.options.fontSize = fontSize;
    const frame = requestAnimationFrame(() => fitRef.current?.());
    return () => cancelAnimationFrame(frame);
  }, [fontSize, attempt]);

  useEffect(() => {
    function handleKeyDown(event: KeyboardEvent) {
      // Escape belongs to the remote shell while its terminal has focus (vim,
      // less, shell completion). Closing the dialog must not steal that input.
      if (event.key === "Escape" && !hostRef.current?.contains(event.target as Node)) onClose();
    }
    window.addEventListener("keydown", handleKeyDown);
    return () => window.removeEventListener("keydown", handleKeyDown);
  }, [onClose]);

  const statusLabel = {
    connecting: t("terminal.connecting"),
    review: t(`${terminalPrefix}.loginReviewStatus`),
    connected: t("terminal.connected"),
    failed: t("terminal.failed"),
    closed: t("terminal.closed"),
  }[state];

  return (
    <div
      className="ssh-terminal-backdrop"
      role="presentation"
      onMouseDown={(event) => {
        if (event.target === event.currentTarget) onClose();
      }}
    >
      <section
        className={`ssh-terminal-dialog${expanded ? " is-expanded" : ""}`}
        role="dialog"
        aria-modal="true"
        aria-labelledby="ssh-terminal-title"
      >
        <header className="ssh-terminal-header">
          <BrandMark compact />
          <div>
            <h2 id="ssh-terminal-title">{assetName}</h2>
            <span className={`ssh-terminal-status ${state}`}>
              <i />
              {statusLabel}
            </span>
          </div>
          <div className="terminal-tools">
            <button
              type="button"
              className="icon-button"
              aria-label={t("ui.terminal.smaller")}
              disabled={fontSize <= 11}
              onClick={() => setFontSize((size) => Math.max(11, size - 1))}
            >
              A−
            </button>
            <output aria-label={t("ui.terminal.fontSize")}>{fontSize}</output>
            <button
              type="button"
              className="icon-button"
              aria-label={t("ui.terminal.larger")}
              disabled={fontSize >= 24}
              onClick={() => setFontSize((size) => Math.min(24, size + 1))}
            >
              A+
            </button>
            <button
              type="button"
              className="icon-button"
              aria-label={t(expanded ? "ui.terminal.restore" : "ui.terminal.expand")}
              aria-pressed={expanded}
              onClick={() => setExpanded((value) => !value)}
            >
              <Icon name={expanded ? "collapse" : "expand"} />
            </button>
          </div>
          <button type="button" className="lang-switch" onClick={() => void toggleLang()}>
            {t("sharing.language")}
          </button>
          {state === "connected" && (
            <button
              type="button"
              className="button-secondary"
              onClick={() => setShowSharing((v) => !v)}
            >
              {t("sharing.manage")}
            </button>
          )}
          <button ref={closeButtonRef} type="button" className="button-secondary" onClick={onClose}>
            {t("terminal.close")}
          </button>
        </header>
        {controlBlocked && (
          <p className="session-monitor-notice">
            {t("sharing.waitControl")}{" "}
            <button
              type="button"
              className="button-secondary"
              onClick={() => {
                setShowSharing(true);
              }}
            >
              {t("sharing.reclaim")}
            </button>
          </p>
        )}
        {showSharing && currentID && (
          <Suspense fallback={null}>
            <SessionSharePanel
              sessionID={currentID}
              accessToken={accessToken}
              onClose={() => setShowSharing(false)}
            />
          </Suspense>
        )}
        {state === "failed" && (
          <p className="ssh-terminal-error" role="alert">
            {t(`${terminalPrefix}.connectFailed`)}
            <button
              type="button"
              className="button-secondary"
              onClick={() => {
                setState("connecting");
                setAttempt((value) => value + 1);
              }}
            >
              {t("ui.retry")}
            </button>
          </p>
        )}
        <div className="session-monitor-surface">
          <div className="ssh-terminal-host" ref={hostRef} />
          {watermark && (
            <div className="session-monitor-watermark" aria-label={t("sessionSecurity.watermark")}>
              {watermark}
            </div>
          )}
        </div>
        <footer className="terminal-footer">
          <span>
            <Icon name="shield" size={13} />
            {t("ui.terminal.audited")}
          </span>
          <span>{t("ui.terminal.escapeHint")}</span>
        </footer>
      </section>
    </div>
  );
}
