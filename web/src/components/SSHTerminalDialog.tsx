import { useEffect, useRef, useState } from "react";
import { Terminal } from "@xterm/xterm";
import { useTranslation } from "react-i18next";
import "@xterm/xterm/css/xterm.css";

type Props = {
  protocol?: "ssh" | "telnet";
  kubernetesSelection?: { namespace: string; pod: string; container: string };
  assetId: string;
  assetName: string;
  accessToken: string;
  onClose: () => void;
};

type CreatedSession = {
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
  const terminalPrefix = kubernetesSelection
    ? "kubernetes"
    : protocol === "telnet"
      ? "telnet"
      : "terminal";
  const hostRef = useRef<HTMLDivElement>(null);
  const [state, setState] = useState<ConnectionState>("connecting");

  useEffect(() => {
    const host = hostRef.current;
    if (!host) return;

    let active = true;
    let sessionId = "";
    let socket: WebSocket | null = null;
    let previousSize = "";
    const controller = new AbortController();
    const fontSize = 13;
    const terminal = new Terminal({
      cursorBlink: true,
      fontFamily: "Cascadia Code, Consolas, monospace",
      fontSize,
      theme: {
        background: "#080d14",
        foreground: "#dbe7f5",
        cursor: "#5ee1a0",
        selectionBackground: "rgba(94, 225, 160, 0.28)",
      },
    });
    terminal.open(host);
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
      const cols = Math.max(24, Math.min(500, Math.floor(contentWidth / (fontSize * 0.6))));
      const rows = Math.max(8, Math.min(500, Math.floor(contentHeight / (fontSize + 2))));
      const size = `${cols}x${rows}`;
      if (size === previousSize) return;
      previousSize = size;
      terminal.resize(cols, rows);
      if (socket?.readyState === WebSocket.OPEN) {
        socket.send(JSON.stringify({ type: "resize", cols, rows }));
      }
    };
    const observer = new ResizeObserver(sendResize);
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
          terminal.write(`\r\n${t(`${terminalPrefix}.loginReviewPending`)}\r\n`);
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
              terminal.write(`\r\n${t(`${terminalPrefix}.loginReviewApproved`)}\r\n`);
              setState("connecting");
              await startSession();
              return;
            }
            terminal.write(
              `\r\n${review.state === "denied" ? t(`${terminalPrefix}.loginReviewDenied`) : t(`${terminalPrefix}.loginReviewExpired`)}\r\n`,
            );
            setState("failed");
            return;
          }
          return;
        }
        if (!response.ok) throw new Error("session creation failed");
        const session = (await response.json()) as CreatedSession;
        if (!session.session_id || !session.ticket || !session.websocket_url.startsWith("/ws/")) {
          throw new Error("incomplete session response");
        }
        sessionId = session.session_id;
        if (!active) {
          void closeSession(sessionId);
          return;
        }
        const socketProtocol = window.location.protocol === "https:" ? "wss:" : "ws:";
        const endpoint = `${socketProtocol}//${window.location.host}${session.websocket_url}`;
        socket = new WebSocket(endpoint, ["jms233-terminal-v1", `jms233-ticket.${session.ticket}`]);
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
              const notice = JSON.parse(event.data) as { type?: string; rule_name?: string };
              if (notice.type === "command_blocked") {
                const message = notice.rule_name
                  ? t("terminal.commandBlockedRule", { rule: notice.rule_name })
                  : t("terminal.commandBlocked");
                terminal.write(`\r\n${message}\r\n`);
              } else if (notice.type === "command_review_pending") {
                const message = notice.rule_name
                  ? t("terminal.commandReviewPendingRule", { rule: notice.rule_name })
                  : t("terminal.commandReviewPending");
                terminal.write(`\r\n${message}\r\n`);
              } else if (notice.type === "command_review_approved") {
                terminal.write(`\r\n${t("terminal.commandReviewApproved")}\r\n`);
              } else if (notice.type === "command_review_denied") {
                terminal.write(`\r\n${t("terminal.commandReviewDenied")}\r\n`);
              } else if (notice.type === "command_review_timed_out") {
                terminal.write(`\r\n${t("terminal.commandReviewTimedOut")}\r\n`);
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
      inputSubscription.dispose();
      socket?.close(1000, "terminal closed");
      terminal.dispose();
      if (sessionId) void closeSession(sessionId);
    };
  }, [accessToken, assetId, t, kubernetesSelection, terminalPrefix, protocol]);

  useEffect(() => {
    function handleKeyDown(event: KeyboardEvent) {
      if (event.key === "Escape") onClose();
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
        className="ssh-terminal-dialog"
        role="dialog"
        aria-modal="true"
        aria-labelledby="ssh-terminal-title"
      >
        <header className="ssh-terminal-header">
          <div>
            <h2 id="ssh-terminal-title">{assetName}</h2>
            <span className={`ssh-terminal-status ${state}`}>
              <i />
              {statusLabel}
            </span>
          </div>
          <button type="button" className="button-secondary" onClick={onClose}>
            {t("terminal.close")}
          </button>
        </header>
        {state === "failed" && (
          <p className="ssh-terminal-error" role="alert">
            {t(`${terminalPrefix}.connectFailed`)}
          </p>
        )}
        <div className="ssh-terminal-host" ref={hostRef} />
      </section>
    </div>
  );
}
