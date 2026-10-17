import { useEffect, useRef, useState, type FormEvent } from "react";
import { Link, useParams } from "react-router-dom";
import { useTranslation } from "react-i18next";
import { Terminal } from "@xterm/xterm";
import "@xterm/xterm/css/xterm.css";
import { useAuth } from "../auth/AuthContext";
import { toggleLang } from "../i18n";

type Connection = {
  session_id: string;
  asset_name: string;
  ticket: string;
  websocket_url: string;
  watermark?: string;
  member: { id: string; mode: string; actor: { id: string; name: string } };
};
function SharedTerminal({ connection }: { connection: Connection }) {
  const { t } = useTranslation();
  const host = useRef<HTMLDivElement>(null),
    socket = useRef<WebSocket | null>(null);
  const [state, setState] = useState("connecting"),
    [control, setControl] = useState(false),
    [reviewBusy, setReviewBusy] = useState(false),
    [notice, setNotice] = useState("");
  useEffect(() => {
    if (!host.current) return;
    let active = true,
      queued = 0;
    const terminal = new Terminal({
      disableStdin: true,
      cursorBlink: true,
      fontSize: 13,
      fontFamily: "Cascadia Code, Consolas, monospace",
      scrollback: 5000,
      theme: { background: "#080d14", foreground: "#dbe7f5" },
    });
    terminal.open(host.current);
    if (terminal.textarea) terminal.textarea.readOnly = true;
    const encoder = new TextEncoder();
    const input = terminal.onData((data) => {
      if (socket.current?.readyState === WebSocket.OPEN) socket.current.send(encoder.encode(data));
    });
    const start = window.setTimeout(() => {
      try {
        const url = new URL(connection.websocket_url, window.location.href);
        if (
          url.origin !== window.location.origin ||
          !url.pathname.startsWith("/ws/") ||
          !connection.ticket
        )
          throw Error("invalid shared terminal");
        url.protocol = url.protocol === "https:" ? "wss:" : "ws:";
        const conn = new WebSocket(url, ["jms233-share-v1", `jms233-ticket.${connection.ticket}`]);
        socket.current = conn;
        conn.binaryType = "arraybuffer";
        conn.onopen = () => {
          if (active) setState("connected");
        };
        conn.onerror = () => {
          if (active) setState("failed");
        };
        conn.onclose = () => {
          if (active) {
            setState((value) => (value === "failed" ? value : "closed"));
            setControl(false);
            terminal.options.disableStdin = true;
          }
        };
        conn.onmessage = (event: MessageEvent<ArrayBuffer | string>) => {
          if (!active) return;
          if (event.data instanceof ArrayBuffer) {
            const bytes = new Uint8Array(event.data);
            queued += bytes.byteLength;
            if (queued > 512 * 1024) {
              setState("failed");
              conn.close();
              return;
            }
            terminal.write(bytes, () => {
              queued -= bytes.byteLength;
            });
            return;
          }
          try {
            const msg = JSON.parse(event.data) as {
              type: string;
              cols: number;
              rows: number;
              controller?: string;
              review_pending?: boolean;
            };
            if (msg.type === "share_state") {
              setReviewBusy(!!msg.review_pending);
              if (
                Number.isInteger(msg.cols) &&
                Number.isInteger(msg.rows) &&
                msg.cols >= 2 &&
                msg.cols <= 500 &&
                msg.rows >= 2 &&
                msg.rows <= 500 &&
                (terminal.cols !== msg.cols || terminal.rows !== msg.rows)
              )
                terminal.resize(msg.cols, msg.rows);
              const own = msg.controller === connection.member.id;
              setControl(own);
              terminal.options.disableStdin = !own;
              if (terminal.textarea) terminal.textarea.readOnly = !own;
            } else if (msg.type === "share_control_required") {
              setControl(false);
              terminal.options.disableStdin = true;
              if (terminal.textarea) terminal.textarea.readOnly = true;
            } else if (msg.type === "share_control_busy") {
              setReviewBusy(true);
            } else if (
              [
                "command_blocked",
                "command_review_pending",
                "command_review_approved",
                "command_review_denied",
                "command_review_timed_out",
              ].includes(msg.type)
            )
              setNotice(msg.type);
          } catch {
            setState("failed");
            conn.close();
          }
        };
      } catch {
        setState("failed");
      }
    }, 0);
    return () => {
      active = false;
      clearTimeout(start);
      socket.current?.close();
      socket.current = null;
      input.dispose();
      terminal.dispose();
    };
  }, [connection]);
  const notices: Record<string, string> = {
    command_blocked: "terminal.commandBlocked",
    command_review_pending: "terminal.commandReviewPending",
    command_review_approved: "terminal.commandReviewApproved",
    command_review_denied: "terminal.commandReviewDenied",
    command_review_timed_out: "terminal.commandReviewTimedOut",
  };
  return (
    <section className="shared-terminal">
      <div className="session-share-row">
        <span role="status">
          {t(`terminal.${state}`)} ·{" "}
          {t(
            connection.member.mode === "read_only"
              ? "sharing.readOnly"
              : control
                ? "sharing.youControl"
                : "sharing.waitControl",
          )}
        </span>
        {connection.member.mode === "read_write" && (
          <button
            className="button-secondary"
            type="button"
            disabled={state !== "connected" || control || reviewBusy}
            onClick={() => socket.current?.send(JSON.stringify({ type: "take_control" }))}
          >
            {t("sharing.takeControl")}
          </button>
        )}
      </div>
      {notice && <p role="status">{t(notices[notice])}</p>}
      {reviewBusy && <p>{t("sharing.reviewBusy")}</p>}
      {state === "failed" && <p role="alert">{t("sharing.error")}</p>}
      <div className="session-monitor-surface">
        <div className="ssh-terminal-host" ref={host} aria-label={t("sharing.output")} />
        <div className="session-monitor-watermark">
          {connection.watermark || connection.session_id} · {connection.member.actor.name}
        </div>
      </div>
    </section>
  );
}
export default function SessionSharePage() {
  const { shareID } = useParams();
  const { accessToken } = useAuth();
  const { t } = useTranslation();
  const [code, setCode] = useState(""),
    [busy, setBusy] = useState(false),
    [error, setError] = useState(false),
    [connection, setConnection] = useState<Connection | null>(null);
  async function join(e: FormEvent) {
    e.preventDefault();
    setError(false);
    setBusy(true);
    try {
      if (!shareID || !/^[A-Za-z0-9_-]{16,128}$/.test(shareID)) throw Error("invalid share ID");
      const response = await fetch(`/api/v1/session-shares/${encodeURIComponent(shareID)}/join`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          ...(accessToken ? { Authorization: `Bearer ${accessToken}` } : {}),
        },
        body: JSON.stringify({ code }),
      });
      if (!response.ok) throw Error("share unavailable");
      setConnection((await response.json()) as Connection);
      setCode("");
    } catch {
      setError(true);
    } finally {
      setBusy(false);
    }
  }
  return (
    <main className="shared-session-page">
      <header className="session-share-row">
        <h1>{t("sharing.title")}</h1>
        <nav>
          <button type="button" className="lang-toggle" onClick={() => void toggleLang()}>
            {t("sharing.language")}
          </button>
          <Link to="/console">{t("nav.console")}</Link>
        </nav>
      </header>
      <p>{t("sharing.hint")}</p>
      {!connection && (
        <form className="settings-card settings-form" onSubmit={(e) => void join(e)}>
          <label>
            {t("sharing.code")}
            <input
              required
              type="password"
              value={code}
              maxLength={128}
              autoComplete="off"
              onChange={(e) => setCode(e.target.value)}
            />
          </label>
          <button className="button-primary" disabled={busy}>
            {t("sharing.join")}
          </button>
        </form>
      )}
      {error && (
        <p role="alert" className="asset-error">
          {t("sharing.error")}
        </p>
      )}
      {connection && (
        <>
          <h2>{connection.asset_name}</h2>
          <SharedTerminal connection={connection} />
        </>
      )}
    </main>
  );
}
