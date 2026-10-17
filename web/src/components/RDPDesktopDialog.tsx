import { useEffect, useRef, useState, type KeyboardEvent, type PointerEvent } from "react";
import { useTranslation } from "react-i18next";
import { createDesktopFrameRenderer } from "./desktopFrameRenderer";
import "./rdp.css";

type Props = { assetId: string; assetName: string; accessToken: string; onClose: () => void };
type State = "connecting" | "connected" | "failed" | "closed" | "review";
const keys: Record<string, number> = {
  Escape: 1,
  Digit1: 2,
  Digit2: 3,
  Digit3: 4,
  Digit4: 5,
  Digit5: 6,
  Digit6: 7,
  Digit7: 8,
  Digit8: 9,
  Digit9: 10,
  Digit0: 11,
  Minus: 12,
  Equal: 13,
  Backspace: 14,
  Tab: 15,
  KeyQ: 16,
  KeyW: 17,
  KeyE: 18,
  KeyR: 19,
  KeyT: 20,
  KeyY: 21,
  KeyU: 22,
  KeyI: 23,
  KeyO: 24,
  KeyP: 25,
  BracketLeft: 26,
  BracketRight: 27,
  Enter: 28,
  ControlLeft: 29,
  ControlRight: 29,
  KeyA: 30,
  KeyS: 31,
  KeyD: 32,
  KeyF: 33,
  KeyG: 34,
  KeyH: 35,
  KeyJ: 36,
  KeyK: 37,
  KeyL: 38,
  Semicolon: 39,
  Quote: 40,
  Backquote: 41,
  ShiftLeft: 42,
  Backslash: 43,
  KeyZ: 44,
  KeyX: 45,
  KeyC: 46,
  KeyV: 47,
  KeyB: 48,
  KeyN: 49,
  KeyM: 50,
  Comma: 51,
  Period: 52,
  Slash: 53,
  ShiftRight: 54,
  AltLeft: 56,
  AltRight: 56,
  Space: 57,
  CapsLock: 58,
  F1: 59,
  F2: 60,
  F3: 61,
  F4: 62,
  F5: 63,
  F6: 64,
  F7: 65,
  F8: 66,
  F9: 67,
  F10: 68,
  F11: 87,
  F12: 88,
  Home: 71,
  ArrowUp: 72,
  PageUp: 73,
  ArrowLeft: 75,
  ArrowRight: 77,
  End: 79,
  ArrowDown: 80,
  PageDown: 81,
  Insert: 82,
  Delete: 83,
};
const extended = (code: string) =>
  /^(Arrow|Home|End|Page|Insert|Delete)/.test(code) ||
  code === "ControlRight" ||
  code === "AltRight";

export default function RDPDesktopDialog({ assetId, assetName, accessToken, onClose }: Props) {
  const { t } = useTranslation();
  const canvas = useRef<HTMLCanvasElement>(null);
  const socket = useRef<WebSocket | null>(null);
  const pressed = useRef(new Set<string>());
  const lastMove = useRef(0);
  const [state, setState] = useState<State>("connecting");
  const [readOnly, setReadOnly] = useState(true);
  const [clipboardEnabled, setClipboardEnabled] = useState(false);
  const [clipboard, setClipboard] = useState("");
  const [clipboardFailed, setClipboardFailed] = useState(false);
  const [text, setText] = useState("");
  const [textFailed, setTextFailed] = useState(false);
  const [textPending, setTextPending] = useState(false);
  const send = (input: object) => {
    if (socket.current?.readyState === WebSocket.OPEN) socket.current.send(JSON.stringify(input));
  };
  useEffect(() => {
    let active = true,
      id = "",
      ws: WebSocket | null = null;
    const renderer = createDesktopFrameRenderer(
      () => canvas.current,
      () => {
        if (active) setState("connected");
      },
      () => {
        if (active) {
          setState("failed");
          ws?.close();
        }
      },
    );
    const controller = new AbortController();
    const headers = new Headers();
    if (accessToken) headers.set("Authorization", `Bearer ${accessToken}`);
    const stop = (value: string) =>
      fetch(`/api/v1/desktop-sessions/${value}`, { method: "DELETE", headers }).catch(
        () => undefined,
      );
    const timer = window.setTimeout(async () => {
      try {
        let response: Response;
        for (;;) {
          response = await fetch(`/api/v1/assets/${assetId}/rdp/sessions`, {
            method: "POST",
            headers,
            signal: controller.signal,
          });
          if (response.status !== 202) break;
          const review = (await response.json()) as { review_id: string };
          if (!review.review_id) throw new Error("Invalid desktop review");
          if (active) setState("review");
          let approved = false;
          while (active) {
            await new Promise((resolve) => setTimeout(resolve, 1000));
            const check = await fetch(`/api/v1/access-reviews/${review.review_id}`, {
              headers,
              signal: controller.signal,
            });
            if (!check.ok) throw new Error("Desktop review failed");
            const value = (await check.json()) as { state: string };
            if (value.state === "approved") {
              approved = true;
              break;
            }
            if (value.state !== "pending") throw new Error("Desktop review ended");
          }
          if (!approved) return;
          if (active) setState("connecting");
        }
        if (!response.ok) throw new Error("RDP connection failed");
        const created = (await response.json()) as {
          session_id: string;
          websocket_url: string;
          ticket: string;
        };
        id = created.session_id;
        if (!active) {
          void stop(id);
          return;
        }
        const url = new URL(created.websocket_url, window.location.href);
        if (url.origin !== window.location.origin || !url.pathname.startsWith("/ws/desktop/"))
          throw new Error("Invalid desktop URL");
        url.protocol = window.location.protocol === "https:" ? "wss:" : "ws:";
        ws = new WebSocket(url, ["jms233-desktop-v1", `jms233-desktop-ticket.${created.ticket}`]);
        socket.current = ws;
        ws.binaryType = "arraybuffer";
        ws.onmessage = (event) => {
          if (!active) return;
          if (typeof event.data === "string") {
            try {
              const value = JSON.parse(event.data);
              if (value.type === "ready") {
                setReadOnly(Boolean(value.read_only));
                setClipboardEnabled(Boolean(value.clipboard));
              }
              if (value.type === "clipboard" && typeof value.text === "string") {
                setClipboard(value.text);
                setClipboardFailed(false);
              }
              if (value.type === "clipboard_error") setClipboardFailed(true);
              if (value.type === "text_error") {
                setTextFailed(true);
                setTextPending(false);
              }
              if (value.type === "text_accepted") {
                setText("");
                setTextFailed(false);
                setTextPending(false);
              }
            } catch {
              setState("failed");
              ws?.close();
            }
            return;
          }
          renderer.push(event.data as ArrayBuffer);
        };
        ws.onclose = () => {
          if (active) {
            setState((old) => (old === "failed" ? old : "closed"));
            setTextPending(false);
          }
        };
        ws.onerror = () => {
          if (active) setState("failed");
        };
      } catch {
        if (active) setState("failed");
      }
    }, 0);
    return () => {
      active = false;
      renderer.dispose();
      clearTimeout(timer);
      controller.abort();
      ws?.close();
      socket.current = null;
      if (id) void stop(id);
    };
  }, [assetId, accessToken]);
  const key = (event: KeyboardEvent<HTMLCanvasElement>, down: boolean) => {
    if (readOnly || state !== "connected" || event.nativeEvent.isComposing) return;
    const code = keys[event.code];
    if (!code) return;
    event.preventDefault();
    if (down) pressed.current.add(event.code);
    else pressed.current.delete(event.code);
    send({ type: "key", code, extended: extended(event.code), down });
  };
  const release = () => {
    for (const code of pressed.current)
      send({ type: "key", code: keys[code], extended: extended(code), down: false });
    pressed.current.clear();
  };
  const pointer = (event: PointerEvent<HTMLCanvasElement>, action: string, down?: boolean) => {
    if (readOnly || state !== "connected") return;
    if (action === "move" && performance.now() - lastMove.current < 25) return;
    lastMove.current = performance.now();
    const host = event.currentTarget,
      rect = host.getBoundingClientRect();
    const x = Math.max(
      0,
      Math.min(host.width - 1, Math.floor(((event.clientX - rect.left) * host.width) / rect.width)),
    );
    const y = Math.max(
      0,
      Math.min(
        host.height - 1,
        Math.floor(((event.clientY - rect.top) * host.height) / rect.height),
      ),
    );
    event.preventDefault();
    if (down) {
      host.focus();
      host.setPointerCapture(event.pointerId);
    }
    send({
      type: "pointer",
      action,
      x,
      y,
      button: ["left", "middle", "right"][event.button],
      down,
    });
  };
  return (
    <div className="ssh-terminal-backdrop" role="presentation">
      <section
        className="ssh-terminal-dialog rdp-dialog"
        role="dialog"
        aria-modal="true"
        aria-labelledby="rdp-title"
      >
        <header className="ssh-terminal-header">
          <div>
            <h2 id="rdp-title">
              {assetName} · {t("rdp.name")}
            </h2>
            <span role="status">
              {t(state === "review" ? "rdp.loginReviewStatus" : `terminal.${state}`)}
            </span>
          </div>
          <button className="button-secondary" onClick={onClose}>
            {t("terminal.close")}
          </button>
        </header>
        <p className="rdp-hint">{t(readOnly ? "rdp.readOnlyHint" : "rdp.inputHint")}</p>
        {state === "failed" && (
          <p role="alert" className="asset-error">
            {t("rdp.failed")}
          </p>
        )}
        <div className="rdp-viewport">
          <canvas
            ref={canvas}
            aria-label={t("rdp.screen")}
            tabIndex={0}
            onKeyDown={(e) => key(e, true)}
            onKeyUp={(e) => key(e, false)}
            onBlur={release}
            onPointerDown={(e) => pointer(e, "button", true)}
            onPointerUp={(e) => pointer(e, "button", false)}
            onPointerMove={(e) => pointer(e, "move")}
            onContextMenu={(e) => e.preventDefault()}
            onWheel={(e) => {
              if (readOnly || state !== "connected") return;
              const host = e.currentTarget,
                rect = host.getBoundingClientRect();
              send({
                type: "pointer",
                action: "wheel",
                x: Math.max(
                  0,
                  Math.min(
                    host.width - 1,
                    Math.floor(((e.clientX - rect.left) * host.width) / rect.width),
                  ),
                ),
                y: Math.max(
                  0,
                  Math.min(
                    host.height - 1,
                    Math.floor(((e.clientY - rect.top) * host.height) / rect.height),
                  ),
                ),
                delta: e.deltaY > 0 ? -120 : 120,
              });
            }}
          />
        </div>
        {!readOnly && (
          <form
            className="rdp-text"
            onSubmit={(e) => {
              e.preventDefault();
              send({ type: "text", text });
              setTextFailed(false);
              setTextPending(true);
            }}
          >
            <label>
              {t("rdp.text")}
              <input
                aria-label={t("rdp.text")}
                disabled={textPending}
                maxLength={2048}
                value={text}
                onChange={(e) => setText(e.target.value)}
              />
            </label>
            <button
              className="button-secondary"
              disabled={state !== "connected" || !text || textPending}
            >
              {t("rdp.sendText")}
            </button>
          </form>
        )}
        {textFailed && (
          <p role="status" className="rdp-hint">
            {t("rdp.textUnavailable")}
          </p>
        )}
        {clipboardEnabled && (
          <details className="rdp-clipboard">
            <summary>{t("rdp.clipboard")}</summary>
            <p>{t("rdp.clipboardHint")}</p>
            <label>
              {t("rdp.clipboardText")}
              <textarea
                aria-label={t("rdp.clipboardText")}
                maxLength={32768}
                value={clipboard}
                onChange={(e) => setClipboard(e.target.value)}
              />
            </label>
            {clipboardFailed && <p role="status">{t("rdp.clipboardUnavailable")}</p>}
            <button
              className="button-secondary"
              disabled={state !== "connected"}
              onClick={() => {
                setClipboardFailed(false);
                send({ type: "clipboard_read" });
              }}
            >
              {t("rdp.readClipboard")}
            </button>
            {!readOnly && (
              <button
                className="button-secondary"
                disabled={state !== "connected"}
                onClick={() => {
                  setClipboardFailed(false);
                  send({ type: "clipboard_write", text: clipboard });
                }}
              >
                {t("rdp.writeClipboard")}
              </button>
            )}
          </details>
        )}
      </section>
    </div>
  );
}
