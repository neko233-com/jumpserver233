import { useEffect, useRef, useState } from "react";
import { Terminal } from "@xterm/xterm";
import { useTranslation } from "react-i18next";
import "@xterm/xterm/css/xterm.css";

type SessionRecord = {
  session_id: string;
  asset_name: string;
  username: string;
  started_at: string;
};

type Props = {
  session: SessionRecord;
  accessToken: string;
  onClose: () => void;
};

type ReplayEvent = { at: number; data: string };
type ReplayState = "loading" | "ready" | "failed";
const maxCompressedBytes = 64 * 1024 * 1024;
const maxExpandedBytes = 128 * 1024 * 1024;
const maxLines = 1_000_000;

async function readReplay(response: Response, signal: AbortSignal): Promise<ReplayEvent[]> {
  const compressed = await response.arrayBuffer();
  if (compressed.byteLength > maxCompressedBytes) throw new Error("recording too large");
  if (typeof DecompressionStream === "undefined")
    throw new Error("gzip decompression is unavailable");

  const reader = new Blob([compressed])
    .stream()
    .pipeThrough(new DecompressionStream("gzip"))
    .getReader();
  const decoder = new TextDecoder();
  const events: ReplayEvent[] = [];
  let pending = "";
  let expandedBytes = 0;
  let lineCount = 0;
  let headerSeen = false;

  function consumeLine(line: string) {
    if (!line) return;
    lineCount++;
    if (lineCount > maxLines) throw new Error("recording has too many events");
    const value: unknown = JSON.parse(line);
    if (!headerSeen) {
      if (!value || typeof value !== "object" || !("version" in value) || value.version !== 2)
        throw new Error("unsupported recording");
      headerSeen = true;
      return;
    }
    if (
      !Array.isArray(value) ||
      value.length !== 3 ||
      typeof value[0] !== "number" ||
      typeof value[1] !== "string" ||
      typeof value[2] !== "string"
    ) {
      throw new Error("invalid recording event");
    }
    // Input events can contain passwords and commands. Playback renders output only.
    if (value[1] === "o") events.push({ at: value[0], data: value[2] });
  }

  try {
    while (true) {
      if (signal.aborted) throw new DOMException("Aborted", "AbortError");
      const { done, value } = await reader.read();
      if (done) break;
      expandedBytes += value.byteLength;
      if (expandedBytes > maxExpandedBytes) throw new Error("recording too large");
      pending += decoder.decode(value, { stream: true });
      let newline = pending.indexOf("\n");
      while (newline >= 0) {
        consumeLine(pending.slice(0, newline));
        pending = pending.slice(newline + 1);
        newline = pending.indexOf("\n");
      }
    }
    pending += decoder.decode();
    consumeLine(pending);
  } finally {
    await reader.cancel().catch(() => undefined);
  }
  if (!headerSeen) throw new Error("recording header is missing");
  return events;
}

function formatDuration(seconds: number) {
  if (!Number.isFinite(seconds) || seconds < 0) return "00:00";
  const whole = Math.floor(seconds);
  return `${String(Math.floor(whole / 60)).padStart(2, "0")}:${String(whole % 60).padStart(2, "0")}`;
}

export default function SessionReplayDialog({ session, accessToken, onClose }: Props) {
  const { t, i18n } = useTranslation();
  const hostRef = useRef<HTMLDivElement>(null);
  const terminalRef = useRef<Terminal | null>(null);
  const [terminalReady, setTerminalReady] = useState(false);
  const [state, setState] = useState<ReplayState>("loading");
  const [events, setEvents] = useState<ReplayEvent[]>([]);
  const [cursor, setCursor] = useState(0);
  const [playing, setPlaying] = useState(false);
  const [speed, setSpeed] = useState(1);

  useEffect(() => {
    const host = hostRef.current;
    if (!host) return;
    const terminal = new Terminal({
      cursorBlink: false,
      fontFamily: "Cascadia Code, Consolas, monospace",
      fontSize: 13,
      scrollback: 5000,
      theme: {
        background: "#080d14",
        foreground: "#dbe7f5",
        cursor: "#5ee1a0",
        selectionBackground: "rgba(94, 225, 160, 0.28)",
      },
    });
    terminal.open(host);
    terminalRef.current = terminal;
    setTerminalReady(true);
    return () => {
      terminalRef.current = null;
      terminal.dispose();
    };
  }, []);

  useEffect(() => {
    const controller = new AbortController();
    async function load() {
      try {
        const headers = new Headers();
        if (accessToken) headers.set("Authorization", `Bearer ${accessToken}`);
        const response = await fetch(
          `/api/v1/sessions/${encodeURIComponent(session.session_id)}/replay`,
          {
            headers,
            signal: controller.signal,
          },
        );
        if (!response.ok) throw new Error("could not load recording");
        const result = await readReplay(response, controller.signal);
        if (controller.signal.aborted) return;
        setEvents(result);
        setState("ready");
      } catch {
        if (!controller.signal.aborted) setState("failed");
      }
    }
    void load();
    return () => controller.abort();
  }, [accessToken, session.session_id]);

  useEffect(() => {
    if (!playing || state !== "ready" || !terminalReady) return;
    if (cursor >= events.length) {
      // eslint-disable-next-line react/set-state-in-effect
      setPlaying(false);
      return;
    }
    const event = events[cursor];
    const previousAt = cursor === 0 ? event.at : events[cursor - 1].at;
    const delay = Math.min(1000, Math.max(0, ((event.at - previousAt) * 1000) / speed));
    const timer = window.setTimeout(() => {
      terminalRef.current?.write(event.data, () => setCursor(cursor + 1));
    }, delay);
    return () => window.clearTimeout(timer);
  }, [cursor, events, playing, speed, state, terminalReady]);

  useEffect(() => {
    function handleKeyDown(event: KeyboardEvent) {
      if (event.key === "Escape") onClose();
    }
    window.addEventListener("keydown", handleKeyDown);
    return () => window.removeEventListener("keydown", handleKeyDown);
  }, [onClose]);

  function restart() {
    terminalRef.current?.reset();
    setCursor(0);
    setPlaying(events.length > 0);
  }

  const duration = events.length > 0 ? events[events.length - 1].at : 0;
  const elapsed = cursor > 0 ? events[cursor - 1].at : 0;
  const statusLabel =
    state === "loading"
      ? t("audit.loadingReplay")
      : state === "failed"
        ? t("audit.replayFailed")
        : playing
          ? t("audit.playing")
          : t("audit.paused");

  return (
    <div
      className="ssh-terminal-backdrop replay-backdrop"
      role="presentation"
      onMouseDown={(event) => {
        if (event.target === event.currentTarget) onClose();
      }}
    >
      <section
        className="ssh-terminal-dialog replay-dialog"
        role="dialog"
        aria-modal="true"
        aria-labelledby="session-replay-title"
      >
        <header className="ssh-terminal-header">
          <div>
            <h2 id="session-replay-title">{session.asset_name || session.session_id}</h2>
            <span className="ssh-terminal-status">
              {t("audit.replayMeta", {
                account: session.username || "—",
                started: new Date(session.started_at).toLocaleString(i18n.language),
              })}
            </span>
          </div>
          <button type="button" className="button-secondary" onClick={onClose}>
            {t("audit.closeReplay")}
          </button>
        </header>
        {state === "failed" && (
          <p className="ssh-terminal-error" role="alert">
            {t("audit.replayFailed")}
          </p>
        )}
        <div className="ssh-terminal-host replay-terminal-host" ref={hostRef}>
          {state === "loading" && (
            <div className="replay-terminal-message">{t("audit.loadingReplay")}</div>
          )}
          {state === "failed" && (
            <div className="replay-terminal-message">{t("audit.replayFailed")}</div>
          )}
        </div>
        <footer className="replay-controls">
          <div className="replay-buttons">
            <button
              type="button"
              className="button-secondary"
              disabled={state !== "ready" || events.length === 0}
              onClick={restart}
            >
              {t("audit.restart")}
            </button>
            <button
              type="button"
              className="button-primary"
              disabled={state !== "ready" || events.length === 0}
              onClick={() => setPlaying((current) => !current)}
            >
              {playing ? t("audit.pause") : t("audit.play")}
            </button>
            <label className="replay-speed">
              <span>{t("audit.speed")}</span>
              <select value={speed} onChange={(event) => setSpeed(Number(event.target.value))}>
                <option value={0.5}>0.5×</option>
                <option value={1}>1×</option>
                <option value={2}>2×</option>
                <option value={4}>4×</option>
              </select>
            </label>
          </div>
          <div className="replay-timeline" aria-live="polite">
            <span>
              {formatDuration(elapsed)} / {formatDuration(duration)}
            </span>
            <span className="replay-state">{statusLabel}</span>
          </div>
        </footer>
      </section>
    </div>
  );
}
