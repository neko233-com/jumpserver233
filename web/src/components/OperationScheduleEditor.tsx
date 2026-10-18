import { useEffect, useRef, useState, type FormEvent } from "react";
import { useTranslation } from "react-i18next";
import { toggleLang } from "../i18n";
import OperationScheduleFields from "./OperationScheduleFields";
import {
  scheduleDraft,
  schedulePayload,
  type Schedule,
  type ScheduledPlan,
} from "./operationSchedules";
type Event = {
  id: string;
  at: string;
  actor: { id: string; name: string };
  action: string;
  revision: number;
  before: Schedule;
  after: Schedule;
};
type Props = {
  plan: ScheduledPlan;
  editable: boolean;
  request: (url: string, init?: RequestInit) => Promise<Response>;
  onSaved: () => void;
  onClose: () => void;
};
function Summary({ schedule: s }: { schedule: Schedule }) {
  const { t } = useTranslation();
  if (!s.kind) return <span>—</span>;
  return (
    <span>
      {t(s.kind === "cron" ? "calendar.kindCron" : "operations.kinds." + s.kind)}
      {s.cron_expression && (
        <>
          {" "}
          · <code>{s.cron_expression}</code> · {s.timezone} · {t("calendar." + s.misfire_policy)} ·{" "}
          {t("calendar.grace")}: {s.grace_seconds} · {t("calendar.fold")}:{" "}
          {t(s.fold_policy === "both" ? "calendar.foldBoth" : "calendar.foldOnce")}
        </>
      )}
      {s.interval_seconds ? (
        <> · {t("calendar.everySeconds", { count: s.interval_seconds })}</>
      ) : null}
      {s.run_at && (
        <>
          {" "}
          · <time dateTime={s.run_at}>{s.run_at}</time>
        </>
      )}
      {s.end_at && (
        <>
          {" "}
          · {t("calendar.endAt")}: {s.end_at}
        </>
      )}
    </span>
  );
}
export default function OperationScheduleEditor({
  plan,
  editable,
  request,
  onSaved,
  onClose,
}: Props) {
  const { t, i18n } = useTranslation(),
    dialog = useRef<HTMLDialogElement>(null),
    life = useRef<AbortController | null>(null);
  const [current, setCurrent] = useState(plan),
    [draft, setDraft] = useState(() => scheduleDraft(plan)),
    [busy, setBusy] = useState(false),
    [error, setError] = useState("");
  const [events, setEvents] = useState<Event[]>([]),
    [offset, setOffset] = useState(0),
    [total, setTotal] = useState(0),
    [version, setVersion] = useState(0);
  const mutable =
    editable && current.kind !== "batch" && !(current.kind === "once" && current.last_run_id);
  useEffect(() => {
    const ctl = new AbortController();
    life.current = ctl;
    const previous = document.activeElement instanceof HTMLElement ? document.activeElement : null;
    const el = dialog.current;
    el?.showModal();
    return () => {
      ctl.abort();
      el?.close();
      if (previous?.isConnected) previous.focus();
    };
  }, []);
  useEffect(() => {
    const ctl = new AbortController();
    void request(
      `/api/v1/ops/plans/${encodeURIComponent(current.id)}/events?offset=${offset}&limit=20`,
      { signal: ctl.signal },
    )
      .then((r) => {
        if (!r.ok) throw Error();
        return r.json() as Promise<{ results: Event[]; total: number }>;
      })
      .then((v) => {
        if (!ctl.signal.aborted) {
          setEvents(v.results);
          setTotal(v.total);
        }
      })
      .catch(() => {
        if (!ctl.signal.aborted) {
          setEvents([]);
          setTotal(0);
          setError("unavailable");
        }
      });
    return () => ctl.abort();
  }, [current.id, offset, version, request]);
  const reload = async () => {
    if (!life.current) return;
    setBusy(true);
    setError("");
    try {
      const r = await request("/api/v1/ops/plans/" + encodeURIComponent(current.id), {
        signal: life.current.signal,
      });
      if (!r.ok) throw Error();
      const p = (await r.json()) as ScheduledPlan;
      if (!life.current.signal.aborted) {
        setCurrent(p);
        setDraft(scheduleDraft(p));
        setVersion((v) => v + 1);
      }
    } catch {
      if (!life.current.signal.aborted) setError("unavailable");
    } finally {
      setBusy(false);
    }
  };
  const save = async (e: FormEvent) => {
    e.preventDefault();
    if (!life.current) return;
    setBusy(true);
    setError("");
    try {
      const r = await request(`/api/v1/ops/plans/${encodeURIComponent(current.id)}/schedule`, {
        method: "PUT",
        body: JSON.stringify({ ...schedulePayload(draft), revision: current.config_revision }),
        signal: life.current.signal,
      });
      if (!r.ok) {
        setError(
          r.status === 409
            ? "conflict"
            : r.status === 403
              ? "denied"
              : r.status === 400
                ? "invalid"
                : "unavailable",
        );
        return;
      }
      if (!life.current.signal.aborted) onSaved();
    } catch {
      if (!life.current.signal.aborted) setError("unavailable");
    } finally {
      setBusy(false);
    }
  };
  const time = (s?: string) => (s ? new Date(s).toLocaleString(i18n.language) : "—");
  return (
    <dialog
      ref={dialog}
      className="calendar-dialog"
      aria-labelledby="calendar-editor-title"
      onCancel={(e) => {
        e.preventDefault();
        onClose();
      }}
    >
      <header>
        <h2 id="calendar-editor-title">
          {t("calendar.title")} · {current.name}
        </h2>
        <button type="button" onClick={() => void toggleLang()}>
          {t("sharing.language")}
        </button>
        <button type="button" onClick={onClose}>
          {t("calendar.close")}
        </button>
      </header>
      <p>
        {t("calendar.revision")}: {current.config_revision} ·{" "}
        {t(current.enabled ? "operations.enabled" : "operations.paused")}
      </p>
      <p>
        {t("operations.nextRun")}: {time(current.next_run)} · {t("calendar.watermark")}:{" "}
        {time(current.last_scheduled_at)} · {t("calendar.skipped")}: {current.skipped_triggers || 0}
      </p>
      <p>{t("calendar.safety")}</p>
      {error && <p role="alert">{t("calendar." + error)}</p>}
      {!mutable && <p>{t("calendar.readonly")}</p>}
      <form onSubmit={(e) => void save(e)}>
        <OperationScheduleFields
          value={draft}
          onChange={setDraft}
          request={request}
          disabled={!mutable || busy}
          allowBatch={current.kind === "batch"}
        />
        <div className="calendar-actions">
          {mutable && (
            <button type="submit" disabled={busy}>
              {t("calendar.save")}
            </button>
          )}
          <button type="button" disabled={busy} onClick={() => void reload()}>
            {t("calendar.reload")}
          </button>
        </div>
      </form>
      <h3>{t("calendar.events")}</h3>
      <div className="calendar-scroll">
        <table>
          <thead>
            <tr>
              {["at", "actor", "action", "revision", "before", "after"].map((k) => (
                <th key={k} scope="col">
                  {t("calendar." + k)}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {events.map((v) => (
              <tr key={v.id}>
                <td>{time(v.at)}</td>
                <td>{v.actor.name || v.actor.id}</td>
                <td>{t("calendar.eventKinds." + v.action)}</td>
                <td>{v.revision}</td>
                <td>
                  <Summary schedule={v.before} />
                </td>
                <td>
                  <Summary schedule={v.after} />
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      {!events.length && <p>{t("calendar.emptyEvents")}</p>}
      <nav className="calendar-actions" aria-label={t("calendar.events")}>
        <button
          type="button"
          disabled={offset === 0}
          onClick={() => setOffset((n) => Math.max(0, n - 20))}
        >
          {t("jobs.previous")}
        </button>
        <span>
          {total === 0 ? 0 : offset + 1}–{Math.min(total, offset + 20)} / {total}
        </span>
        <button
          type="button"
          disabled={offset + 20 >= total}
          onClick={() => setOffset((n) => n + 20)}
        >
          {t("jobs.next")}
        </button>
      </nav>
    </dialog>
  );
}
