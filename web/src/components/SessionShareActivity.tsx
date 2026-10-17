import { useEffect, useState } from "react";
import { useTranslation } from "react-i18next";
type Event = { event: string; at: string; actor: { id: string; name: string }; member_id?: string };
const kinds = new Set([
  "share_created",
  "share_joined",
  "share_left",
  "share_kicked",
  "share_revoked",
  "share_control_taken",
  "share_control_reclaimed",
  "share_connected",
  "share_disconnected",
]);
export default function SessionShareActivity({
  sessionID,
  accessToken,
}: {
  sessionID: string;
  accessToken: string;
}) {
  const { t, i18n } = useTranslation();
  const [offset, setOffset] = useState(0),
    [reload, setReload] = useState(0),
    [events, setEvents] = useState<Event[]>([]),
    [total, setTotal] = useState(0),
    [error, setError] = useState(false);
  useEffect(() => {
    const controller = new AbortController();
    void fetch(
      `/api/v1/sessions/${encodeURIComponent(sessionID)}/share-events?limit=20&offset=${offset}`,
      {
        signal: controller.signal,
        headers: accessToken ? { Authorization: `Bearer ${accessToken}` } : {},
      },
    )
      .then(async (r) => {
        if (!r.ok) throw Error("sharing activity unavailable");
        const data = (await r.json()) as { results: Event[]; total: number };
        if (!controller.signal.aborted) {
          setEvents(data.results);
          setTotal(data.total);
          setError(false);
        }
      })
      .catch(() => {
        if (!controller.signal.aborted) setError(true);
      });
    return () => controller.abort();
  }, [accessToken, sessionID, offset, reload]);
  return (
    <section className="session-share-activity" aria-label={t("sharing.events")}>
      <div className="session-share-row">
        <h3>{t("sharing.events")}</h3>
        <button type="button" className="button-secondary" onClick={() => setReload((v) => v + 1)}>
          {t("sharing.refresh")}
        </button>
      </div>
      {error && <p role="alert">{t("sharing.error")}</p>}
      {events.map((e, index) => (
        <p key={`${e.at}-${e.event}-${index}`}>
          <time dateTime={e.at}>{new Date(e.at).toLocaleString(i18n.language)}</time> ·{" "}
          <strong>{e.actor.name}</strong> ·{" "}
          {t(kinds.has(e.event) ? `sharing.eventNames.${e.event}` : "sharing.otherEvent")}
        </p>
      ))}
      {!error && total === 0 && <p>{t("sharing.empty")}</p>}
      <div className="session-share-row">
        <span>
          {t("audit.showing", {
            from: total === 0 ? 0 : offset + 1,
            to: Math.min(offset + events.length, total),
            total,
          })}
        </span>
        <div>
          <button
            className="button-secondary"
            type="button"
            disabled={offset === 0}
            onClick={() => setOffset((v) => Math.max(0, v - 20))}
          >
            {t("audit.previous")}
          </button>
          <button
            className="button-secondary"
            type="button"
            disabled={offset + 20 >= total}
            onClick={() => setOffset((v) => v + 20)}
          >
            {t("audit.next")}
          </button>
        </div>
      </div>
    </section>
  );
}
