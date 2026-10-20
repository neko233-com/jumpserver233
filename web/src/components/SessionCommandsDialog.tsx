import { useEffect, useState } from "react";
import { useTranslation } from "react-i18next";

type CommandRecord = {
  working_directory?: string;
  directory_verified?: boolean;
  actor?: string;
  id: string;
  command: string;
  submitted_at: string;
  outcome: "allowed" | "blocked" | "pending" | "approved" | "denied" | "timed_out" | "cancelled";
  rule_name?: string;
  reviewed_by?: string;
};

type CommandPage = { results: CommandRecord[]; total: number };
const pageSize = 50;

type Props = {
  sessionID: string;
  assetName: string;
  status: "active" | "ended" | "interrupted";
  accessToken: string;
  onClose: () => void;
};

function formatTime(value: string, locale: string) {
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? "—" : date.toLocaleString(locale);
}

export default function SessionCommandsDialog({
  sessionID,
  assetName,
  status,
  accessToken,
  onClose,
}: Props) {
  const { t, i18n } = useTranslation();
  const [commands, setCommands] = useState<CommandRecord[]>([]);
  const [total, setTotal] = useState(0);
  const [offset, setOffset] = useState(0);
  const [loading, setLoading] = useState(true);
  const [failed, setFailed] = useState(false);

  useEffect(() => {
    let active = true;
    const load = async () => {
      try {
        const headers = new Headers();
        if (accessToken) headers.set("Authorization", `Bearer ${accessToken}`);
        const response = await fetch(
          `/api/v1/sessions/${encodeURIComponent(sessionID)}/commands?limit=${pageSize}&offset=${offset}`,
          { headers },
        );
        if (!response.ok) throw new Error("command audit request failed");
        const result = (await response.json()) as CommandPage;
        if (!active) return;
        setCommands(result.results);
        setTotal(result.total);
        setFailed(false);
      } catch {
        if (active) setFailed(true);
      } finally {
        if (active) setLoading(false);
      }
    };
    void load();
    const timer = status === "active" ? window.setInterval(() => void load(), 5_000) : undefined;
    return () => {
      active = false;
      if (timer !== undefined) window.clearInterval(timer);
    };
  }, [accessToken, offset, sessionID, status]);

  return (
    <div
      className="asset-modal-backdrop command-audit-backdrop"
      role="presentation"
      onMouseDown={(event) => {
        if (event.target === event.currentTarget) onClose();
      }}
    >
      <section
        className="asset-modal command-audit-dialog"
        role="dialog"
        aria-modal="true"
        aria-labelledby="command-audit-title"
      >
        <h3 id="command-audit-title">{t("audit.commandsTitle", { name: assetName })}</h3>
        <p className="command-audit-hint">{t("audit.commandHint")}</p>
        {failed && (
          <p className="asset-error" role="alert">
            {t("audit.commandLoadError")}
          </p>
        )}
        {loading && commands.length === 0 && (
          <p className="command-audit-empty">{t("audit.commandLoading")}</p>
        )}
        {!loading && !failed && total === 0 && (
          <p className="command-audit-empty">{t("audit.commandEmpty")}</p>
        )}
        {commands.length > 0 && (
          <div className="command-audit-list" aria-label={t("audit.commands")}>
            {commands.map((entry) => (
              <article className={`command-audit-row ${entry.outcome}`} key={entry.id}>
                <time dateTime={entry.submitted_at}>
                  {formatTime(entry.submitted_at, i18n.language)}
                </time>
                <span className={`command-audit-outcome ${entry.outcome}`}>
                  {t(`audit.commandOutcomes.${entry.outcome}`)}
                </span>
                <div>
                  <code>{entry.command || t("audit.commandUnknownInput")}</code>
                  {entry.directory_verified && entry.working_directory && (
                    <small>
                      {t("audit.commandDirectory", { directory: entry.working_directory })}
                    </small>
                  )}
                  {entry.actor && <small>{t("sharing.actor", { name: entry.actor })}</small>}
                  {entry.rule_name && (
                    <small>{t("audit.commandRule", { rule: entry.rule_name })}</small>
                  )}
                  {entry.reviewed_by && (
                    <small>{t("audit.commandReviewedBy", { user: entry.reviewed_by })}</small>
                  )}
                </div>
              </article>
            ))}
          </div>
        )}
        <div className="command-audit-pagination">
          <span>
            {t("audit.showing", {
              from: total === 0 ? 0 : offset + 1,
              to: Math.min(offset + commands.length, total),
              total,
            })}
          </span>
          <div>
            <button
              type="button"
              className="button-secondary"
              disabled={offset === 0 || loading}
              onClick={() => setOffset(Math.max(0, offset - pageSize))}
            >
              {t("audit.previous")}
            </button>
            <button
              type="button"
              className="button-secondary"
              disabled={offset + pageSize >= total || loading}
              onClick={() => setOffset(offset + pageSize)}
            >
              {t("audit.next")}
            </button>
          </div>
        </div>
        <div className="asset-modal-actions command-audit-actions">
          <button type="button" className="button-secondary" onClick={onClose}>
            {t("audit.closeCommands")}
          </button>
        </div>
      </section>
    </div>
  );
}
