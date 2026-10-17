import { useEffect } from "react";
import { useTranslation } from "react-i18next";
import SessionShareActivity from "./SessionShareActivity";
export default function SessionShareActivityDialog({
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
  useEffect(() => {
    const key = (e: KeyboardEvent) => {
      if (e.key === "Escape") onClose();
    };
    window.addEventListener("keydown", key);
    return () => window.removeEventListener("keydown", key);
  }, [onClose]);
  return (
    <div
      className="ssh-terminal-backdrop"
      role="presentation"
      onMouseDown={(e) => {
        if (e.currentTarget === e.target) onClose();
      }}
    >
      <section
        className="asset-modal command-audit-dialog"
        role="dialog"
        aria-modal="true"
        aria-label={t("sharing.events")}
      >
        <h2>{assetName}</h2>
        <SessionShareActivity sessionID={sessionID} accessToken={accessToken} />
        <button className="button-secondary" type="button" onClick={onClose}>
          {t("audit.closeCommands")}
        </button>
      </section>
    </div>
  );
}
