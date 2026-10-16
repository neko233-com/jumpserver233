import { useCallback, useEffect, useState } from "react";
import { useTranslation } from "react-i18next";

type CredentialBackup = {
  backup_id: string;
  created_at: string;
  credential_type?: string;
  key_fingerprint?: string;
};
type Request = (url: string, init?: RequestInit) => Promise<Response>;

type Props = {
  asset: { id: string; name: string };
  request: Request;
  onClose: () => void;
  onChanged: () => Promise<void>;
};

export default function CredentialBackupsDialog({ asset, request, onClose, onChanged }: Props) {
  const { t, i18n } = useTranslation();
  const [backups, setBackups] = useState<CredentialBackup[]>([]);
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState("");
  const [error, setError] = useState(false);
  const [message, setMessage] = useState("");

  const loadBackups = useCallback(async () => {
    try {
      const response = await request(
        `/api/v1/assets/${encodeURIComponent(asset.id)}/credential-backups`,
      );
      if (!response.ok) throw new Error("credential backup list failed");
      setBackups((await response.json()) as CredentialBackup[]);
      setError(false);
    } catch {
      setError(true);
    } finally {
      setLoading(false);
    }
  }, [asset.id, request]);

  // Fetching the server-owned backup list is the dialog's initial state.
  useEffect(() => {
    // eslint-disable-next-line react/set-state-in-effect
    void loadBackups();
  }, [loadBackups]);

  function formatDate(value: string) {
    const date = new Date(value);
    if (Number.isNaN(date.getTime())) return "—";
    return new Intl.DateTimeFormat(i18n.language === "zh-CN" ? "zh-CN" : "en", {
      dateStyle: "medium",
      timeStyle: "short",
    }).format(date);
  }

  async function createBackup() {
    setBusy("create");
    setError(false);
    setMessage("");
    try {
      const response = await request(
        `/api/v1/assets/${encodeURIComponent(asset.id)}/credential-backups`,
        { method: "POST" },
      );
      if (!response.ok) throw new Error("credential backup create failed");
      setLoading(true);
      await loadBackups();
    } catch {
      setError(true);
    } finally {
      setBusy("");
    }
  }

  async function restoreBackup(backup: CredentialBackup) {
    if (
      !window.confirm(
        t(
          backup.credential_type === "ssh_key"
            ? "assets.keyBackupRestoreConfirm"
            : "assets.backupRestoreConfirm",
          { name: asset.name, date: formatDate(backup.created_at) },
        ),
      )
    )
      return;
    setBusy(backup.backup_id);
    setError(false);
    setMessage("");
    try {
      const response = await request(
        `/api/v1/assets/${encodeURIComponent(asset.id)}/credential-backups/${encodeURIComponent(backup.backup_id)}/restore`,
        { method: "POST" },
      );
      if (!response.ok) throw new Error("credential backup restore failed");
      await onChanged();
      setMessage(
        t(
          backup.credential_type === "ssh_key"
            ? "assets.keyBackupRestoreSucceeded"
            : "assets.backupRestoreSucceeded",
        ),
      );
    } catch {
      setError(true);
    } finally {
      setBusy("");
    }
  }

  async function deleteBackup(backup: CredentialBackup) {
    if (!window.confirm(t("assets.backupDeleteConfirm", { date: formatDate(backup.created_at) })))
      return;
    setBusy(backup.backup_id);
    setError(false);
    setMessage("");
    try {
      const response = await request(
        `/api/v1/assets/${encodeURIComponent(asset.id)}/credential-backups/${encodeURIComponent(backup.backup_id)}`,
        { method: "DELETE" },
      );
      if (!response.ok) throw new Error("credential backup delete failed");
      setLoading(true);
      await loadBackups();
    } catch {
      setError(true);
    } finally {
      setBusy("");
    }
  }

  return (
    <div
      className="asset-modal-backdrop"
      role="presentation"
      onMouseDown={(event) => {
        if (event.target === event.currentTarget && !busy) onClose();
      }}
    >
      <section
        className="asset-modal credential-backups-dialog"
        role="dialog"
        aria-modal="true"
        aria-labelledby="credential-backups-title"
      >
        <h3 id="credential-backups-title">{t("assets.backupsTitle", { name: asset.name })}</h3>
        <p className="credential-backups-hint">{t("assets.backupsHint")}</p>
        {error && (
          <p className="asset-error" role="alert">
            {t("assets.backupOperationFailed")}
          </p>
        )}
        {message && (
          <p className="credential-backups-success" role="status">
            {message}
          </p>
        )}
        {loading ? (
          <p className="metrics-empty">{t("assets.backupsLoading")}</p>
        ) : backups.length === 0 ? (
          <p className="metrics-empty">{t("assets.backupsEmpty")}</p>
        ) : (
          <div className="credential-backup-list">
            {backups.map((backup) => (
              <div className="credential-backup-row" key={backup.backup_id}>
                <div>
                  <strong>{formatDate(backup.created_at)}</strong>
                  <small>
                    {t(
                      backup.credential_type === "ssh_key"
                        ? "assets.credentialKey"
                        : "assets.credentialPassword",
                    )}{" "}
                    · {t("assets.backupEncrypted")}
                  </small>
                  {backup.key_fingerprint && <small>{backup.key_fingerprint}</small>}
                </div>
                <div className="credential-backup-actions">
                  <button
                    type="button"
                    className="button-text"
                    disabled={Boolean(busy)}
                    onClick={() => void restoreBackup(backup)}
                  >
                    {busy === backup.backup_id
                      ? t("assets.backupRestoring")
                      : t("assets.backupRestore")}
                  </button>
                  <button
                    type="button"
                    className="button-text danger"
                    disabled={Boolean(busy)}
                    onClick={() => void deleteBackup(backup)}
                  >
                    {t("assets.delete")}
                  </button>
                </div>
              </div>
            ))}
          </div>
        )}
        <div className="asset-modal-actions credential-backup-footer">
          <button
            type="button"
            className="button-secondary"
            onClick={onClose}
            disabled={Boolean(busy)}
          >
            {t("assets.cancel")}
          </button>
          <button
            type="button"
            className="button-primary"
            onClick={() => void createBackup()}
            disabled={Boolean(busy) || loading}
          >
            {busy === "create" ? t("assets.backupCreating") : t("assets.backupCreate")}
          </button>
        </div>
      </section>
    </div>
  );
}
