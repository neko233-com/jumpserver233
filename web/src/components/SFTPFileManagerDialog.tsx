import { useCallback, useEffect, useRef, useState, type ChangeEvent, type FormEvent } from "react";
import { useTranslation } from "react-i18next";

type Entry = {
  name: string;
  size: number;
  mode: string;
  mod_time: string;
  is_dir: boolean;
  is_regular: boolean;
  is_symlink: boolean;
};

type DirectoryResult = { path: string; entries: Entry[] };
type AccessReview = { state: "pending" | "approved" | "denied" | "expired" | "consumed" };
type SFTPAccessResponse = { review_id?: string; session_token?: string; required?: boolean };

function formatBytes(bytes: number) {
  if (!Number.isFinite(bytes) || bytes < 0) return "—";
  if (bytes < 1024) return `${bytes} B`;
  const units = ["KB", "MB", "GB", "TB"];
  let value = bytes / 1024;
  let unit = 0;
  while (value >= 1024 && unit < units.length - 1) {
    value /= 1024;
    unit++;
  }
  return `${value.toFixed(value < 10 ? 1 : 0)} ${units[unit]}`;
}

export default function SFTPFileManagerDialog({
  assetId,
  assetName,
  accessToken,
  onClose,
  workspace,
}: {
  assetId: string;
  assetName: string;
  accessToken: string | null;
  onClose: () => void;
  workspace?: string;
}) {
  const { t, i18n } = useTranslation();
  const [currentPath, setCurrentPath] = useState("");
  const [entries, setEntries] = useState<Entry[]>([]);
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState(false);
  const [failed, setFailed] = useState(false);
  const [reviewState, setReviewState] = useState<"pending" | "denied" | "expired" | null>(null);
  const [sessionReady, setSessionReady] = useState(false);
  const [folderName, setFolderName] = useState("");
  const sessionToken = useRef<string | null>(null);

  const request = useCallback(
    (url: string, init?: RequestInit, sessionOverride?: string | null) => {
      const headers = new Headers(init?.headers);
      if (accessToken) headers.set("Authorization", `Bearer ${accessToken}`);
      const activeSession = sessionOverride === undefined ? sessionToken.current : sessionOverride;
      if (activeSession) headers.set("X-JMS-SFTP-Session", activeSession);
      return fetch(url, { ...init, headers });
    },
    [accessToken],
  );

  const loadDirectory = useCallback(
    async (directory: string, sessionOverride?: string | null) => {
      setLoading(true);
      setFailed(false);
      try {
        const query = new URLSearchParams({ path: directory });
        const response = await request(
          `/api/v1/assets/${encodeURIComponent(assetId)}/files?${query}`,
          undefined,
          sessionOverride,
        );
        if (!response.ok) throw new Error("directory request failed");
        const result = (await response.json()) as DirectoryResult;
        const sorted = result.entries.sort(
          (a, b) => Number(b.is_dir) - Number(a.is_dir) || a.name.localeCompare(b.name),
        );
        setCurrentPath(result.path);
        setEntries(sorted);
      } catch {
        setFailed(true);
      } finally {
        setLoading(false);
      }
    },
    [assetId, request],
  );

  useEffect(() => {
    const controller = new AbortController();
    let timer: number | undefined;
    const sessionURL = `/api/v1/assets/${encodeURIComponent(assetId)}/files/session`;
    const pause = () =>
      new Promise<void>((resolve) => {
        timer = window.setTimeout(resolve, 1500);
      });

    async function establishSession() {
      const deadline = Date.now() + 5 * 60 * 1000;
      setLoading(true);
      setFailed(false);
      setReviewState(null);
      try {
        for (;;) {
          const response = await request(sessionURL, { method: "POST" }, null);
          if (response.status === 202) {
            const pending = (await response.json()) as SFTPAccessResponse;
            if (!pending.review_id) throw new Error("missing SFTP review identifier");
            setReviewState("pending");
            let reviewStatus: AccessReview["state"] = "pending";
            while (
              !controller.signal.aborted &&
              Date.now() < deadline &&
              reviewStatus === "pending"
            ) {
              await pause();
              if (controller.signal.aborted) return;
              const statusResponse = await request(
                `/api/v1/access-reviews/${encodeURIComponent(pending.review_id)}`,
                undefined,
                null,
              );
              if (!statusResponse.ok) throw new Error("SFTP review status request failed");
              const review = (await statusResponse.json()) as AccessReview;
              reviewStatus = review.state;
            }
            if (controller.signal.aborted) return;
            if (reviewStatus !== "approved") {
              setReviewState(reviewStatus === "denied" ? "denied" : "expired");
              setLoading(false);
              return;
            }
            continue;
          }
          if (!response.ok) throw new Error("SFTP session request failed");
          const result = (await response.json()) as SFTPAccessResponse;
          const token: string | null =
            response.status === 201 ? (result.session_token ?? null) : null;
          if (response.status === 201 && !token) throw new Error("missing SFTP session token");
          sessionToken.current = token;
          setSessionReady(true);
          setReviewState(null);
          await loadDirectory("", token);
          return;
        }
      } catch {
        if (controller.signal.aborted) return;
        setFailed(true);
        setLoading(false);
      }
    }

    void establishSession();
    return () => {
      controller.abort();
      if (timer !== undefined) window.clearTimeout(timer);
      const token = sessionToken.current;
      sessionToken.current = null;
      if (token) void request(sessionURL, { method: "DELETE" }, token);
    };
  }, [assetId, loadDirectory, request]);

  async function createFolder(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const name = folderName.trim();
    if (!sessionReady || !name || name.includes("/") || name.includes("\\")) return;
    const path = [currentPath, name].filter(Boolean).join("/");
    setBusy(true);
    setFailed(false);
    try {
      const response = await request(`/api/v1/assets/${encodeURIComponent(assetId)}/directories`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ path }),
      });
      if (!response.ok) throw new Error("directory creation failed");
      setFolderName("");
      await loadDirectory(currentPath);
    } catch {
      setFailed(true);
    } finally {
      setBusy(false);
    }
  }

  async function uploadFile(event: ChangeEvent<HTMLInputElement>) {
    const file = event.target.files?.[0];
    event.target.value = "";
    if (!sessionReady || !file) return;
    const path = [currentPath, file.name].filter(Boolean).join("/");
    const send = (overwrite: boolean) => {
      const query = new URLSearchParams({ path });
      if (overwrite) query.set("overwrite", "true");
      return request(`/api/v1/assets/${encodeURIComponent(assetId)}/files/content?${query}`, {
        method: "PUT",
        headers: { "Content-Type": "application/octet-stream" },
        body: file,
      });
    };
    setBusy(true);
    setFailed(false);
    try {
      let response = await send(false);
      if (
        response.status === 409 &&
        window.confirm(t("files.overwriteConfirm", { name: file.name }))
      ) {
        response = await send(true);
      }
      if (!response.ok) throw new Error("file upload failed");
      await loadDirectory(currentPath);
    } catch {
      setFailed(true);
    } finally {
      setBusy(false);
    }
  }

  async function downloadFile(entry: Entry) {
    if (!sessionReady) return;
    const path = [currentPath, entry.name].filter(Boolean).join("/");
    const query = new URLSearchParams({ path });
    setBusy(true);
    setFailed(false);
    try {
      const response = await request(
        `/api/v1/assets/${encodeURIComponent(assetId)}/files/content?${query}`,
      );
      if (!response.ok) throw new Error("file download failed");
      const blob = await response.blob();
      const objectURL = URL.createObjectURL(blob);
      const anchor = document.createElement("a");
      anchor.href = objectURL;
      anchor.download = entry.name;
      anchor.click();
      URL.revokeObjectURL(objectURL);
    } catch {
      setFailed(true);
    } finally {
      setBusy(false);
    }
  }

  async function deleteEntry(entry: Entry) {
    if (!sessionReady) return;
    if (!window.confirm(t("files.deleteConfirm", { name: entry.name }))) return;
    const path = [currentPath, entry.name].filter(Boolean).join("/");
    const query = new URLSearchParams({ path });
    setBusy(true);
    setFailed(false);
    try {
      const response = await request(
        `/api/v1/assets/${encodeURIComponent(assetId)}/files/content?${query}`,
        { method: "DELETE" },
      );
      if (!response.ok) throw new Error("file delete failed");
      await loadDirectory(currentPath);
    } catch {
      setFailed(true);
    } finally {
      setBusy(false);
    }
  }

  const parentPath = currentPath.includes("/")
    ? currentPath.slice(0, currentPath.lastIndexOf("/"))
    : "";
  const segments = currentPath ? currentPath.split("/") : [];
  const locale = i18n.language === "zh-CN" ? "zh-CN" : "en";

  return (
    <div
      className="asset-modal-backdrop"
      role="presentation"
      onMouseDown={(event) => {
        if (event.target === event.currentTarget) onClose();
      }}
    >
      <section
        className="asset-modal sftp-manager"
        role="dialog"
        aria-modal="true"
        aria-labelledby="sftp-title"
      >
        <div className="sftp-manager-heading">
          <div>
            <h3 id="sftp-title">{t("files.title")}</h3>
            <p>{assetName}</p>
            {workspace && <small>{t("files.workspaceRoot", { path: workspace })}</small>}
          </div>
          <button
            type="button"
            className="button-text"
            aria-label={t("assets.cancel")}
            onClick={onClose}
          >
            ×
          </button>
        </div>

        <div className="sftp-toolbar">
          <button
            type="button"
            className="button-secondary"
            disabled={!sessionReady || !currentPath || loading || busy}
            onClick={() => void loadDirectory(parentPath)}
          >
            {t("files.parent")}
          </button>
          <nav className="sftp-breadcrumbs" aria-label={t("files.location")}>
            <button type="button" className="button-text" onClick={() => void loadDirectory("")}>
              /
            </button>
            {segments.map((segment, index) => {
              const path = segments.slice(0, index + 1).join("/");
              return (
                <span key={path}>
                  <span aria-hidden="true">/</span>
                  <button
                    type="button"
                    className="button-text"
                    onClick={() => void loadDirectory(path)}
                  >
                    {segment}
                  </button>
                </span>
              );
            })}
          </nav>
          <label className="button-primary sftp-upload-button">
            {busy ? "…" : t("files.upload")}
            <input
              type="file"
              disabled={!sessionReady || busy || loading}
              onChange={(event) => void uploadFile(event)}
            />
          </label>
        </div>

        <form className="sftp-create-folder" onSubmit={(event) => void createFolder(event)}>
          <input
            value={folderName}
            onChange={(event) => setFolderName(event.target.value)}
            maxLength={255}
            disabled={!sessionReady || busy || loading}
            placeholder={t("files.folderPlaceholder")}
            aria-label={t("files.folderPlaceholder")}
          />
          <button
            type="submit"
            className="button-secondary"
            disabled={!sessionReady || busy || loading || !folderName.trim()}
          >
            {t("files.newFolder")}
          </button>
        </form>

        {reviewState === "pending" && (
          <p className="settings-notice" role="status">
            {t("files.loginReviewPending")}
          </p>
        )}
        {reviewState === "denied" && (
          <p className="asset-error" role="alert">
            {t("files.loginReviewDenied")}
          </p>
        )}
        {reviewState === "expired" && (
          <p className="asset-error" role="alert">
            {t("files.loginReviewExpired")}
          </p>
        )}
        {failed && (
          <p className="asset-error" role="alert">
            {t("files.operationFailed")}
          </p>
        )}
        <div className="sftp-list-wrap">
          <table className="session-table sftp-table">
            <thead>
              <tr>
                <th>{t("files.name")}</th>
                <th>{t("files.size")}</th>
                <th>{t("files.modified")}</th>
                <th>{t("assets.actions")}</th>
              </tr>
            </thead>
            <tbody>
              {entries.map((entry) => (
                <tr key={entry.name}>
                  <td>
                    <button
                      type="button"
                      className="button-text sftp-entry-name"
                      disabled={!sessionReady || loading || busy || entry.is_symlink}
                      onClick={() =>
                        entry.is_dir
                          ? void loadDirectory([currentPath, entry.name].filter(Boolean).join("/"))
                          : void downloadFile(entry)
                      }
                    >
                      <span aria-hidden="true">
                        {entry.is_symlink ? "↗" : entry.is_dir ? "▰" : "▤"}
                      </span>
                      {entry.name}
                    </button>
                    {entry.is_symlink && <small>{t("files.symlink")}</small>}
                  </td>
                  <td>{entry.is_dir ? "—" : formatBytes(entry.size)}</td>
                  <td>{entry.mod_time ? new Date(entry.mod_time).toLocaleString(locale) : "—"}</td>
                  <td>
                    <div className="session-actions">
                      {entry.is_regular && !entry.is_symlink && (
                        <button
                          type="button"
                          className="button-text"
                          disabled={!sessionReady || loading || busy}
                          onClick={() => void downloadFile(entry)}
                        >
                          {t("files.download")}
                        </button>
                      )}
                      <button
                        type="button"
                        className="button-text danger"
                        disabled={!sessionReady || loading || busy}
                        onClick={() => void deleteEntry(entry)}
                      >
                        {t("assets.delete")}
                      </button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
          {loading && <div className="session-empty">{t("files.loading")}</div>}
          {!loading && entries.length === 0 && !failed && (
            <div className="session-empty">{t("files.empty")}</div>
          )}
        </div>
        <div className="asset-modal-actions">
          <button type="button" className="button-secondary" onClick={onClose}>
            {t("assets.cancel")}
          </button>
        </div>
      </section>
    </div>
  );
}
