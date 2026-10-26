import { requestID as newRequestID } from "../utils/requestID";
import { useCallback, useEffect, useRef, useState } from "react";
import { useTranslation } from "react-i18next";
import { useAuth } from "../auth/AuthContext";
import "../i18n/locales/features/runtime-logs/register";

type Status = {
  instance: string;
  revision: number;
  max_bytes: number;
  max_backups: number;
  max_age_days: number;
  current_bytes: number;
  total_bytes: number;
  backups: number;
  last_rotation: string;
  error_code?: string;
  truncated_records: number;
};
type Result = { enabled: boolean; status?: Status };
type Input = { instance: string; revision: number; request_id: string };
const endpoint = "/api/v1/settings/security/runtime-logs";

export default function RuntimeLogs() {
  const { t, i18n } = useTranslation();
  const { accessToken } = useAuth();
  const [value, setValue] = useState<Result | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState(false);
  const pending = useRef<Input | null>(null);
  const refresh = useCallback(
    async (signal?: AbortSignal) => {
      const response = await fetch(endpoint, {
        signal,
        headers: accessToken ? { Authorization: `Bearer ${accessToken}` } : undefined,
      });
      if (!response.ok) throw new Error("unavailable");
      const result = (await response.json()) as Result;
      return result;
    },
    [accessToken],
  );
  useEffect(() => {
    const controller = new AbortController();
    void refresh(controller.signal)
      .then((result) => { if (!controller.signal.aborted) setValue(result); })
      .catch(() => { if (!controller.signal.aborted) setError("unavailable"); });
    return () => controller.abort();
  }, [refresh]);
  async function rotate() {
    if (!value?.status) return;
    pending.current ??= {
      instance: value.status.instance,
      revision: value.status.revision,
      request_id: newRequestID(),
    };
    setBusy(true);
    setError("");
    setNotice(false);
    try {
      const response = await fetch(endpoint + "/rotate", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          ...(accessToken ? { Authorization: `Bearer ${accessToken}` } : {}),
        },
        body: JSON.stringify(pending.current),
      });
      if (!response.ok) {
        if (response.status === 409) {
          pending.current = null;
          setError("conflict");
          setValue(await refresh());
        } else setError("unavailable");
        return;
      }
      setValue((await response.json()) as Result);
      pending.current = null;
      setNotice(true);
    } catch {
      setError("unavailable");
    } finally {
      setBusy(false);
    }
  }
  const status = value?.status;
  const mb = (bytes: number) =>
    new Intl.NumberFormat(i18n.language, { maximumFractionDigits: 1 }).format(bytes / 1024 / 1024);
  return (
    <section
      className="settings-card settings-form"
      aria-labelledby="runtime-logs-title"
      aria-busy={busy}
    >
      <h3 id="runtime-logs-title">{t("runtimeLogs.title")}</h3>
      <p>{t("runtimeLogs.description")}</p>
      {!value && !error && <p role="status">{t("runtimeLogs.loading")}</p>}
      {value?.enabled === false && <p>{t("runtimeLogs.console")}</p>}
      {status && (
        <>
          <dl className="runtime-log-summary">
            <div>
              <dt>{t("runtimeLogs.usage")}</dt>
              <dd>{t("runtimeLogs.megabytes", { value: mb(status.total_bytes) })}</dd>
            </div>
            <div>
              <dt>{t("runtimeLogs.archives")}</dt>
              <dd>
                {status.backups} / {status.max_backups}
              </dd>
            </div>
          </dl>
          <p>
            {t("runtimeLogs.policy", {
              size: mb(status.max_bytes),
              count: status.max_backups,
              days: status.max_age_days,
            })}
          </p>
          {status.last_rotation && !status.last_rotation.startsWith("0001-") && (
            <p>
              {t("runtimeLogs.last", {
                at: new Date(status.last_rotation).toLocaleString(i18n.language),
              })}
            </p>
          )}
          {(status.error_code || status.truncated_records > 0) && (
            <p role="alert" className="asset-error">
              {t(status.error_code ? "runtimeLogs.ioError" : "runtimeLogs.truncated", {
                count: status.truncated_records,
              })}
            </p>
          )}
        </>
      )}
      {error && (
        <p role="alert" className="asset-error">
          {t(error === "conflict" ? "runtimeLogs.conflict" : "runtimeLogs.error")}
        </p>
      )}
      {notice && (
        <p role="status" className="settings-notice">
          {t("runtimeLogs.rotated")}
        </p>
      )}
      <div className="settings-review-actions">
        {status && (
          <button type="button" disabled={busy} onClick={() => void rotate()}>
            {t(busy ? "runtimeLogs.rotating" : "runtimeLogs.rotate")}
          </button>
        )}
        <button
          type="button"
          disabled={busy}
          onClick={() => {
            setError("");
            setNotice(false);
            void refresh().then(setValue).catch(() => setError("unavailable"));
          }}
        >
          {t("runtimeLogs.refresh")}
        </button>
      </div>
    </section>
  );
}
