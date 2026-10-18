import { useEffect, useId, useRef, useState } from "react";
import { useTranslation } from "react-i18next";
import { schedulePayload, type ScheduleDraft } from "./operationSchedules";
import "../i18n/locales/features/operations/register";
import "./operation-schedules.css";
type Props = {
  value: ScheduleDraft;
  onChange: (value: ScheduleDraft) => void;
  request: (url: string, init?: RequestInit) => Promise<Response>;
  disabled?: boolean;
  allowBatch?: boolean;
};
type Preview = { occurrences: { at: string; local: string }[] };
export default function OperationScheduleFields({
  value: d,
  onChange,
  request,
  disabled = false,
  allowBatch = true,
}: Props) {
  const { t } = useTranslation(),
    id = useId(),
    controller = useRef<AbortController | null>(null);
  const [preview, setPreview] = useState<{ key: string; data: Preview } | null>(null),
    [error, setError] = useState(""),
    [busy, setBusy] = useState(false);
  const key = JSON.stringify(d);
  useEffect(() => () => controller.current?.abort(), []);
  const change = (v: Partial<ScheduleDraft>) => {
    onChange({ ...d, ...v });
    setError("");
  };
  const calculate = async () => {
    controller.current?.abort();
    const next = new AbortController();
    controller.current = next;
    setBusy(true);
    setError("");
    try {
      const response = await request("/api/v1/ops/schedules/preview", {
        method: "POST",
        body: JSON.stringify({ ...schedulePayload(d), limit: 5 }),
        signal: AbortSignal.any([next.signal, AbortSignal.timeout(15_000)]),
      });
      if (!response.ok) throw Error();
      const data = (await response.json()) as Preview;
      if (!next.signal.aborted) setPreview({ key, data });
    } catch {
      if (!next.signal.aborted) {
        setPreview(null);
        setError(key);
      }
    } finally {
      if (!next.signal.aborted) setBusy(false);
    }
  };
  return (
    <>
      <fieldset className="calendar-fields" disabled={disabled}>
        <legend>{t("operations.kind")}</legend>
        <label>
          {t("operations.kind")}
          <select
            value={d.kind}
            onChange={(e) => change({ kind: e.target.value, runAt: "", endAt: "" })}
          >
            {allowBatch && <option value="batch">{t("operations.kinds.batch")}</option>}
            <option value="once">{t("operations.kinds.once")}</option>
            <option value="interval">{t("operations.kinds.interval")}</option>
            <option value="cron">{t("calendar.kindCron")}</option>
          </select>
        </label>
        {d.kind !== "batch" && (
          <label>
            {t("operations.runAt")}
            <input
              type="datetime-local"
              step="1"
              required={d.kind === "once"}
              value={d.runAt}
              onChange={(e) => change({ runAt: e.target.value })}
            />
          </label>
        )}
        {d.kind === "interval" && (
          <label>
            {t("operations.interval")}
            <input
              type="number"
              min={60}
              max={2678400}
              required
              value={d.interval}
              onChange={(e) => change({ interval: Number(e.target.value) })}
            />
          </label>
        )}
        {d.kind === "cron" && (
          <>
            <label>
              {t("calendar.expression")}
              <input
                value={d.expression}
                required
                maxLength={128}
                spellCheck={false}
                autoComplete="off"
                aria-describedby={id + "-syntax"}
                onChange={(e) => change({ expression: e.target.value })}
              />
            </label>
            <p id={id + "-syntax"} className="calendar-help">
              {t("calendar.syntax")}
            </p>
            <div className="calendar-actions">
              {[
                ["0 2 * * *", "daily"],
                ["0 9 * * 1-5", "weekdays"],
                ["0 * * * *", "hourly"],
              ].map(([expr, label]) => (
                <button key={expr} type="button" onClick={() => change({ expression: expr })}>
                  {t("calendar." + label)}
                </button>
              ))}
            </div>
            <label>
              {t("calendar.timezone")}
              <input
                value={d.timezone}
                required
                maxLength={64}
                list={id + "-zones"}
                autoComplete="off"
                spellCheck={false}
                aria-describedby={id + "-zone-hint"}
                onChange={(e) => change({ timezone: e.target.value })}
              />
            </label>
            <datalist id={id + "-zones"}>
              {[
                "UTC",
                "Asia/Shanghai",
                "Asia/Tokyo",
                "Asia/Singapore",
                "Europe/London",
                "Europe/Berlin",
                "America/New_York",
                "America/Los_Angeles",
                "Australia/Sydney",
              ].map((zone) => (
                <option key={zone} value={zone} />
              ))}
            </datalist>
            <p id={id + "-zone-hint"} className="calendar-help">
              {t("calendar.timezoneHint")}
            </p>
            <label>
              {t("calendar.misfire")}
              <select value={d.misfire} onChange={(e) => change({ misfire: e.target.value })}>
                <option value="coalesce">{t("calendar.coalesce")}</option>
                <option value="skip">{t("calendar.skip")}</option>
              </select>
            </label>
            <label>
              {t("calendar.grace")}
              <input
                type="number"
                min={1}
                max={3600}
                required
                value={d.grace}
                onChange={(e) => change({ grace: Number(e.target.value) })}
              />
            </label>
            <label>
              {t("calendar.fold")}
              <select value={d.fold} onChange={(e) => change({ fold: e.target.value })}>
                <option value="once">{t("calendar.foldOnce")}</option>
                <option value="both">{t("calendar.foldBoth")}</option>
              </select>
            </label>
            <p className="calendar-help">{t("calendar.dstHint")}</p>
          </>
        )}
        {["cron", "interval"].includes(d.kind) && (
          <>
            <label>
              {t("calendar.endAt")}
              <input
                type="datetime-local"
                step="1"
                value={d.endAt}
                onChange={(e) => change({ endAt: e.target.value })}
              />
            </label>
            <p className="calendar-help">{t("calendar.windowHint")}</p>
          </>
        )}
      </fieldset>
      {d.kind !== "batch" && (
        <div className="calendar-preview">
          <button type="button" disabled={busy} onClick={() => void calculate()}>
            {t(busy ? "calendar.previewing" : "calendar.preview")}
          </button>
          <p className="calendar-help">{t("calendar.previewHint")}</p>
          {error === key && <p role="alert">{t("calendar.invalid")}</p>}
          {preview?.key === key && (
            <>
              <h4>{t("calendar.previewTitle")}</h4>
              <div className="calendar-scroll">
                <table>
                  <thead>
                    <tr>
                      <th scope="col">{t("calendar.utc")}</th>
                      <th scope="col">{t("calendar.local")}</th>
                    </tr>
                  </thead>
                  <tbody>
                    {preview.data.occurrences.map((v) => (
                      <tr key={v.at}>
                        <td>
                          <time dateTime={v.at}>{v.at}</time>
                        </td>
                        <td>{v.local}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </>
          )}
        </div>
      )}
    </>
  );
}
