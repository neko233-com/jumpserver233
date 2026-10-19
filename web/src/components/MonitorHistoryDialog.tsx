import { useCallback, useEffect, useId, useMemo, useRef, useState } from "react";
import { useTranslation } from "react-i18next";
import "../i18n/locales/features/monitor-history/register";
import "./MonitorHistoryDialog.css";

type Stat = { mean: number; min: number; max: number; samples: number };
type Point = {
  at: string;
  last_sample?: string;
  state: string;
  samples: number;
  online: number;
  offline: number;
  values: Record<string, Stat>;
};
type History = {
  from: string;
  to: string;
  step_seconds: number;
  resolution: string;
  results: Point[];
  health: { error_code?: string; prune_pending: boolean };
};
const metrics = [
  "cpu_percent",
  "memory_percent",
  "disk_percent",
  "latency_ms",
  "network_rx_bps",
  "network_tx_bps",
] as const;
type Metric = (typeof metrics)[number];
type Props = {
  asset: { id: string; name: string };
  request: (url: string, init?: RequestInit) => Promise<Response>;
  onClose: () => void;
};

function Chart({
  points,
  metric,
  selected,
  label,
}: {
  points: Point[];
  metric: Metric;
  selected: number;
  label: string;
}) {
  const { t, i18n } = useTranslation();
  const percent = metric.endsWith("percent");
  const geometry = useMemo(() => {
    const maximum = percent ? 100 : Math.max(1, ...points.map((p) => p.values[metric]?.max ?? 0));
    const x = (i: number) => 8 + (i / Math.max(1, points.length - 1)) * 584;
    const y = (value: number) => 116 - (value / maximum) * 108;
    const path = points
      .map((p, i) => {
        const value = p.values[metric]?.mean;
        if (value === undefined) return "";
        const connected = i > 0 && points[i - 1].values[metric]?.mean !== undefined;
        return `${connected ? "L" : "M"}${x(i).toFixed(2)},${y(value).toFixed(2)}`;
      })
      .join(" ");
    return { maximum, x, y, path };
  }, [metric, percent, points]);
  const value = points[selected]?.values[metric]?.mean;
  return (
    <figure className="monitor-history-chart">
      <figcaption>
        <strong>{label}</strong>
        <span>
          {value === undefined
            ? t("monitorHistory.missing")
            : new Intl.NumberFormat(i18n.language, { maximumFractionDigits: 2 }).format(value)}{" "}
          {t(
            `monitorHistory.units.${percent ? "percent" : metric === "latency_ms" ? "latency" : "rate"}`,
          )}
        </span>
      </figcaption>
      <div className="monitor-history-plot">
        <div className="monitor-history-axis" aria-hidden="true">
          <span>
            {new Intl.NumberFormat(i18n.language, {
              maximumFractionDigits: 1,
              notation: "compact",
            }).format(geometry.maximum)}
          </span>
          <span>0</span>
        </div>
        <svg viewBox="0 0 600 124" role="img" aria-label={label}>
          <path className="monitor-history-grid" d="M8,8H592 M8,62H592 M8,116H592" />
          <path className="monitor-history-line" d={geometry.path} />
          {selected >= 0 && (
            <path className="monitor-history-cursor" d={`M${geometry.x(selected)},8V116`} />
          )}
          {value !== undefined && (
            <circle
              className="monitor-history-dot"
              cx={geometry.x(selected)}
              cy={geometry.y(value)}
              r="3"
            />
          )}
        </svg>
      </div>
    </figure>
  );
}

export default function MonitorHistoryDialog({ asset, request, onClose }: Props) {
  const { t, i18n } = useTranslation();
  const dialog = useRef<HTMLDialogElement>(null),
    title = useId();
  const [hours, setHours] = useState(1),
    [refresh, setRefresh] = useState(0),
    [cursor, setCursor] = useState<number | null>(null);
  const [data, setData] = useState<History | null>(null),
    [loading, setLoading] = useState(true),
    [error, setError] = useState("");
  useEffect(() => {
    const previous = document.activeElement,
      element = dialog.current;
    element?.showModal();
    return () => {
      element?.close();
      if (previous instanceof HTMLElement && previous.isConnected)
        previous.focus({ preventScroll: true });
    };
  }, []);
  const load = useCallback(
    async (signal: AbortSignal) => {
      setLoading(true);
      setError("");
      setData(null);
      setCursor(null);
      const end = new Date(),
        start = new Date(end.getTime() - hours * 3600_000);
      const query = new URLSearchParams({
        from: start.toISOString(),
        to: end.toISOString(),
        step: hours > 24 ? "900" : "60",
      });
      try {
        const response = await request(
          `/api/v1/assets/${encodeURIComponent(asset.id)}/monitor-history?${query}`,
          { signal },
        );
        if (signal.aborted) return;
        if (!response.ok) {
          setError(
            response.status === 404 || response.status === 403 || response.status === 401
              ? "denied"
              : "unavailable",
          );
          return;
        }
        const result = (await response.json()) as History;
        if (!signal.aborted) setData(result);
      } catch {
        if (!signal.aborted) setError("unavailable");
      } finally {
        if (!signal.aborted) setLoading(false);
      }
    },
    [asset.id, hours, request],
  );
  useEffect(() => {
    const controller = new AbortController();
    // The initial range and explicit refresh fetch server-owned observations.
    // eslint-disable-next-line react/set-state-in-effect
    void load(controller.signal);
    return () => controller.abort();
  }, [load, refresh]);
  const points = data?.results ?? [],
    selected = Math.min(cursor ?? points.length - 1, points.length - 1),
    point = points[selected];
  const date = (value: string) =>
    new Intl.DateTimeFormat(i18n.language, {
      month: "2-digit",
      day: "2-digit",
      hour: "2-digit",
      minute: "2-digit",
      second: "2-digit",
      hour12: false,
    }).format(new Date(value));
  const number = (value: number | undefined) =>
    value === undefined
      ? t("monitorHistory.missing")
      : new Intl.NumberFormat(i18n.language, { maximumFractionDigits: 2 }).format(value);
  return (
    <dialog
      ref={dialog}
      className="monitor-history-dialog"
      aria-labelledby={title}
      onCancel={(event) => {
        event.preventDefault();
        onClose();
      }}
    >
      <header>
        <div>
          <h2 id={title}>{t("monitorHistory.title")}</h2>
          <p>{error === "denied" ? t("monitorHistory.unavailableHost") : asset.name}</p>
        </div>
        <button type="button" className="button-secondary" onClick={onClose}>
          {t("monitorHistory.close")}
        </button>
      </header>
      <div className="monitor-history-controls">
        <label>
          {t("monitorHistory.range")}
          <select value={hours} onChange={(event) => setHours(Number(event.target.value))}>
            {[1, 6, 24, 168].map((v) => (
              <option key={v} value={v}>
                {t(`monitorHistory.ranges.${v}`)}
              </option>
            ))}
          </select>
        </label>
        <button
          className="button-secondary"
          type="button"
          disabled={loading}
          onClick={() => setRefresh((value) => value + 1)}
        >
          {t("monitorHistory.refresh")}
        </button>
      </div>
      <p className="monitor-history-note">{t("monitorHistory.resolution")}</p>
      <section aria-busy={loading}>
        {loading && <p role="status">{t("monitorHistory.loading")}</p>}
        {error && <p role="alert">{t(`monitorHistory.${error}`)}</p>}
        {data && (
          <>
            {(data.health.error_code || data.health.prune_pending) && (
              <p role="alert">{t("monitorHistory.storageWarning")}</p>
            )}
            {!points.some((p) => p.samples > 0) && <p role="status">{t("monitorHistory.empty")}</p>}
            <div className="monitor-history-charts">
              {metrics.map((metric) => (
                <Chart
                  key={metric}
                  points={points}
                  metric={metric}
                  selected={selected}
                  label={t(`monitorHistory.metrics.${metric}`)}
                />
              ))}
            </div>
            {points.length > 0 && (
              <label className="monitor-history-picker">
                {t("monitorHistory.inspect")}
                <input
                  type="range"
                  min="0"
                  max={points.length - 1}
                  value={selected}
                  onChange={(event) => setCursor(Number(event.target.value))}
                  aria-valuetext={
                    point
                      ? `${date(point.at)} · ${t(`monitorHistory.states.${point.state}`)}`
                      : undefined
                  }
                />
              </label>
            )}
            <p className="monitor-history-period">
              {date(data.from)} → {date(data.to)} ·{" "}
              {t("monitorHistory.step", { seconds: data.step_seconds })}
            </p>
            {point && (
              <>
                <p>
                  <strong>{date(point.at)}</strong> · {t(`monitorHistory.states.${point.state}`)} ·{" "}
                  {t("monitorHistory.observations", {
                    online: point.online,
                    offline: point.offline,
                  })}
                </p>
                <div className="monitor-history-table">
                  <table>
                    <thead>
                      <tr>
                        <th scope="col">{t("monitorHistory.metric")}</th>
                        <th scope="col">{t("monitorHistory.mean")}</th>
                        <th scope="col">{t("monitorHistory.minimum")}</th>
                        <th scope="col">{t("monitorHistory.maximum")}</th>
                        <th scope="col">{t("monitorHistory.count")}</th>
                      </tr>
                    </thead>
                    <tbody>
                      {metrics.map((metric) => {
                        const stat = point.values[metric];
                        return (
                          <tr key={metric}>
                            <th scope="row">{t(`monitorHistory.metrics.${metric}`)}</th>
                            <td>{number(stat?.mean)}</td>
                            <td>{number(stat?.min)}</td>
                            <td>{number(stat?.max)}</td>
                            <td>{stat?.samples ?? 0}</td>
                          </tr>
                        );
                      })}
                    </tbody>
                  </table>
                </div>
              </>
            )}
          </>
        )}
      </section>
    </dialog>
  );
}
