import { useCallback, useEffect, useRef, useState } from "react";
import { useTranslation } from "react-i18next";
import { useAuth } from "../auth/AuthContext";
import "../i18n/locales/features/reports/register";
import "./rotation-plans.css";
import "./reports.css";
type Source = {
  id: string;
  scope: string;
  mode: string;
  status: string;
  captured_at: string;
  retained?: number;
  matched?: number;
  oldest?: string;
  newest?: string;
  states: { state: string; count: number }[];
  days: { date: string; count: number }[];
};
type Report = {
  generated_at: string;
  partial: boolean;
  query: { from: string; to: string };
  sources: Source[];
};
type Caps = { export: boolean; audit_all: boolean };
type Receipt = {
  id: string;
  owner_id: string;
  at: string;
  sha256: string;
  bytes: number;
  partial: boolean;
};
type Filters = { from: string; to: string; source: string; platform: boolean };
const sourceIDs = [
  "assets",
  "accounts",
  "terminal_sessions",
  "rdp_sessions",
  "database_queries",
  "ssh_jobs",
  "rotation_runs",
  "account_risks",
  "monitor_alerts",
  "access_tickets",
  "agent_alerts",
  "file_transfers",
];
const local = (d: Date) =>
  new Date(d.getTime() - d.getTimezoneOffset() * 60_000).toISOString().slice(0, 19);
const period = (days: number): Filters => ({
  from: local(new Date(Date.now() - days * 86_400_000)),
  to: local(new Date()),
  source: "",
  platform: false,
});
class ReportError extends Error {
  constructor(public code: string) {
    super(code);
  }
}
function query(f: Filters) {
  const from = new Date(f.from),
    to = new Date(f.to);
  if (!Number.isFinite(from.getTime()) || !Number.isFinite(to.getTime()) || from >= to)
    throw new ReportError("invalid");
  return new URLSearchParams({
    from: from.toISOString(),
    to: to.toISOString(),
    include_platform: String(f.platform),
    ...(f.source ? { sources: f.source } : {}),
  }).toString();
}
export default function ReportsPage() {
  const { t, i18n } = useTranslation(),
    { accessToken } = useAuth();
  const [filters, setFilters] = useState(() => period(7)),
    [draft, setDraft] = useState(() => period(7)),
    [version, setVersion] = useState(0);
  const [report, setReport] = useState<Report | null>(null),
    [caps, setCaps] = useState<Caps>({ export: false, audit_all: false }),
    [trend, setTrend] = useState("ssh_jobs"),
    [partial, setPartial] = useState(false);
  const [history, setHistory] = useState<Receipt[]>([]),
    [offset, setOffset] = useState(0),
    [total, setTotal] = useState(0),
    [all, setAll] = useState(false);
  const [busy, setBusy] = useState(false),
    [error, setError] = useState(""),
    [notice, setNotice] = useState("");
  const life = useRef<AbortController | null>(null),
    working = useRef(false),
    generation = useRef(0);
  const headers = useCallback(
    (): Record<string, string> => (accessToken ? { Authorization: `Bearer ${accessToken}` } : {}),
    [accessToken],
  );
  const request = useCallback(
    async <T,>(path: string, signal: AbortSignal): Promise<T> => {
      const r = await fetch("/api/v1/reports/" + path, {
        headers: headers(),
        signal: AbortSignal.any([signal, AbortSignal.timeout(30_000)]),
      });
      if (!r.ok)
        throw new ReportError(
          r.status === 400
            ? "invalid"
            : r.status === 401 || r.status === 403
              ? "denied"
              : "unavailable",
        );
      return r.json() as Promise<T>;
    },
    [headers],
  );
  useEffect(() => {
    const controller = new AbortController();
    life.current = controller;
    return () => controller.abort();
  }, []);
  useEffect(() => {
    const controller = new AbortController();
    let running = false;
    const load = async () => {
      if (running || working.current || document.visibilityState === "hidden") return;
      running = true;
      const serial = ++generation.current;
      try {
        const c = await request<Caps>("capabilities", controller.signal);
        if (controller.signal.aborted) return;
        setCaps(c);
        if (all && !c.audit_all) {
          setAll(false);
          setOffset(0);
          setHistory([]);
          setReport(null);
          return;
        }
        const [r, h] = await Promise.all([
          request<Report>("overview?" + query(filters), controller.signal),
          request<{ results: Receipt[]; total: number }>(
            `exports?offset=${offset}&limit=20&scope=${all ? "all" : "mine"}`,
            controller.signal,
          ),
        ]);
        if (!controller.signal.aborted && serial === generation.current) {
          setReport(r);
          setHistory(h.results);
          setTotal(h.total);
          setError("");
        }
      } catch (e) {
        if (!controller.signal.aborted) {
          setReport(null);
          setHistory([]);
          setTotal(0);
          setError(e instanceof ReportError ? e.code : "unavailable");
        }
      } finally {
        running = false;
      }
    };
    void load();
    const timer = setInterval(() => void load(), 30_000);
    document.addEventListener("visibilitychange", load);
    return () => {
      controller.abort();
      clearInterval(timer);
      document.removeEventListener("visibilitychange", load);
    };
  }, [filters, version, offset, all, request]);
  const download = async () => {
    if (working.current || !life.current) return;
    working.current = true;
    setBusy(true);
    setError("");
    setNotice("");
    try {
      const r = await fetch(
        "/api/v1/reports/export.csv?" + query(filters) + (partial ? "&allow_partial=true" : ""),
        {
          headers: headers(),
          signal: AbortSignal.any([life.current.signal, AbortSignal.timeout(30_000)]),
        },
      );
      if (!r.ok)
        throw new ReportError(
          r.status === 409
            ? "partial"
            : r.status === 401 || r.status === 403
              ? "denied"
              : r.status === 400
                ? "invalid"
                : "unavailable",
        );
      if (!r.headers.get("Content-Type")?.startsWith("text/csv"))
        throw new ReportError("integrity");
      const blob = await r.blob();
      if (blob.size > 4 * 1024 * 1024) throw new ReportError("integrity");
      const id = r.headers.get("X-JMS-Report-ID"),
        expected = r.headers.get("X-JMS-Report-SHA256");
      const sum = await crypto.subtle.digest("SHA-256", await blob.arrayBuffer());
      const actual = Array.from(new Uint8Array(sum), (v) => v.toString(16).padStart(2, "0")).join(
        "",
      );
      if (!id || !/^report-export-[a-f0-9]{32}$/.test(id) || actual !== expected)
        throw new ReportError("integrity");
      if (!life.current.signal.aborted) {
        const url = URL.createObjectURL(blob),
          a = document.createElement("a");
        a.href = url;
        a.download = "operations-report.csv";
        a.click();
        setTimeout(() => URL.revokeObjectURL(url), 1000);
        setNotice(id);
        setVersion((v) => v + 1);
      }
    } catch (e) {
      if (!life.current?.signal.aborted)
        setError(e instanceof ReportError ? e.code : "unavailable");
    } finally {
      working.current = false;
      if (!life.current?.signal.aborted) setBusy(false);
    }
  };
  const date = (v?: string) =>
    v ? new Date(v).toLocaleString(i18n.language) : t("reports.missing");
  const sourceName = (id: string) => t(`reports.sources.${id}`);
  const selected =
    report?.sources.find((s) => s.id === trend) || report?.sources.find((s) => s.days.length > 0);
  const points = selected?.days || [],
    max = Math.max(1, ...points.map((p) => p.count)),
    coords = points
      .map(
        (p, i) =>
          `${42 + (i / Math.max(1, points.length - 1)) * 630},${178 - (p.count / max) * 150}`,
      )
      .join(" ");
  const state = (s: string) =>
    t(`reports.stateNames.${s}`, { defaultValue: t("reports.otherState", { value: s }) });
  return (
    <section className="rotation-page reports-page" aria-busy={busy}>
      <header>
        <div>
          <h1>{t("reports.title")}</h1>
          <p>{t("reports.hint")}</p>
        </div>
        <div className="rotation-actions">
          <button type="button" disabled={busy} onClick={() => setVersion((v) => v + 1)}>
            {t("reports.refresh")}
          </button>
          <button
            type="button"
            disabled={busy || !caps.export}
            aria-describedby={!caps.export ? "report-export-permission" : undefined}
            onClick={() => void download()}
          >
            {t("reports.export")}
          </button>
        </div>
      </header>
      {!caps.export && <p id="report-export-permission">{t("reports.exportDenied")}</p>}
      <p role="status">{notice && t("reports.downloaded", { id: notice })}</p>
      {error && (
        <p role="alert" id="report-error">
          {t(`reports.errors.${error}`)}
        </p>
      )}
      <form
        className="report-filters"
        onSubmit={(e) => {
          e.preventDefault();
          setFilters({ ...draft });
          setNotice("");
          setVersion((v) => v + 1);
        }}
      >
        <label>
          {t("reports.from")}
          <input
            type="datetime-local"
            step="1"
            required
            aria-invalid={error === "invalid"}
            aria-describedby={error === "invalid" ? "report-error" : undefined}
            value={draft.from}
            onChange={(e) => setDraft({ ...draft, from: e.target.value })}
          />
        </label>
        <label>
          {t("reports.to")}
          <input
            type="datetime-local"
            step="1"
            required
            aria-invalid={error === "invalid"}
            aria-describedby={error === "invalid" ? "report-error" : undefined}
            value={draft.to}
            onChange={(e) => setDraft({ ...draft, to: e.target.value })}
          />
        </label>
        <label>
          {t("reports.source")}
          <select
            value={draft.source}
            onChange={(e) => setDraft({ ...draft, source: e.target.value })}
          >
            <option value="">{t("reports.allSources")}</option>
            {[...sourceIDs, ...(draft.platform ? ["platform_logins", "platform_users"] : [])].map(
              (id) => (
                <option key={id} value={id}>
                  {sourceName(id)}
                </option>
              ),
            )}
          </select>
        </label>
        <button type="submit" disabled={busy}>
          {t("reports.apply")}
        </button>
        <label className="report-check">
          <input
            type="checkbox"
            checked={draft.platform}
            onChange={(e) =>
              setDraft({
                ...draft,
                platform: e.target.checked,
                source:
                  !e.target.checked && draft.source.startsWith("platform_") ? "" : draft.source,
              })
            }
          />
          {t("reports.platform")}
        </label>
      </form>
      <div className="rotation-actions">
        {[7, 30, 90].map((days) => (
          <button
            key={days}
            type="button"
            disabled={busy}
            onClick={() => {
              const f = { ...period(days), source: filters.source, platform: filters.platform };
              setDraft(f);
              setFilters(f);
            }}
          >
            {t("reports.days", { count: days })}
          </button>
        ))}
      </div>
      <p>{t("reports.semantics")}</p>
      <p>{t("reports.retention")}</p>
      {filters.platform && <p>{t("reports.platformHint")}</p>}
      <label className="report-check">
        <input type="checkbox" checked={partial} onChange={(e) => setPartial(e.target.checked)} />
        {t("reports.allowPartial")}
      </label>
      {report?.partial && <p role="alert">{t("reports.partial")}</p>}
      {report && (
        <>
          <p>
            {t("reports.generated")}:{" "}
            <time dateTime={report.generated_at}>{date(report.generated_at)}</time> ·{" "}
            {date(report.query.from)} – {date(report.query.to)}
          </p>
          <div className="report-cards">
            {report.sources
              .filter((s) =>
                [
                  "assets",
                  "accounts",
                  "terminal_sessions",
                  "ssh_jobs",
                  "monitor_alerts",
                  "account_risks",
                ].includes(s.id),
              )
              .map((s) => (
                <article key={s.id} className="report-card">
                  <h2>{sourceName(s.id)}</h2>
                  <strong>
                    {s.matched === undefined
                      ? t("reports.missing")
                      : s.matched.toLocaleString(i18n.language)}
                  </strong>
                  <small>{t(`reports.modes.${s.mode}`)}</small>
                  <small>
                    {t(`reports.scopes.${s.scope}`)} · {t(`reports.statuses.${s.status}`)}
                  </small>
                </article>
              ))}
          </div>
          <h2>{t("reports.trend")}</h2>
          <label>
            {t("reports.trendSource")}
            <select value={selected?.id || ""} onChange={(e) => setTrend(e.target.value)}>
              {report.sources
                .filter((s) => s.days.length > 0)
                .map((s) => (
                  <option key={s.id} value={s.id}>
                    {sourceName(s.id)}
                  </option>
                ))}
            </select>
          </label>
          <p>{t("reports.trendHint")}</p>
          {points.length > 0 ? (
            <figure className="report-chart">
              <figcaption>{sourceName(selected!.id)}</figcaption>
              <svg
                role="img"
                aria-label={t("reports.trend") + " · " + sourceName(selected!.id)}
                viewBox="0 0 700 210"
              >
                <title>{t("reports.trend") + " · " + sourceName(selected!.id)}</title>
                <line x1="42" y1="178" x2="672" y2="178" stroke="currentColor" opacity=".3" />
                <text x="4" y="178">
                  0
                </text>
                <text x="4" y="28">
                  {max}
                </text>
                <polyline points={coords} fill="none" stroke="#79bfff" strokeWidth="2" />
                <text x="42" y="204">
                  {points[0].date}
                </text>
                <text x="672" y="204" textAnchor="end">
                  {points[points.length - 1].date}
                </text>
              </svg>
              <details>
                <summary>{t("reports.table")}</summary>
                <table>
                  <thead>
                    <tr>
                      <th scope="col">{t("reports.day")}</th>
                      <th scope="col">{t("reports.count")}</th>
                    </tr>
                  </thead>
                  <tbody>
                    {points.map((p) => (
                      <tr key={p.date}>
                        <td>{p.date}</td>
                        <td>{p.count}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </details>
            </figure>
          ) : (
            <p>{t("reports.noTrend")}</p>
          )}
          <div className="report-table">
            <table aria-label={t("reports.source")}>
              <thead>
                <tr>
                  {[
                    "source",
                    "scope",
                    "mode",
                    "status",
                    "matched",
                    "retained",
                    "captured",
                    "states",
                  ].map((k) => (
                    <th key={k} scope="col">
                      {t(`reports.${k}`)}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {report.sources.map((s) => (
                  <tr key={s.id}>
                    <th scope="row">{sourceName(s.id)}</th>
                    <td>{t(`reports.scopes.${s.scope}`)}</td>
                    <td>{t(`reports.modes.${s.mode}`)}</td>
                    <td>{t(`reports.statuses.${s.status}`)}</td>
                    <td>{s.matched ?? t("reports.missing")}</td>
                    <td>{s.retained ?? t("reports.missing")}</td>
                    <td>
                      {date(s.captured_at)}
                      <details>
                        <summary>{t("reports.oldest")}</summary>
                        <p>{date(s.oldest)}</p>
                        <p>
                          {t("reports.newest")}: {date(s.newest)}
                        </p>
                      </details>
                    </td>
                    <td>
                      {s.states.map((v) => (
                        <div key={v.state}>
                          {state(v.state)}: {v.count}
                        </div>
                      ))}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </>
      )}
      <h2>{t("reports.exports")}</h2>
      {caps.audit_all && (
        <label className="report-check">
          <input
            type="checkbox"
            checked={all}
            onChange={(e) => {
              setAll(e.target.checked);
              setOffset(0);
            }}
          />
          {t("reports.auditAll")}
        </label>
      )}
      <div className="report-table">
        <table aria-label={t("reports.exports")}>
          <thead>
            <tr>
              {["captured", "receipt", "owner", "bytes", "digest"].map((k) => (
                <th key={k} scope="col">
                  {t(`reports.${k}`)}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {history.map((r) => (
              <tr key={r.id}>
                <td>{date(r.at)}</td>
                <td>
                  <code>{r.id}</code>
                  {r.partial && <p>{t("reports.partial")}</p>}
                </td>
                <td>
                  <code>{r.owner_id}</code>
                </td>
                <td>{r.bytes}</td>
                <td>
                  <code>{r.sha256}</code>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      {!history.length && <p>{t("reports.empty")}</p>}
      <div className="rotation-actions">
        <button
          type="button"
          disabled={busy || offset === 0}
          onClick={() => setOffset((v) => Math.max(0, v - 20))}
        >
          {t("reports.previous")}
        </button>
        <span>
          {t("reports.pagination", {
            from: total ? offset + 1 : 0,
            to: Math.min(total, offset + 20),
            total,
          })}
        </span>
        <button
          type="button"
          disabled={busy || offset + 20 >= total}
          onClick={() => setOffset((v) => v + 20)}
        >
          {t("reports.next")}
        </button>
      </div>
    </section>
  );
}
