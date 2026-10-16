import { useCallback, useEffect, useRef, useState, type FormEvent } from "react";
import { useTranslation } from "react-i18next";
import "./database.css";

export type DatabaseResult = {
  missing_cells?: [number, number][];
  result_sets?: { columns: { name: string }[]; rows: (string | null)[][] }[];
  columns: { name: string; type_oid: number }[];
  rows: (string | null)[][];
  affected_rows: number;
  affected_rows_known?: boolean;
  transaction: string;
  duration_ms: number;
  error_code?: string;
  sqlstate?: string;
  database_code?: string;
  truncated: boolean;
};
export type DatabaseQuery = {
  protocol?: string;
  id: string;
  asset_name: string;
  operator: string;
  sql: string;
  parameter_count: number;
  state: string;
  created_at: string;
  rule_name?: string;
  reviewed_by?: string;
  result_available: boolean;
  summary: DatabaseResult;
  result?: DatabaseResult;
};
const pending = (state: string) => ["queued", "running", "awaiting_review"].includes(state);

export function DatabaseResultView({ job }: { job: DatabaseQuery }) {
  const { t } = useTranslation();
  const result = job.result ?? job.summary;
  const missing = new Set((result.missing_cells ?? []).map(([row, column]) => `${row}:${column}`));
  const tables = [
    { columns: result.columns, rows: result.rows },
    ...(result.result_sets ?? []),
  ].filter((table) => table.columns?.length > 0);
  return (
    <div className="database-result" aria-live="polite">
      <p>
        <strong>{t(`database.states.${job.state}`)}</strong> ·{" "}
        {t(`database.transactions.${result.transaction || "not_started"}`)} · {result.duration_ms}{" "}
        ms ·{" "}
        {result.affected_rows_known === false
          ? t("database.affectedUnknown")
          : t("database.affected", { count: result.affected_rows })}
      </p>
      {job.rule_name && <p>{t("database.rule", { name: job.rule_name })}</p>}
      {result.error_code && (
        <p role="alert">
          {t(`database.errors.${result.error_code}`, { defaultValue: t("database.failed") })}
          {result.sqlstate ? ` (${result.sqlstate})` : ""}
          {result.database_code && ` (${t("database.nativeCode", { code: result.database_code })})`}
        </p>
      )}
      {result.truncated && <p>{t("database.truncated")}</p>}
      {job.result &&
        tables.map((table, index) => (
          <div className="database-table" key={index}>
            {tables.length > 1 && <p>{t("database.resultSet", { number: index + 1 })}</p>}
            <table>
              <thead>
                <tr>
                  {table.columns.map((c, i) => (
                    <th key={i}>{c.name}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {table.rows?.map((row, i) => (
                  <tr key={i}>
                    {row.map((cell, n) => (
                      <td key={n}>
                        {index === 0 && missing.has(`${i}:${n}`) ? (
                          <em>{t("database.missing")}</em>
                        ) : cell === null ? (
                          <em>NULL</em>
                        ) : (
                          cell
                        )}
                      </td>
                    ))}
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ))}
      {!pending(job.state) && !job.result && <small>{t("database.resultUnavailable")}</small>}
    </div>
  );
}

export default function DatabaseConsoleDialog({
  assetId,
  assetName,
  protocol = "postgresql",
  accessToken,
  onClose,
}: {
  assetId: string;
  assetName: string;
  protocol?: string;
  accessToken: string;
  onClose: () => void;
}) {
  const { t } = useTranslation();
  const [session, setSession] = useState<{
    session_token: string;
    read_only: boolean;
    database: string;
  } | null>(null);
  const [review, setReview] = useState("");
  const mysqlProtocol = protocol === "mysql" || protocol === "mariadb";
  const sqlServerProtocol = protocol === "sqlserver";
  const clickHouseProtocol = protocol === "clickhouse";
  const redisProtocol = protocol === "redis";
  const noSqlProtocol = redisProtocol || protocol === "mongodb";
  const paramsKey = mysqlProtocol
    ? "database.mysqlParams"
    : sqlServerProtocol
      ? "database.sqlServerParams"
      : clickHouseProtocol
        ? "database.clickHouseParams"
        : "database.params";
  const engine =
    protocol === "mysql"
      ? "MySQL"
      : protocol === "mariadb"
        ? "MariaDB"
        : sqlServerProtocol
          ? "SQL Server"
          : clickHouseProtocol
            ? "ClickHouse"
            : redisProtocol
              ? "Redis"
              : protocol === "mongodb"
                ? "MongoDB"
                : "PostgreSQL";
  const [sql, setSQL] = useState(
    mysqlProtocol
      ? "SELECT DATABASE(), CURRENT_USER()"
      : sqlServerProtocol
        ? "SELECT DB_NAME() AS database_name, CURRENT_USER AS account"
        : clickHouseProtocol
          ? "SELECT currentDatabase(), currentUser()"
          : redisProtocol
            ? '["PING"]'
            : protocol === "mongodb"
              ? '{"ping":1}'
              : "SELECT current_database(), current_user",
  );
  const [params, setParams] = useState("[]");
  const [readOnly, setReadOnly] = useState(true);
  const [rowLimit, setRowLimit] = useState(500);
  const [timeout, setTimeoutValue] = useState(30);
  const [busy, setBusy] = useState(false);
  const [failed, setFailed] = useState("");
  const [job, setJob] = useState<DatabaseQuery | null>(null);
  const [history, setHistory] = useState<DatabaseQuery[]>([]);
  const token = useRef("");
  const alive = useRef(true);
  const generation = useRef(0);
  const request = useCallback(
    (path: string, init?: RequestInit) => {
      const headers = new Headers(init?.headers);
      if (accessToken) headers.set("Authorization", `Bearer ${accessToken}`);
      if (token.current && !headers.has("X-JMS-DB-SESSION"))
        headers.set("X-JMS-DB-SESSION", token.current);
      return fetch(path, { ...init, headers });
    },
    [accessToken],
  );
  const connect = useCallback(async () => {
    const attempt = ++generation.current;
    setBusy(true);
    setFailed("");
    try {
      const response = await request(`/api/v1/assets/${assetId}/database-sessions`, {
        method: "POST",
      });
      const data = await response.json();
      if (response.status === 202) {
        if (attempt !== generation.current || !alive.current) return;
        setReview(data.review_id);
        return;
      }
      if (!response.ok) throw new Error(data.detail);
      if (!alive.current || attempt !== generation.current) {
        await request("/api/v1/database-sessions", {
          method: "DELETE",
          headers: { "X-JMS-DB-SESSION": data.session_token },
        });
        return;
      }
      token.current = data.session_token;
      setSession(data);
      setReview("");
    } catch {
      if (alive.current) setFailed("database.connectFailed");
    } finally {
      if (alive.current) setBusy(false);
    }
  }, [assetId, request]);
  const loadHistory = useCallback(async () => {
    try {
      const r = await request(`/api/v1/database-queries?asset_id=${assetId}`);
      if (!r.ok) return;
      const data = await r.json();
      if (alive.current) setHistory(data.results);
    } catch {
      /* polling retries */
    }
  }, [assetId, request]);
  const closeSession = useCallback(() => {
    alive.current = false;
    generation.current++;
    if (token.current) {
      void request("/api/v1/database-sessions", { method: "DELETE", keepalive: true }).catch(
        () => undefined,
      );
      token.current = "";
    }
  }, [request]);
  useEffect(() => {
    alive.current = true;
    // Initialize the server-owned connection and query history for this asset.
    // eslint-disable-next-line react/set-state-in-effect
    void connect();
    void loadHistory();
    return closeSession;
  }, [connect, loadHistory, closeSession]);
  useEffect(() => {
    if (!review) return;
    const timer = window.setInterval(
      () =>
        void (async () => {
          try {
            const r = await request(`/api/v1/access-reviews/${review}`);
            if (!r.ok) return;
            const data = await r.json();
            if (!alive.current) return;
            if (data.state === "approved") {
              setReview("");
              await connect();
            } else if (data.state !== "pending") {
              setReview("");
              setFailed("database.reviewDenied");
            }
          } catch {
            /* polling retries */
          }
        })(),
      1500,
    );
    return () => window.clearInterval(timer);
  }, [review, request, connect]);
  const jobID = job?.id,
    jobState = job?.state;
  useEffect(() => {
    if (!jobID || !jobState || !pending(jobState)) return;
    const id = jobID;
    const timer = window.setInterval(
      () =>
        void (async () => {
          try {
            const r = await request(`/api/v1/database-queries/${id}`);
            if (!r.ok) {
              if (alive.current) setFailed("database.failed");
              return;
            }
            const next = await r.json();
            if (alive.current) {
              setJob(next);
              if (!pending(next.state)) void loadHistory();
            }
          } catch {
            /* polling retries */
          }
        })(),
      500,
    );
    return () => window.clearInterval(timer);
  }, [jobID, jobState, request, loadHistory]);
  async function submit(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    setFailed("");
    try {
      const parameters: unknown = JSON.parse(params);
      if (!Array.isArray(parameters)) throw new Error();
      const r = await request(`/api/v1/assets/${assetId}/database-queries`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          sql,
          parameters,
          read_only: readOnly,
          row_limit: rowLimit,
          timeout_seconds: timeout,
          request_id: crypto.randomUUID(),
        }),
      });
      if (!r.ok) throw new Error();
      setJob(await r.json());
      void loadHistory();
    } catch {
      setFailed("database.submitFailed");
    } finally {
      setBusy(false);
    }
  }
  async function inspect(id: string) {
    try {
      const r = await request(`/api/v1/database-queries/${id}`);
      if (!r.ok) throw new Error();
      setJob(await r.json());
    } catch {
      setFailed("database.failed");
    }
  }
  return (
    <div className="asset-modal-backdrop">
      <section
        className="asset-modal database-console"
        role="dialog"
        aria-modal="true"
        aria-label={t("database.consoleTitle", { name: assetName, engine })}
      >
        <div className="database-heading">
          <h2>{t("database.consoleTitle", { name: assetName, engine })}</h2>
          <button type="button" className="button-secondary" onClick={onClose}>
            {t("database.close")}
          </button>
        </div>
        <p>{t(noSqlProtocol ? "database.noSqlSessionHint" : "database.sessionHint")}</p>
        {!session && (
          <div>
            <p>
              {review
                ? t("database.reviewPending")
                : busy
                  ? t("database.connecting")
                  : t("database.disconnected")}
            </p>
            {!busy && !review && (
              <button className="button-primary" onClick={() => void connect()}>
                {t("database.reconnect")}
              </button>
            )}
          </div>
        )}
        {failed && (
          <p role="alert" className="asset-error">
            {t(failed)}
          </p>
        )}
        {session && (
          <form onSubmit={(e) => void submit(e)}>
            <label>
              <span>{t(noSqlProtocol ? "database.jsonCommand" : "database.sql")}</span>
              <textarea
                aria-label={t(noSqlProtocol ? "database.jsonCommand" : "database.sql")}
                rows={6}
                required
                maxLength={65536}
                value={sql}
                onChange={(e) => setSQL(e.target.value)}
                spellCheck={false}
              />
            </label>
            <details>
              <summary>{t("database.options")}</summary>
              <div className="database-options">
                {!noSqlProtocol && (
                  <label>
                    <span>{t(paramsKey)}</span>
                    <textarea
                      aria-label={t(paramsKey)}
                      rows={2}
                      maxLength={131072}
                      value={params}
                      onChange={(e) => setParams(e.target.value)}
                      spellCheck={false}
                    />
                  </label>
                )}
                <label>
                  <span>{t("database.rowLimit")}</span>
                  <input
                    type="number"
                    min={1}
                    max={10000}
                    value={rowLimit}
                    onChange={(e) => setRowLimit(Number(e.target.value))}
                  />
                </label>
                <label>
                  <span>{t("database.timeout")}</span>
                  <input
                    type="number"
                    min={1}
                    max={300}
                    value={timeout}
                    onChange={(e) => setTimeoutValue(Number(e.target.value))}
                  />
                </label>
                <label>
                  <input
                    type="checkbox"
                    checked={readOnly || session.read_only}
                    disabled={session.read_only}
                    onChange={(e) => setReadOnly(e.target.checked)}
                  />
                  {t(
                    noSqlProtocol
                      ? "database.readOnlyCommand"
                      : clickHouseProtocol
                        ? "database.readOnlyQuery"
                        : "database.readOnly",
                  )}
                </label>
              </div>
            </details>
            {noSqlProtocol && (
              <>
                <p role="status">
                  {t(
                    readOnly || session.read_only
                      ? "database.noSqlReadHint"
                      : "database.noSqlWriteHint",
                  )}
                </p>
                <div className="database-heading">
                  <button
                    type="button"
                    className="button-secondary"
                    onClick={() =>
                      setSQL(
                        redisProtocol
                          ? '["SCAN","0","COUNT","100"]'
                          : '{"listCollections":1,"nameOnly":true}',
                      )
                    }
                  >
                    {t(redisProtocol ? "database.browseKeys" : "database.browseCollections")}
                  </button>
                  <button
                    type="button"
                    className="button-secondary"
                    onClick={() => setSQL(redisProtocol ? '["PING"]' : '{"ping":1}')}
                  >
                    {t("database.ping")}
                  </button>
                </div>
              </>
            )}
            {mysqlProtocol && !readOnly && !session.read_only && (
              <p role="status">{t("database.mysqlWriteHint")}</p>
            )}
            {clickHouseProtocol && (
              <p role="status">
                {t(
                  readOnly || session.read_only
                    ? "database.clickHouseReadHint"
                    : "database.clickHouseWriteHint",
                )}
              </p>
            )}
            {sqlServerProtocol && (
              <p role="status">
                {t(
                  readOnly || session.read_only
                    ? "database.sqlServerReadHint"
                    : "database.sqlServerWriteHint",
                )}
              </p>
            )}
            <div className="database-heading">
              <button
                type="submit"
                className="button-primary"
                disabled={busy || Boolean(job && pending(job.state))}
              >
                {t(noSqlProtocol ? "database.runCommand" : "database.run")}
              </button>
              {job && pending(job.state) && (
                <button
                  type="button"
                  className="button-secondary"
                  onClick={() =>
                    void request(`/api/v1/database-queries/${job.id}/cancel`, {
                      method: "POST",
                    }).then((r) => {
                      if (!r.ok) setFailed("database.failed");
                    })
                  }
                >
                  {t("database.cancel")}
                </button>
              )}
            </div>
          </form>
        )}
        {job && <DatabaseResultView job={job} />}
        <details>
          <summary>{t("database.history")}</summary>
          <p>{t("database.auditHint")}</p>
          {history.map((j) => (
            <button
              type="button"
              className="database-history"
              key={j.id}
              onClick={() => void inspect(j.id)}
            >
              <time>{new Date(j.created_at).toLocaleString()}</time> ·{" "}
              {t(`database.states.${j.state}`)}
              <code>{j.sql}</code>
            </button>
          ))}
        </details>
      </section>
    </div>
  );
}
