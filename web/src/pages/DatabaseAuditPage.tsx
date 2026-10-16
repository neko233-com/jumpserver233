import { useCallback, useEffect, useState } from "react";
import { useTranslation } from "react-i18next";
import { useAuth } from "../auth/AuthContext";
import { usePermissions } from "../auth/usePermissions";
import { DatabaseResultView, type DatabaseQuery } from "../components/DatabaseConsoleDialog";

export default function DatabaseAuditPage() {
  const { t } = useTranslation();
  const { accessToken } = useAuth();
  const { allows } = usePermissions();
  const [rows, setRows] = useState<DatabaseQuery[]>([]);
  const [selected, setSelected] = useState<DatabaseQuery | null>(null);
  const [reviews, setReviews] = useState(false);
  const [failed, setFailed] = useState(false);
  const [busy, setBusy] = useState(false);
  const request = useCallback(
    (path: string, init?: RequestInit) => {
      const headers = new Headers(init?.headers);
      if (accessToken) headers.set("Authorization", `Bearer ${accessToken}`);
      return fetch(path, { ...init, headers });
    },
    [accessToken],
  );
  const load = useCallback(async () => {
    try {
      const r = await request(`/api/v1/database-queries${reviews ? "?pending_reviews=true" : ""}`);
      if (!r.ok) throw new Error();
      setRows((await r.json()).results);
      setFailed(false);
    } catch {
      setFailed(true);
    }
  }, [request, reviews]);
  useEffect(() => {
    // Synchronize with the server-owned audit/review queue.
    // eslint-disable-next-line react/set-state-in-effect
    void load();
    const timer = window.setInterval(() => void load(), 3000);
    return () => window.clearInterval(timer);
  }, [load]);
  async function action(id: string, approve: boolean) {
    setBusy(true);
    try {
      const r = await request(`/api/v1/database-queries/${id}/review`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ approve }),
      });
      if (!r.ok) throw new Error();
      setSelected(null);
      await load();
    } catch {
      setFailed(true);
    } finally {
      setBusy(false);
    }
  }
  return (
    <section className="database-audit">
      <h1>{t("database.auditTitle")}</h1>
      <p>{t("database.auditHint")}</p>
      {allows("reviews.command.manage") && (
        <label>
          <input
            type="checkbox"
            checked={reviews}
            onChange={(e) => {
              setReviews(e.target.checked);
              setSelected(null);
            }}
          />
          {t("database.pendingOnly")}
        </label>
      )}
      {failed && <p role="alert">{t("database.failed")}</p>}
      <div className="database-table">
        <table>
          <thead>
            <tr>
              <th>{t("database.time")}</th>
              <th>{t("assets.name")}</th>
              <th>{t("database.operator")}</th>
              <th>{t("database.request")}</th>
              <th>{t("database.state")}</th>
              <th>{t("database.actions")}</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((j) => (
              <tr key={j.id}>
                <td>{new Date(j.created_at).toLocaleString()}</td>
                <td>{j.asset_name}</td>
                <td>{j.operator}</td>
                <td>
                  <code>{j.sql}</code>
                  <small>{t("database.parameterCount", { count: j.parameter_count })}</small>
                </td>
                <td>{t(`database.states.${j.state}`)}</td>
                <td>
                  <button
                    type="button"
                    className="button-text"
                    onClick={() =>
                      void request(`/api/v1/database-queries/${j.id}`)
                        .then(async (r) => {
                          if (r.ok) setSelected(await r.json());
                          else setFailed(true);
                        })
                        .catch(() => setFailed(true))
                    }
                  >
                    {t("database.details")}
                  </button>
                  {j.state === "awaiting_review" && allows("reviews.command.manage") && (
                    <>
                      <button
                        disabled={busy}
                        className="button-text"
                        onClick={() => void action(j.id, true)}
                      >
                        {t("database.approve")}
                      </button>
                      <button
                        disabled={busy}
                        className="button-text danger"
                        onClick={() => void action(j.id, false)}
                      >
                        {t("database.deny")}
                      </button>
                    </>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      {!rows.length && <p>{t("database.noHistory")}</p>}
      {selected && (
        <>
          <h2>{selected.asset_name}</h2>
          <DatabaseResultView job={selected} />
        </>
      )}
    </section>
  );
}
