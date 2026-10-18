import { useCallback, useEffect, useState, type FormEvent } from "react";
import { useTranslation } from "react-i18next";
import { useAuth } from "../auth/AuthContext";
import PasswordRules, { type PasswordPolicy } from "./PasswordRules";
type Audit = { id: string; at: string; actor: string; after: PasswordPolicy; affected: number };
export default function PasswordSecuritySettings() {
  const { t, i18n } = useTranslation(),
    { accessToken } = useAuth();
  const [policy, setPolicy] = useState<PasswordPolicy | null>(null),
    [baseline, setBaseline] = useState<PasswordPolicy | null>(null),
    [audit, setAudit] = useState<Audit[]>([]),
    [offset, setOffset] = useState(0),
    [total, setTotal] = useState(0),
    [busy, setBusy] = useState(false),
    [error, setError] = useState(false);
  const request = useCallback(
    (path: string, init?: RequestInit) => {
      const headers = new Headers(init?.headers);
      if (accessToken) headers.set("Authorization", `Bearer ${accessToken}`);
      if (init?.body) headers.set("Content-Type", "application/json");
      return fetch("/api/v1/settings/security/passwords" + path, { ...init, headers });
    },
    [accessToken],
  );
  useEffect(() => {
    const c = new AbortController();
    void Promise.all([
      request("", { signal: c.signal }),
      request(`/audit?offset=${offset}&limit=25`, { signal: c.signal }),
    ])
      .then(async (rs) => {
        if (rs.some((r) => !r.ok)) throw Error();
        const [p, a] = (await Promise.all(rs.map((r) => r.json()))) as [
          PasswordPolicy,
          { results: Audit[]; total: number },
        ];
        if (!c.signal.aborted) {
          setPolicy(p);
          setBaseline(p);
          setAudit(a.results);
          setTotal(a.total);
        }
      })
      .catch(() => {
        if (!c.signal.aborted) setError(true);
      });
    return () => c.abort();
  }, [request, offset]);
  const dirty = Boolean(
    policy &&
    baseline &&
    Object.keys(baseline).some(
      (k) => policy[k as keyof PasswordPolicy] !== baseline[k as keyof PasswordPolicy],
    ),
  );
  async function save(e: FormEvent) {
    e.preventDefault();
    if (!policy || !dirty) return;
    setBusy(true);
    setError(false);
    try {
      const r = await request("", { method: "PUT", body: JSON.stringify(policy) });
      if (!r.ok) throw Error();
      window.location.assign("/login");
    } catch {
      setError(true);
    } finally {
      setBusy(false);
    }
  }
  return (
    <section className="settings-card session-security-card">
      <h3>{t("passwordSecurity.title")}</h3>
      <p>{t("passwordSecurity.scope")}</p>
      {error && <p role="alert">{t("passwordSecurity.error")}</p>}
      {policy && (
        <form className="settings-form" onSubmit={(e) => void save(e)}>
          {[
            "min_length",
            "admin_min_length",
            "history_count",
            "max_age_days",
            "admin_max_age_days",
          ].map((k) => (
            <label key={k}>
              {t("passwordSecurity." + k)}
              <input
                type="number"
                min={k.endsWith("length") ? 12 : 0}
                max={k.endsWith("length") ? 128 : k === "history_count" ? 24 : 36500}
                required
                value={policy[k as keyof PasswordPolicy] as number}
                onChange={(e) => setPolicy({ ...policy, [k]: Number(e.target.value) })}
              />
            </label>
          ))}
          {["upper", "lower", "digit", "special"].map((k) => (
            <label key={k} className="settings-checkbox">
              <input
                type="checkbox"
                checked={policy[("require_" + k) as keyof PasswordPolicy] as boolean}
                onChange={(e) => setPolicy({ ...policy, ["require_" + k]: e.target.checked })}
              />
              {t("passwordSecurity." + k)}
            </label>
          ))}
          <PasswordRules policy={policy} />
          <p>{t("passwordSecurity.policyWarning")}</p>
          <button type="submit" className="button-primary" disabled={busy || !dirty}>
            {t("passwordSecurity.save")}
          </button>
        </form>
      )}
      <h3>{t("passwordSecurity.audit")}</h3>
      {audit.map((a) => (
        <p key={a.id}>
          {new Date(a.at).toLocaleString(i18n.language)} · {a.actor} ·{" "}
          {t("passwordSecurity.revision", { revision: a.after.revision, count: a.affected })}
        </p>
      ))}
      <div className="users-toolbar">
        <button disabled={busy || offset === 0} onClick={() => setOffset(Math.max(0, offset - 25))}>
          {t("passwordSecurity.previous")}
        </button>
        <button disabled={busy || offset + 25 >= total} onClick={() => setOffset(offset + 25)}>
          {t("passwordSecurity.next")}
        </button>
      </div>
    </section>
  );
}
