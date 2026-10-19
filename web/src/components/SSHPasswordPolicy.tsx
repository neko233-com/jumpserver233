import { useCallback, useEffect, useId, useRef, useState, type FormEvent } from "react";
import { useTranslation } from "react-i18next";
import { useAuth } from "../auth/AuthContext";
import "../i18n/locales/features/ssh-password-policy/register";

type Policy = {
  revision: number;
  min_length: number;
  max_length: number;
  min_upper: number;
  min_lower: number;
  min_digits: number;
  min_symbols: number;
  exclude: string;
};
type Audit = { at: string; actor: string; after: Policy };
type State = { policy: Policy; audit: Audit[] };
const fields = [
  "min_length",
  "max_length",
  "min_upper",
  "min_lower",
  "min_digits",
  "min_symbols",
] as const;
type Pending = { request_id: string; policy: Policy };
export default function SSHPasswordPolicy({ view, manage }: { view: boolean; manage: boolean }) {
  const { t } = useTranslation(),
    { accessToken } = useAuth(),
    id = useId();
  const [state, setState] = useState<State | null>(null),
    [draft, setDraft] = useState<Policy | null>(null),
    [busy, setBusy] = useState(false),
    [notice, setNotice] = useState("");
  const pending = useRef<Pending | null>(null),
    lifetime = useRef<AbortController | null>(null);
  const request = useCallback(
    async (init?: RequestInit) => {
      const response = await fetch("/api/v1/accounts/password-policy", {
        ...init,
        headers: {
          ...(accessToken ? { Authorization: `Bearer ${accessToken}` } : {}),
          ...(init?.body ? { "Content-Type": "application/json" } : {}),
        },
        signal: AbortSignal.any([
          AbortSignal.timeout(15000),
          ...(lifetime.current ? [lifetime.current.signal] : []),
        ]),
      });
      if (!response.ok)
        throw new Error(
          response.status === 409
            ? "conflict"
            : response.status === 400
              ? "invalid"
              : response.status === 403
                ? "denied"
                : "unavailable",
        );
      return (await response.json()) as State;
    },
    [accessToken],
  );
  const load = useCallback(async () => {
    try {
      const result = await request();
      setState(result);
      setDraft(result.policy);
      pending.current = null;
      setNotice("");
    } catch {
      if (!lifetime.current?.signal.aborted) setNotice("unavailable");
    }
  }, [request]);
  useEffect(() => {
    const controller = new AbortController();
    lifetime.current = controller;
    if (view) void load();
    return () => controller.abort();
  }, [load, view]);
  async function save(event: FormEvent) {
    event.preventDefault();
    if (!draft || busy) return;
    setBusy(true);
    setNotice("");
    const input =
      pending.current?.policy && JSON.stringify(pending.current.policy) === JSON.stringify(draft)
        ? pending.current
        : { request_id: crypto.randomUUID(), policy: draft };
    pending.current = input;
    try {
      const result = await request({ method: "PUT", body: JSON.stringify(input) });
      setState(result);
      setDraft(result.policy);
      pending.current = null;
      setNotice("saved");
    } catch (error) {
      if (lifetime.current?.signal.aborted) return;
      const code = error instanceof Error ? error.message : "unavailable";
      if (code === "conflict") {
        pending.current = null;
        await load();
      }
      setNotice(["invalid", "conflict", "denied"].includes(code) ? code : "unavailable");
    } finally {
      if (!lifetime.current?.signal.aborted) setBusy(false);
    }
  }
  if (!view) return null;
  return (
    <section className="ssh-password-policy" aria-labelledby={id + "-title"}>
      <h2 id={id + "-title"}>{t("sshPasswordPolicy.title")}</h2>
      <p className="settings-help">{t("sshPasswordPolicy.hint")}</p>
      <button type="button" disabled={busy} onClick={() => void load()}>
        {t("sshPasswordPolicy.refresh")}
      </button>
      {notice && <p role="status">{t(`sshPasswordPolicy.${notice}`)}</p>}
      {state && draft ? (
        <>
          <p>{t("sshPasswordPolicy.revision", { revision: state.policy.revision })}</p>
          <details>
            <summary>{t("sshPasswordPolicy.configure")}</summary>
            <form onSubmit={(e) => void save(e)}>
              <div className="ssh-password-policy-grid">
                {fields.map((field) => (
                  <label key={field} htmlFor={id + field}>
                    {t(`sshPasswordPolicy.${field}`)}
                    <input
                      id={id + field}
                      type="number"
                      min={field === "min_length" || field === "max_length" ? 16 : 0}
                      max="128"
                      required
                      disabled={!manage || busy}
                      value={draft[field]}
                      onChange={(e) => {
                        pending.current = null;
                        setDraft({ ...draft, [field]: Number(e.target.value) });
                      }}
                    />
                  </label>
                ))}
              </div>
              <label htmlFor={id + "exclude"}>
                {t("sshPasswordPolicy.exclude")}
                <input
                  id={id + "exclude"}
                  value={draft.exclude}
                  maxLength={62}
                  disabled={!manage || busy}
                  autoComplete="off"
                  onChange={(e) => {
                    pending.current = null;
                    setDraft({ ...draft, exclude: e.target.value });
                  }}
                />
              </label>
              <p className="settings-help">{t("sshPasswordPolicy.allowed")}</p>
              {manage && (
                <button className="button-primary" disabled={busy} type="submit">
                  {t("sshPasswordPolicy.save")}
                </button>
              )}
            </form>
          </details>
          <details>
            <summary>{t("sshPasswordPolicy.history")}</summary>
            <ul>
              {state.audit
                .slice(-20)
                .reverse()
                .map((row) => (
                  <li key={row.after.revision}>
                    {new Date(row.at).toLocaleString()} · {row.actor} ·{" "}
                    {t("sshPasswordPolicy.revision", { revision: row.after.revision })}
                  </li>
                ))}
            </ul>
          </details>
        </>
      ) : (
        <p role="status">{t("sshPasswordPolicy.loading")}</p>
      )}
    </section>
  );
}
