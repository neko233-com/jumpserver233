import { requestID as newRequestID } from "../utils/requestID";
import { useCallback, useEffect, useId, useRef, useState, type FormEvent } from "react";
import { useTranslation } from "react-i18next";
import { useAuth } from "../auth/AuthContext";
import "../i18n/locales/features/ssh-password-policy/register";
import SSHPasswordRuleFields, { type SSHPasswordRules } from "./SSHPasswordRuleFields";

type Policy = SSHPasswordRules & { revision: number };
type Audit = { at: string; actor: string; after: Policy };
type State = { policy: Policy; audit: Audit[] };
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
    if (view)
      queueMicrotask(() => {
        if (!controller.signal.aborted) void load();
      });
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
        : { request_id: newRequestID(), policy: draft };
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
              <SSHPasswordRuleFields
                rules={draft}
                disabled={!manage || busy}
                onChange={(rules) => {
                  pending.current = null;
                  setDraft({ ...draft, ...rules });
                }}
              />
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
