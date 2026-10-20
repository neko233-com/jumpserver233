import { useCallback, useEffect, useRef, useState, type FormEvent } from "react";
import { useTranslation } from "react-i18next";
import { useSearchParams } from "react-router-dom";
import { useAuth } from "../auth/AuthContext";
import { usePermissions } from "../auth/usePermissions";
import "../i18n/locales/features/ssh-certificates/register";
import "./LabelsPage.css";

type Input = {
  name: string;
  provider: "builtin" | "openbao";
  enabled: boolean;
  ttl_seconds: number;
  endpoint: string;
  mount: string;
  role: string;
  namespace: string;
  root_ca_pem: string;
  public_key: string;
  token: string;
  revision: number;
};
type Issuer = Input & {
  id: string;
  fingerprint: string;
  has_token: boolean;
  trust_bundle: string;
  pending_public_key?: string;
};
type Binding = { asset_id: string; issuer_id: string; revision: number };
type Detail = {
  binding: Binding;
  target: { host: string; port: number; username: string };
  assignable: boolean;
};
type Target = {
  id: string;
  name: string;
  username: string;
  protocol?: string;
  accounts?: { id: string; username: string }[];
};
type Audit = {
  at: string;
  action: string;
  issuer_id?: string;
  asset_id?: string;
  actor_id?: string;
  serial?: number;
};
const fresh = (): Input => ({
  name: "",
  provider: "builtin",
  enabled: true,
  ttl_seconds: 300,
  endpoint: "",
  mount: "",
  role: "",
  namespace: "",
  root_ca_pem: "",
  public_key: "",
  token: "",
  revision: 0,
});
const nonce = () =>
  Array.from(crypto.getRandomValues(new Uint8Array(16)), (n) =>
    n.toString(16).padStart(2, "0"),
  ).join("");
const fields = [
  "name",
  "endpoint",
  "mount",
  "role",
  "namespace",
  "root_ca_pem",
  "public_key",
  "token",
] as const;

export default function SSHCertificatesPage() {
  const { t, i18n } = useTranslation();
  const { accessToken } = useAuth();
  const { allows, ready } = usePermissions();
  const [params, setParams] = useSearchParams();
  const [issuers, setIssuers] = useState<Issuer[]>([]),
    [targets, setTargets] = useState<Target[]>([]),
    [draft, setDraft] = useState<(Input & { id: string }) | null>(null);
  const [detail, setDetail] = useState<(Detail & { id: string }) | null>(null),
    [issuerID, setIssuerID] = useState(""),
    [busy, setBusy] = useState(false),
    [refresh, setRefresh] = useState(0),
    [error, setError] = useState(""),
    [message, setMessage] = useState("");
  const [audit, setAudit] = useState<{ results: Audit[]; total: number }>({
      results: [],
      total: 0,
    }),
    [auditOpen, setAuditOpen] = useState(false),
    [offset, setOffset] = useState(0);
  const assetID = params.get("asset_id") || "",
    canManage = allows("ssh_certificates.manage"),
    canView = allows("ssh_certificates.view"),
    canAudit = allows("ssh_certificates.audit");
  const saveNonce = useRef(nonce()),
    bindNonce = useRef(nonce()),
    mutations = useRef<Record<string, string>>({});
  const request = useCallback(
    async (path: string, method = "GET", body?: unknown, signal?: AbortSignal) => {
      const r = await fetch("/api/v1/" + path, {
        method,
        signal,
        credentials: "same-origin",
        headers: {
          ...(accessToken ? { Authorization: `Bearer ${accessToken}` } : {}),
          ...(body === undefined ? {} : { "Content-Type": "application/json" }),
        },
        ...(body === undefined ? {} : { body: JSON.stringify(body) }),
      });
      if (!r.ok) {
        const v = await r.json().catch(() => ({}));
        throw Error(v.error_code || "ssh_certificates_unavailable");
      }
      return r.status === 204 ? null : r.json();
    },
    [accessToken],
  );
  const base = "settings/ssh-certificates";
  useEffect(() => {
    if (!ready || !canView) return;
    const c = new AbortController();
    void Promise.all([
      request(base + "/issuers", "GET", undefined, c.signal),
      request("assets", "GET", undefined, c.signal),
    ])
      .then(([i, a]) => {
        if (!c.signal.aborted) {
          setIssuers(i);
          setTargets(a.filter((v: Target) => !v.protocol || v.protocol === "ssh"));
        }
      })
      .catch((e) => {
        if (!c.signal.aborted) setError(e.message);
      });
    return () => c.abort();
  }, [request, ready, canView, canManage, refresh]);
  useEffect(() => {
    if (!assetID) return;
    const c = new AbortController();
    void request(`${base}/bindings/${encodeURIComponent(assetID)}`, "GET", undefined, c.signal)
      .then((v) => {
        if (!c.signal.aborted) {
          setDetail({ ...v, id: assetID });
          setIssuerID(v.binding.issuer_id);
          bindNonce.current = nonce();
        }
      })
      .catch((e) => {
        if (!c.signal.aborted) {
          setDetail(null);
          setError(e.message);
        }
      });
    return () => c.abort();
  }, [request, assetID, refresh]);
  useEffect(() => {
    if (!auditOpen || !canAudit) return;
    const c = new AbortController();
    void request(`${base}/audit?offset=${offset}&limit=20`, "GET", undefined, c.signal)
      .then((v) => {
        if (!c.signal.aborted) setAudit(v);
      })
      .catch((e) => {
        if (!c.signal.aborted) setError(e.message);
      });
    return () => c.abort();
  }, [request, auditOpen, canAudit, offset, refresh]);
  const reload = () => {
    setDraft(null);
    setError("");
    setRefresh((v) => v + 1);
  };
  const edit = (value?: Issuer) => {
    const v = fresh();
    if (value) {
      for (const key of fields) if (key !== "token") v[key] = value[key] || "";
      v.provider = value.provider;
      v.enabled = value.enabled;
      v.ttl_seconds = value.ttl_seconds;
      v.revision = value.revision;
    }
    saveNonce.current = nonce();
    setDraft({ ...v, id: value?.id || "" });
    setMessage("");
    setError("");
  };
  const change = (value: Input & { id: string }) => {
    setDraft(value);
    saveNonce.current = nonce();
  };
  async function save(event: FormEvent) {
    event.preventDefault();
    if (!draft || busy) return;
    setBusy(true);
    setError("");
    setMessage("");
    try {
      const { id, ...body } = draft;
      await request(base + "/issuers" + (id ? "/" + id : ""), id ? "PUT" : "POST", {
        ...body,
        request_id: saveNonce.current,
      });
      setDraft(null);
      setMessage(t("sshCertificates.saved"));
      setRefresh((v) => v + 1);
    } catch (e) {
      setError(e instanceof Error ? e.message : "ssh_certificates_unavailable");
    } finally {
      setBusy(false);
    }
  }
  async function mutate(value: Issuer, action: "rotate" | "activate" | "delete") {
    if (busy || !window.confirm(t(`sshCertificates.confirm.${action}`))) return;
    setBusy(true);
    setError("");
    setMessage("");
    const key = `${action}:${value.id}:${value.revision}`;
    mutations.current[key] ??= nonce();
    try {
      await request(
        `${base}/issuers/${value.id}${action === "delete" ? "" : "/" + action}`,
        action === "delete" ? "DELETE" : "POST",
        { revision: value.revision, request_id: mutations.current[key] },
      );
      setMessage(t("sshCertificates.saved"));
      setRefresh((v) => v + 1);
    } catch (e) {
      setError(e instanceof Error ? e.message : "ssh_certificates_unavailable");
    } finally {
      setBusy(false);
    }
  }
  const current = detail?.id === assetID ? detail : null;
  async function bind(event: FormEvent) {
    event.preventDefault();
    if (!current?.assignable || busy) return;
    setBusy(true);
    setError("");
    setMessage("");
    try {
      await request(`${base}/bindings/${assetID}`, "PUT", {
        issuer_id: issuerID,
        revision: current.binding.revision,
        request_id: bindNonce.current,
      });
      setMessage(t("sshCertificates.bound"));
      setRefresh((v) => v + 1);
    } catch (e) {
      setError(e instanceof Error ? e.message : "ssh_certificates_unavailable");
    } finally {
      setBusy(false);
    }
  }
  return (
    <section className="labels-page ssh-certificates-page">
      <h1>{t("sshCertificates.title")}</h1>
      <p>{t("sshCertificates.description")}</p>
      <p>{t("sshCertificates.trustHint")}</p>
      {error && (
        <p role="alert">
          {t(`sshCertificates.errors.${error}`, {
            defaultValue: t("sshCertificates.errors.ssh_certificates_unavailable"),
          })}{" "}
          <button type="button" className="button-secondary" disabled={busy} onClick={reload}>
            {t("sshCertificates.reload")}
          </button>
        </p>
      )}
      {message && <p role="status">{message}</p>}
      {ready && !canView ? (
        <p>{t("sshCertificates.denied")}</p>
      ) : (
        <>
          <div className="labels-toolbar">
            <button type="button" className="button-secondary" disabled={busy} onClick={reload}>
              {t("sshCertificates.refresh")}
            </button>
            {canManage && (
              <button
                type="button"
                className="button-primary"
                disabled={busy}
                onClick={() => edit()}
              >
                {t("sshCertificates.new")}
              </button>
            )}
          </div>
          {canManage && draft && (
            <form className="labels-editor ssh-certificate-editor" onSubmit={save}>
              <fieldset disabled={busy}>
                <h2>{t(draft.id ? "sshCertificates.edit" : "sshCertificates.new")}</h2>
                <label>
                  {t("sshCertificates.provider")}
                  <select
                    value={draft.provider}
                    disabled={!!draft.id}
                    onChange={(e) =>
                      change({
                        ...fresh(),
                        name: draft.name,
                        id: draft.id,
                        provider: e.target.value as Input["provider"],
                      })
                    }
                  >
                    <option value="builtin">{t("sshCertificates.builtin")}</option>
                    <option value="openbao">{t("sshCertificates.openbao")}</option>
                  </select>
                </label>
                {fields
                  .filter((key) => key === "name" || draft.provider === "openbao")
                  .map((key) => (
                    <label key={key}>
                      {t(`sshCertificates.fields.${key}`)}
                      {key === "root_ca_pem" || key === "public_key" ? (
                        <textarea
                          rows={3}
                          value={draft[key]}
                          required={key === "public_key"}
                          onChange={(e) => change({ ...draft, [key]: e.target.value })}
                        />
                      ) : (
                        <input
                          type={key === "token" ? "password" : "text"}
                          autoComplete={key === "token" ? "new-password" : "off"}
                          required={
                            key === "name" ||
                            ["endpoint", "mount", "role"].includes(key) ||
                            (key === "token" && !draft.id)
                          }
                          value={draft[key]}
                          onChange={(e) => change({ ...draft, [key]: e.target.value })}
                        />
                      )}
                    </label>
                  ))}
                <label>
                  {t("sshCertificates.ttl")}
                  <input
                    type="number"
                    min={60}
                    max={600}
                    required
                    value={draft.ttl_seconds}
                    onChange={(e) => change({ ...draft, ttl_seconds: Number(e.target.value) })}
                  />
                </label>
                <label>
                  <input
                    type="checkbox"
                    checked={draft.enabled}
                    onChange={(e) => change({ ...draft, enabled: e.target.checked })}
                  />
                  {t("sshCertificates.enabled")}
                </label>
                <p>{t("sshCertificates.tokenHint")}</p>
                <div className="labels-toolbar">
                  <button className="button-primary" type="submit">
                    {t("sshCertificates.save")}
                  </button>
                  <button className="button-secondary" type="button" onClick={() => setDraft(null)}>
                    {t("sshCertificates.cancel")}
                  </button>
                </div>
              </fieldset>
            </form>
          )}
          <div className="labels-catalog">
            {issuers.map((value) => (
              <article key={value.id} aria-label={value.name}>
                <h2>{value.name}</h2>
                <p>
                  {t(`sshCertificates.${value.provider}`)} ·{" "}
                  {t(value.enabled ? "sshCertificates.enabled" : "sshCertificates.disabled")} ·{" "}
                  {t("sshCertificates.revision", { revision: value.revision })}
                </p>
                <code>{value.fingerprint}</code>
                <details>
                  <summary>{t("sshCertificates.trustBundle")}</summary>
                  <pre style={{ whiteSpace: "pre-wrap", overflowWrap: "anywhere" }}>
                    {value.trust_bundle}
                  </pre>
                  <p>{t("sshCertificates.rotationHint")}</p>
                </details>
                {canManage && (
                  <div className="labels-toolbar">
                    <button
                      type="button"
                      className="button-secondary"
                      disabled={busy}
                      onClick={() => edit(value)}
                    >
                      {t("sshCertificates.edit")}
                    </button>
                    {value.provider === "builtin" && (
                      <button
                        type="button"
                        className="button-secondary"
                        disabled={busy}
                        onClick={() =>
                          void mutate(value, value.pending_public_key ? "activate" : "rotate")
                        }
                      >
                        {t(
                          value.pending_public_key
                            ? "sshCertificates.activate"
                            : "sshCertificates.rotate",
                        )}
                      </button>
                    )}
                    <button
                      type="button"
                      className="button-secondary"
                      disabled={busy}
                      onClick={() => void mutate(value, "delete")}
                    >
                      {t("sshCertificates.delete")}
                    </button>
                  </div>
                )}
              </article>
            ))}
          </div>
          <section className="labels-bindings">
            <h2>{t("sshCertificates.binding")}</h2>
            <label>
              {t("sshCertificates.account")}
              <select
                value={assetID}
                disabled={busy}
                onChange={(e) => {
                  setParams(e.target.value ? { asset_id: e.target.value } : {});
                  setError("");
                  setMessage("");
                }}
              >
                <option value="">{t("sshCertificates.chooseAccount")}</option>
                {targets.flatMap((a) =>
                  (a.accounts?.length ? a.accounts : [{ id: a.id, username: a.username }]).map(
                    (c) => (
                      <option value={c.id} key={c.id}>
                        {a.name} · {c.username}
                      </option>
                    ),
                  ),
                )}
              </select>
            </label>
            {current && (
              <form onSubmit={bind}>
                <p>
                  <code>
                    {current.target.username}@{current.target.host}:{current.target.port}
                  </code>
                </p>
                <p>{t("sshCertificates.bindingHint")}</p>
                <label>
                  {t("sshCertificates.issuer")}
                  <select
                    value={issuerID}
                    disabled={busy || !current.assignable}
                    onChange={(e) => {
                      setIssuerID(e.target.value);
                      bindNonce.current = nonce();
                    }}
                  >
                    <option value="">{t("sshCertificates.bootstrap")}</option>
                    {issuers.map((v) => (
                      <option value={v.id} key={v.id} disabled={!v.enabled}>
                        {v.name}
                      </option>
                    ))}
                  </select>
                </label>
                <p>{t("sshCertificates.revision", { revision: current.binding.revision })}</p>
                {current.assignable && (
                  <button type="submit" disabled={busy} className="button-primary">
                    {t("sshCertificates.bind")}
                  </button>
                )}
              </form>
            )}
          </section>
        </>
      )}
      {canAudit && (
        <details onToggle={(e) => setAuditOpen(e.currentTarget.open)}>
          <summary>{t("sshCertificates.audit")}</summary>
          {auditOpen && (
            <>
              <ul className="labels-audit">
                {audit.results.map((v, index) => (
                  <li key={`${v.at}:${index}`}>
                    {new Date(v.at).toLocaleString(i18n.language)} ·{" "}
                    {t(`sshCertificates.actions.${v.action}`)} ·{" "}
                    <code>
                      {v.issuer_id} {v.asset_id}
                    </code>{" "}
                    · {v.actor_id || t("sshCertificates.service")}
                  </li>
                ))}
              </ul>
              <div className="labels-toolbar">
                <button
                  type="button"
                  className="button-secondary"
                  disabled={offset === 0}
                  onClick={() => setOffset(Math.max(0, offset - 20))}
                >
                  {t("sshCertificates.previous")}
                </button>
                <span>{t("sshCertificates.total", { count: audit.total })}</span>
                <button
                  type="button"
                  className="button-secondary"
                  disabled={offset + 20 >= audit.total}
                  onClick={() => setOffset(offset + 20)}
                >
                  {t("sshCertificates.next")}
                </button>
              </div>
            </>
          )}
        </details>
      )}
    </section>
  );
}
