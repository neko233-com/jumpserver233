import { useCallback, useEffect, useMemo, useRef, useState, type FormEvent } from "react";
import { useTranslation } from "react-i18next";
import { useSearchParams } from "react-router-dom";
import { useAuth } from "../auth/AuthContext";
import { usePermissions } from "../auth/usePermissions";
import "../i18n/locales/features/labels/register";
import "./LabelsPage.css";

type Choice = { id: string; name: string; value: string; color: string };
type Label = Choice & { description: string; revision: number };
type Resource = { type: string; id: string };
type Applied = Choice & { inherited: boolean; source: Resource };
type Binding = { resource: Resource; label_ids: string[]; revision: number };
type BindingDetails = { binding: Binding; effective: Applied[]; assignable: boolean };
type Target = { id: string; name: string };
type Audit = {
  at: string;
  actor_id: string;
  action: string;
  label_id?: string;
  resource?: Resource;
  revision: number;
};
type Draft = Label;
const fresh = (): Draft => ({
  id: "",
  name: "",
  value: "",
  color: "#58a6ff",
  description: "",
  revision: 0,
});
const nonce = () =>
  Array.from(crypto.getRandomValues(new Uint8Array(16)), (b) =>
    b.toString(16).padStart(2, "0"),
  ).join("");
const labelText = (v: Choice) => (v.value ? `${v.name}: ${v.value}` : v.name);
const resourceKey = (v: Resource) => `${v.type}:${v.id}`;

export default function LabelsPage() {
  const { t, i18n } = useTranslation();
  const { accessToken } = useAuth();
  const { allows } = usePermissions();
  const [params, setParams] = useSearchParams();
  const target: Resource = {
    type: params.get("type") === "node" ? "node" : "asset",
    id: params.get("id") || "",
  };
  const targetKey = resourceKey(target);
  const [data, setData] = useState<{ results: Label[]; total: number }>({ results: [], total: 0 });
  const [choices, setChoices] = useState<Choice[]>([]);
  const [assets, setAssets] = useState<Target[]>([]);
  const [nodes, setNodes] = useState<Target[]>([]);
  const [search, setSearch] = useState("");
  const [offset, setOffset] = useState(0);
  const [draft, setDraft] = useState<Draft | null>(null);
  const [binding, setBinding] = useState<(BindingDetails & { key: string }) | null>(null);
  const [selected, setSelected] = useState<string[]>([]);
  const [choiceSearch, setChoiceSearch] = useState("");
  const [audit, setAudit] = useState<{ results: Audit[]; total: number }>({
    results: [],
    total: 0,
  });
  const [auditOpen, setAuditOpen] = useState(false);
  const [auditOffset, setAuditOffset] = useState(0);
  const [busy, setBusy] = useState(false);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [message, setMessage] = useState("");
  const [refresh, setRefresh] = useState(0);
  const saveID = useRef(nonce());
  const bindID = useRef(nonce());
  const deletions = useRef<Record<string, string>>({});
  const activeTarget = useRef(targetKey);
  activeTarget.current = targetKey;
  const canManage = allows("labels.manage");
  const canAudit = allows("labels.audit");
  const request = useCallback(
    async (path: string, method = "GET", body?: unknown, signal?: AbortSignal) => {
      const response = await fetch("/api/v1/" + path, {
        method,
        signal,
        credentials: "same-origin",
        headers: {
          ...(accessToken ? { Authorization: `Bearer ${accessToken}` } : {}),
          ...(body === undefined ? {} : { "Content-Type": "application/json" }),
        },
        ...(body === undefined ? {} : { body: JSON.stringify(body) }),
      });
      if (!response.ok) {
        const v = await response.json().catch(() => ({}));
        throw Error(v.error_code || "labels_unavailable");
      }
      return response.status === 204 ? null : response.json();
    },
    [accessToken],
  );
  useEffect(() => {
    const c = new AbortController();
    queueMicrotask(() => {
      if (!c.signal.aborted) setLoading(true);
    });
    void request(
      `labels/labels?search=${encodeURIComponent(search)}&offset=${offset}&limit=20`,
      "GET",
      undefined,
      c.signal,
    )
      .then((page) => {
        if (!c.signal.aborted) setData(page);
      })
      .catch((e) => {
        if (!c.signal.aborted) setError(e.message);
      })
      .finally(() => {
        if (!c.signal.aborted) setLoading(false);
      });
    return () => c.abort();
  }, [request, search, offset, refresh]);
  useEffect(() => {
    const c = new AbortController();
    void request("labels/choices", "GET", undefined, c.signal)
      .then((v) => {
        if (!c.signal.aborted) setChoices(v);
      })
      .catch((e) => {
        if (!c.signal.aborted) setError(e.message);
      });
    return () => c.abort();
  }, [request, refresh]);
  useEffect(() => {
    const c = new AbortController();
    void Promise.all([
      request("assets", "GET", undefined, c.signal),
      request("assets/nodes", "GET", undefined, c.signal),
    ])
      .then(([a, n]) => {
        if (!c.signal.aborted) {
          setAssets(a);
          setNodes(n);
        }
      })
      .catch((e) => {
        if (!c.signal.aborted) setError(e.message);
      });
    return () => c.abort();
  }, [request]);
  useEffect(() => {
    if (!target.id) return;
    const c = new AbortController();
    void request(
      `labels/bindings/${target.type}/${encodeURIComponent(target.id)}`,
      "GET",
      undefined,
      c.signal,
    )
      .then((v) => {
        if (!c.signal.aborted) {
          setBinding({ ...v, key: targetKey });
          setSelected(v.binding.label_ids);
          bindID.current = nonce();
        }
      })
      .catch((e) => {
        if (!c.signal.aborted) {
          setBinding(null);
          setError(e.message);
        }
      });
    return () => c.abort();
  }, [request, target.type, target.id, targetKey, refresh]);
  useEffect(() => {
    if (!auditOpen || !canAudit) return;
    const c = new AbortController();
    void request(`labels/audit?offset=${auditOffset}&limit=20`, "GET", undefined, c.signal)
      .then((v) => {
        if (!c.signal.aborted) setAudit(v);
      })
      .catch((e) => {
        if (!c.signal.aborted) setError(e.message);
      });
    return () => c.abort();
  }, [request, auditOpen, auditOffset, refresh, canAudit]);
  const visibleChoices = useMemo(
    () =>
      choices.filter((v) =>
        labelText(v).toLocaleLowerCase().includes(choiceSearch.trim().toLocaleLowerCase()),
      ),
    [choices, choiceSearch],
  );
  const current = binding?.key === targetKey && target.id ? binding : null;
  const edit = (value?: Label) => {
    saveID.current = nonce();
    setDraft(value ? { ...value } : fresh());
    setError("");
    setMessage("");
  };
  const changed = (value: Draft) => {
    setDraft(value);
    saveID.current = nonce();
  };
  const reload = () => {
    setError("");
    setDraft(null);
    setRefresh((v) => v + 1);
  };
  async function save(event: FormEvent) {
    event.preventDefault();
    if (!draft || busy) return;
    setBusy(true);
    setError("");
    setMessage("");
    try {
      const { id, name, value, color, description, revision } = draft;
      await request("labels/labels" + (id ? "/" + id : ""), id ? "PUT" : "POST", {
        name,
        value,
        color,
        description,
        revision,
        request_id: saveID.current,
      });
      setDraft(null);
      setMessage(t("labels.saved"));
      setRefresh((v) => v + 1);
    } catch (e) {
      setError(e instanceof Error ? e.message : "labels_unavailable");
    } finally {
      setBusy(false);
    }
  }
  async function remove(value: Label) {
    if (busy || !window.confirm(t("labels.confirmDelete"))) return;
    setBusy(true);
    setError("");
    setMessage("");
    const key = value.id + ":" + value.revision;
    deletions.current[key] ??= nonce();
    try {
      await request("labels/labels/" + value.id, "DELETE", {
        revision: value.revision,
        request_id: deletions.current[key],
      });
      setMessage(t("labels.deleted"));
      setRefresh((v) => v + 1);
    } catch (e) {
      setError(e instanceof Error ? e.message : "labels_unavailable");
    } finally {
      setBusy(false);
    }
  }
  function toggle(value: Choice, checked: boolean) {
    bindID.current = nonce();
    setMessage("");
    setSelected((ids) =>
      checked
        ? [
            ...ids.filter(
              (id) =>
                choices.find((c) => c.id === id)?.name.toLowerCase() !== value.name.toLowerCase(),
            ),
            value.id,
          ]
        : ids.filter((id) => id !== value.id),
    );
  }
  async function bind(event: FormEvent) {
    event.preventDefault();
    if (!current?.assignable || busy) return;
    const key = targetKey;
    setBusy(true);
    setError("");
    setMessage("");
    try {
      await request(`labels/bindings/${target.type}/${encodeURIComponent(target.id)}`, "PUT", {
        label_ids: [...selected].sort(),
        revision: current.binding.revision,
        request_id: bindID.current,
      });
      if (activeTarget.current === key) {
        setMessage(t("labels.bound"));
        setRefresh((v) => v + 1);
      }
    } catch (e) {
      if (activeTarget.current === key)
        setError(e instanceof Error ? e.message : "labels_unavailable");
    } finally {
      setBusy(false);
    }
  }
  function selectTarget(type: string, id: string) {
    setParams(id ? { type, id } : { type });
    setError("");
    setMessage("");
  }
  const pager = (start: number, total: number, change: (value: number) => void) => (
    <div className="labels-toolbar">
      <button
        type="button"
        className="button-secondary"
        disabled={busy || start === 0}
        onClick={() => change(Math.max(0, start - 20))}
      >
        {t("labels.previous")}
      </button>
      <span>
        {t("labels.page", {
          start: total ? start + 1 : 0,
          end: Math.min(start + 20, total),
          total,
        })}
      </span>
      <button
        type="button"
        className="button-secondary"
        disabled={busy || start + 20 >= total}
        onClick={() => change(start + 20)}
      >
        {t("labels.next")}
      </button>
    </div>
  );
  return (
    <section className="labels-page">
      <h1>{t("labels.title")}</h1>
      <p>{t("labels.description")}</p>
      {error && (
        <p role="alert">
          {t(`labels.errors.${error}`, { defaultValue: t("labels.errors.labels_unavailable") })}{" "}
          <button type="button" className="button-secondary" disabled={busy} onClick={reload}>
            {t("labels.reload")}
          </button>
        </p>
      )}
      {message && <p role="status">{message}</p>}
      <div className="labels-toolbar">
        <label>
          {t("labels.search")}
          <input
            value={search}
            onChange={(e) => {
              setSearch(e.target.value);
              setOffset(0);
            }}
          />
        </label>
        <button type="button" className="button-secondary" disabled={busy} onClick={reload}>
          {t("labels.refresh")}
        </button>
        {canManage && (
          <button type="button" className="button-primary" disabled={busy} onClick={() => edit()}>
            {t("labels.new")}
          </button>
        )}
      </div>
      {canManage && draft && (
        <form className="labels-editor" onSubmit={save}>
          <h2>{t(draft.id ? "labels.edit" : "labels.new")}</h2>
          <fieldset disabled={busy}>
            <label>
              {t("labels.name")}
              <input
                required
                maxLength={64}
                value={draft.name}
                onChange={(e) => changed({ ...draft, name: e.target.value })}
              />
            </label>
            <label>
              {t("labels.value")}
              <input
                maxLength={128}
                value={draft.value}
                onChange={(e) => changed({ ...draft, value: e.target.value })}
              />
            </label>
            <label>
              {t("labels.color")}
              <input
                type="color"
                value={draft.color}
                onChange={(e) => changed({ ...draft, color: e.target.value })}
              />
            </label>
            <label>
              {t("labels.detail")}
              <input
                maxLength={500}
                value={draft.description}
                onChange={(e) => changed({ ...draft, description: e.target.value })}
              />
            </label>
            <div className="labels-toolbar">
              <button type="submit" className="button-primary">
                {t("labels.save")}
              </button>
              <button type="button" className="button-secondary" onClick={() => setDraft(null)}>
                {t("labels.cancel")}
              </button>
            </div>
          </fieldset>
        </form>
      )}
      {loading ? (
        <p role="status">{t("labels.loading")}</p>
      ) : (
        <>
          <div className="labels-catalog">
            {data.results.map((value) => (
              <article key={value.id} aria-label={labelText(value)}>
                <span className="label-badge" style={{ borderColor: value.color }}>
                  {labelText(value)}
                </span>
                <p>{value.description}</p>
                <small>{t("labels.revision", { revision: value.revision })}</small>
                {canManage && (
                  <div className="labels-toolbar">
                    <button
                      type="button"
                      className="button-secondary"
                      disabled={busy}
                      onClick={() => edit(value)}
                    >
                      {t("labels.edit")}
                    </button>
                    <button
                      type="button"
                      className="button-secondary"
                      disabled={busy}
                      onClick={() => void remove(value)}
                    >
                      {t("labels.delete")}
                    </button>
                  </div>
                )}
              </article>
            ))}
          </div>
          {!data.total && <p>{t("labels.empty")}</p>}
          {pager(offset, data.total, setOffset)}
        </>
      )}
      <section className="labels-bindings">
        <h2>{t("labels.bindings")}</h2>
        <p>{t("labels.inheritance")}</p>
        <div className="labels-toolbar">
          <label>
            {t("labels.resourceType")}
            <select
              value={target.type}
              disabled={busy}
              onChange={(e) => selectTarget(e.target.value, "")}
            >
              <option value="asset">{t("labels.asset")}</option>
              <option value="node">{t("labels.node")}</option>
            </select>
          </label>
          <label>
            {t("labels.target")}
            <select
              value={target.id}
              disabled={busy}
              onChange={(e) => selectTarget(target.type, e.target.value)}
            >
              <option value="">{t("labels.chooseTarget")}</option>
              {(target.type === "asset" ? assets : nodes).map((v) => (
                <option value={v.id} key={v.id}>
                  {v.name} · {v.id}
                </option>
              ))}
            </select>
          </label>
        </div>
        {current && (
          <>
            <h3>{t("labels.effective")}</h3>
            <div className="labels-effective">
              {current.effective.map((v) => (
                <div key={v.id}>
                  <span className="label-badge" style={{ borderColor: v.color }}>
                    {labelText(v)}
                  </span>
                  <small>
                    {v.inherited
                      ? t("labels.inherited", {
                          type: t(`labels.${v.source.type}`),
                          id: v.source.id,
                        })
                      : t("labels.direct")}
                  </small>
                </div>
              ))}
              {!current.effective.length && <p>{t("labels.noBindings")}</p>}
            </div>
            <form onSubmit={bind}>
              <h3>{t("labels.directLabels")}</h3>
              <p>{t("labels.oneValue")}</p>
              {!current.assignable && <p>{t("labels.readOnly")}</p>}
              <label>
                {t("labels.choiceSearch")}
                <input value={choiceSearch} onChange={(e) => setChoiceSearch(e.target.value)} />
              </label>
              <fieldset className="labels-choices" disabled={busy || !current.assignable}>
                {visibleChoices.map((value) => (
                  <label key={value.id}>
                    <input
                      type="checkbox"
                      checked={selected.includes(value.id)}
                      onChange={(e) => toggle(value, e.target.checked)}
                    />
                    <span className="label-badge" style={{ borderColor: value.color }}>
                      {labelText(value)}
                    </span>
                  </label>
                ))}
              </fieldset>
              {current.assignable && (
                <button
                  className="button-primary"
                  type="submit"
                  disabled={busy || selected.length > 64}
                >
                  {t("labels.saveBindings")}
                </button>
              )}
            </form>
          </>
        )}
      </section>
      {allows("labels.audit") && (
        <details onToggle={(e) => setAuditOpen(e.currentTarget.open)}>
          <summary>{t("labels.audit")}</summary>
          {auditOpen && (
            <>
              <ul className="labels-audit">
                {audit.results.map((v, index) => (
                  <li key={`${v.at}:${index}`}>
                    <time>{new Date(v.at).toLocaleString(i18n.language)}</time> · {v.actor_id} ·{" "}
                    {t(`labels.actions.${v.action}`)} ·{" "}
                    <code>{v.label_id || (v.resource && resourceKey(v.resource))}</code> ·{" "}
                    {t("labels.revision", { revision: v.revision })}
                  </li>
                ))}
              </ul>
              {pager(auditOffset, audit.total, setAuditOffset)}
            </>
          )}
        </details>
      )}
    </section>
  );
}
