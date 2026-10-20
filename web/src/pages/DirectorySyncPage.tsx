import { useCallback, useEffect, useState, type FormEvent } from "react";
import { Link } from "react-router-dom";
import { useTranslation } from "react-i18next";
import { usePermissions } from "../auth/usePermissions";
import { useIdentitySource } from "../auth/identitySource";
import { useIdentitySourceAPI } from "./identity-source-api";
import "../i18n/locales/features/identity-sources/register";
import "./IdentitySourcesPage.css";

type Mapping = {
  directory_group_dn: string;
  group_ids: string[];
  organization_id: string;
  organization_role: string;
};
type Config = {
  user_filter: string;
  username_attribute: string;
  group_base_dn: string;
  group_filter: string;
  mappings: Mapping[];
  missing_action: "keep" | "remove" | "disable";
  interval_minutes: number;
  revision: number;
};
type Entry = {
  subject: string;
  user_id: string;
  username: string;
  group_ids: string[];
  organizations: Record<string, string>;
  missing_count: number;
  suspended: boolean;
};
type Run = {
  id: string;
  request_id: string;
  actor_id: string;
  source_id: string;
  preview_id: string;
  revision: number;
  state: "applying" | "completed" | "aborted";
  at: string;
  users: number;
};
type Preview = {
  id: string;
  revision: number;
  result: {
    users: { subject: string; username: string; disabled: boolean; groups: string[] }[];
    groups: { dn: string; name: string }[];
  };
};
type Page<T> = { items: T[]; total: number };
type Choice = { id: string; name: string };
const empty: Config = {
  user_filter: "(objectClass=person)",
  username_attribute: "uid",
  group_base_dn: "",
  group_filter: "",
  mappings: [],
  missing_action: "keep",
  interval_minutes: 0,
  revision: 0,
};

export default function DirectorySyncPage() {
  const { t, i18n } = useTranslation();
  const { id, prefix } = useIdentitySource();
  const { request, operation, completed } = useIdentitySourceAPI();
  const { systemAllows, userID, ready } = usePermissions();
  const allowed = systemAllows("security.manage");
  const canWrite =
    allowed && ["groups.manage", "roles.manage", "organizations.manage"].every(systemAllows);
  const [config, setConfig] = useState<Config>(empty);
  const [entries, setEntries] = useState<Page<Entry>>({ items: [], total: 0 });
  const [runs, setRuns] = useState<Run[]>([]);
  const [preview, setPreview] = useState<Preview | null>(null);
  const [groups, setGroups] = useState<Choice[]>([]);
  const [orgs, setOrgs] = useState<Choice[]>([]);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [message, setMessage] = useState("");
  const [offset, setOffset] = useState(0);
  const [loaded, setLoaded] = useState(false);
  const [savedConfig, setSavedConfig] = useState("");
  const dirty = JSON.stringify(config) !== savedConfig;
  const base = prefix + "/sync";
  const pending = runs.find((run) => run.state === "applying");
  const load = useCallback(
    async (signal?: AbortSignal) => {
      if (!id) return;
      try {
        const [c, e, r] = await Promise.all([
          request<Config>(base, { signal }),
          request<Page<Entry>>(base + `/entries?offset=${offset}&limit=100`, { signal }),
          request<Page<Run>>(base + "/runs?limit=100", { signal }),
        ]);
        if (!signal?.aborted) {
          setConfig(c);
          setSavedConfig(JSON.stringify(c));
          setEntries(e);
          setRuns(r.items);
          setLoaded(true);
          setError("");
        }
      } catch (e) {
        if (!signal?.aborted)
          setError(e instanceof Error ? e.message : "directory_sync_unavailable");
      }
    },
    [request, base, id, offset],
  );
  useEffect(() => {
    if (!allowed) return;
    const c = new AbortController();
    queueMicrotask(() => {
      if (!c.signal.aborted) void load(c.signal);
    });
    return () => c.abort();
  }, [allowed, load]);
  useEffect(() => {
    if (!canWrite) return;
    const c = new AbortController();
    void Promise.all([
      request<Choice[]>("/api/v1/system/user-groups", { signal: c.signal }),
      request<{ results: Choice[] }>("/api/v1/organizations", { signal: c.signal }),
    ])
      .then(([g, o]) => {
        if (!c.signal.aborted) {
          setGroups(g);
          setOrgs(o.results);
        }
      })
      .catch(() => {
        if (!c.signal.aborted) setError("directory_sync_unavailable");
      });
    return () => c.abort();
  }, [request, canWrite]);
  async function save(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    setMessage("");
    try {
      const c = await request<Config>(base, {
        method: "PUT",
        body: JSON.stringify(operation("config:" + id, config)),
      });
      setConfig(c);
      setSavedConfig(JSON.stringify(c));
      setPreview(null);
      setError("");
      setMessage(t("identitySources.syncSaved"));
    } catch (e) {
      setError(e instanceof Error ? e.message : "directory_sync_unavailable");
    } finally {
      setBusy(false);
    }
  }
  async function scan() {
    setBusy(true);
    setPreview(null);
    setMessage("");
    try {
      const p = await request<Preview>(base + "/preview", {
        method: "POST",
        body: JSON.stringify(operation("preview:" + id, { revision: config.revision })),
      });
      setPreview(p);
      completed("preview:" + id);
      setError("");
    } catch (e) {
      setError(e instanceof Error ? e.message : "directory_sync_unavailable");
    } finally {
      setBusy(false);
    }
  }
  async function apply(run?: Run) {
    if (!run && !preview) return;
    setBusy(true);
    setMessage("");
    try {
      const body = run
        ? { request_id: run.request_id, revision: run.revision, preview_id: run.preview_id }
        : operation("apply:" + id, { revision: preview!.revision, preview_id: preview!.id });
      await request<Run>(base + "/apply", { method: "POST", body: JSON.stringify(body) });
      setPreview(null);
      await load();
      setMessage(t("identitySources.applied"));
    } catch (e) {
      setError(e instanceof Error ? e.message : "directory_sync_unavailable");
      await load();
    } finally {
      setBusy(false);
    }
  }
  async function abort() {
    if (!pending) return;
    setBusy(true);
    try {
      await request<Run>(base + "/abort", {
        method: "POST",
        body: JSON.stringify(
          operation("abort:" + id, { revision: pending.revision, preview_id: pending.preview_id }),
        ),
      });
      await load();
      setMessage(t("identitySources.aborted"));
    } catch (e) {
      setError(e instanceof Error ? e.message : "directory_sync_unavailable");
    } finally {
      setBusy(false);
    }
  }
  function mapping(index: number, patch: Partial<Mapping>) {
    setConfig((c) => ({
      ...c,
      mappings: c.mappings.map((m, i) => (i === index ? { ...m, ...patch } : m)),
    }));
    setPreview(null);
  }
  if (!ready) return null;
  if (!allowed || !id) return <p role="alert">{t("identitySources.denied")}</p>;
  return (
    <section className="identity-sources-page">
      <header>
        <h1>{t("identitySources.sync")}</h1>
        <p>{t("identitySources.syncHint")}</p>
        <Link to="/console/identity-sources">{t("identitySources.title")}</Link>
      </header>
      {error && (
        <p role="alert">
          {t("identitySources.errors." + error, {
            defaultValue: t("identitySources.errors.directory_sync_unavailable"),
          })}
        </p>
      )}
      {message && <p role="status">{message}</p>}
      {pending && (
        <aside role="status">
          <p>{t("identitySources.pendingHint")}</p>
          <div className="identity-source-toolbar">
            {canWrite && pending.actor_id === userID && (
              <button disabled={busy} onClick={() => void apply(pending)}>
                {t("identitySources.retry")}
              </button>
            )}
            {canWrite && (
              <button disabled={busy} onClick={() => void abort()}>
                {t("identitySources.abort")}
              </button>
            )}
          </div>
          <p>{t("identitySources.abortHint")}</p>
        </aside>
      )}
      <form className="identity-source-form" onSubmit={(e) => void save(e)}>
        <fieldset disabled={!loaded || busy || !canWrite || !!pending}>
          <legend>{t("identitySources.scanSettings")}</legend>
          {(["user_filter", "username_attribute", "group_base_dn", "group_filter"] as const).map(
            (field) => (
              <label key={field}>
                {t("identitySources.fields." + field)}
                <input
                  maxLength={field === "username_attribute" ? 64 : 2048}
                  required={field === "user_filter" || field === "username_attribute"}
                  value={config[field]}
                  onChange={(e) => {
                    setConfig({ ...config, [field]: e.target.value });
                    setPreview(null);
                  }}
                />
              </label>
            ),
          )}
          <label>
            {t("identitySources.fields.interval_minutes")}
            <input
              type="number"
              min={0}
              max={10080}
              step={1}
              value={config.interval_minutes}
              onChange={(e) => {
                setConfig({ ...config, interval_minutes: Number(e.target.value) });
                setPreview(null);
              }}
            />
          </label>
          <label>
            {t("identitySources.fields.missing_action")}
            <select
              value={config.missing_action}
              onChange={(e) => {
                setConfig({
                  ...config,
                  missing_action: e.target.value as Config["missing_action"],
                });
                setPreview(null);
              }}
            >
              {(["keep", "remove", "disable"] as const).map((v) => (
                <option key={v} value={v}>
                  {t("identitySources.missing." + v)}
                </option>
              ))}
            </select>
          </label>
          <p>{t("identitySources.missingHint")}</p>
          <h2>{t("identitySources.mappings")}</h2>
          {config.mappings.map((m, index) => (
            <div key={index} className="identity-source-mapping">
              <label>
                {t("identitySources.fields.directory_group_dn")}
                <input
                  required
                  maxLength={2048}
                  value={m.directory_group_dn}
                  onChange={(e) => mapping(index, { directory_group_dn: e.target.value })}
                />
              </label>
              <label>
                {t("identitySources.fields.group_ids")}
                <select
                  multiple
                  value={m.group_ids}
                  onChange={(e) =>
                    mapping(index, {
                      group_ids: Array.from(e.target.selectedOptions, (o) => o.value),
                    })
                  }
                >
                  {groups.map((g) => (
                    <option key={g.id} value={g.id}>
                      {g.name}
                    </option>
                  ))}
                </select>
              </label>
              <label>
                {t("identitySources.fields.organization_id")}
                <select
                  value={m.organization_id ?? ""}
                  onChange={(e) =>
                    mapping(index, {
                      organization_id: e.target.value,
                      organization_role: e.target.value ? m.organization_role || "member" : "",
                    })
                  }
                >
                  <option value="">{t("identitySources.none")}</option>
                  {orgs.map((o) => (
                    <option key={o.id} value={o.id}>
                      {o.name}
                    </option>
                  ))}
                </select>
              </label>
              {m.organization_id && (
                <label>
                  {t("identitySources.fields.organization_role")}
                  <select
                    value={m.organization_role}
                    onChange={(e) => mapping(index, { organization_role: e.target.value })}
                  >
                    {["member", "auditor", "admin"].map((role) => (
                      <option key={role} value={role}>
                        {t("identitySources.roles." + role)}
                      </option>
                    ))}
                  </select>
                </label>
              )}
              <button
                type="button"
                onClick={() => {
                  setConfig({ ...config, mappings: config.mappings.filter((_, i) => i !== index) });
                  setPreview(null);
                }}
              >
                {t("identitySources.remove")}
              </button>
            </div>
          ))}
          <div className="identity-source-toolbar">
            <button
              type="button"
              disabled={config.mappings.length >= 200}
              onClick={() =>
                setConfig({
                  ...config,
                  mappings: [
                    ...config.mappings,
                    {
                      directory_group_dn: "",
                      group_ids: [],
                      organization_id: "",
                      organization_role: "",
                    },
                  ],
                })
              }
            >
              {t("identitySources.addMapping")}
            </button>
            <button type="submit">{t("identitySources.save")}</button>
          </div>
        </fieldset>
      </form>
      <div className="identity-source-toolbar">
        <button
          disabled={busy || !loaded || !canWrite || !!pending || config.revision === 0 || dirty}
          onClick={() => void scan()}
        >
          {t("identitySources.preview")}
        </button>
        <button disabled={busy} onClick={() => void load()}>
          {t("identitySources.refresh")}
        </button>
      </div>
      {preview && (
        <section>
          <h2>{t("identitySources.preview")}</h2>
          <p>
            {t("identitySources.previewCount", {
              users: preview.result.users.length,
              groups: preview.result.groups.length,
            })}
          </p>
          <p>{t("identitySources.previewHint")}</p>
          <div className="identity-source-table">
            <table>
              <thead>
                <tr>
                  <th>{t("identitySources.username")}</th>
                  <th>{t("identitySources.groups")}</th>
                  <th>{t("identitySources.status")}</th>
                </tr>
              </thead>
              <tbody>
                {preview.result.users.slice(0, 50).map((u) => (
                  <tr key={u.subject}>
                    <td>{u.username}</td>
                    <td>{u.groups.length}</td>
                    <td>
                      {t(u.disabled ? "identitySources.suspended" : "identitySources.active")}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <button disabled={busy || !canWrite || dirty} onClick={() => void apply()}>
            {t("identitySources.apply")}
          </button>
        </section>
      )}
      <section>
        <h2>{t("identitySources.entries")}</h2>
        <div className="identity-source-table">
          <table>
            <thead>
              <tr>
                <th>{t("identitySources.username")}</th>
                <th>{t("identitySources.userID")}</th>
                <th>{t("identitySources.groups")}</th>
                <th>{t("identitySources.status")}</th>
              </tr>
            </thead>
            <tbody>
              {entries.items.map((e) => (
                <tr key={e.subject}>
                  <td>{e.username}</td>
                  <td>{e.user_id}</td>
                  <td>
                    {e.group_ids
                      .map((id) => groups.find((g) => g.id === id)?.name ?? id)
                      .join(", ")}
                  </td>
                  <td>{t(e.suspended ? "identitySources.suspended" : "identitySources.active")}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        <div className="identity-source-toolbar">
          <button
            disabled={busy || offset === 0}
            onClick={() => setOffset(Math.max(0, offset - 100))}
          >
            {t("identitySources.previous")}
          </button>
          <span>{t("identitySources.total", { count: entries.total })}</span>
          <button
            disabled={busy || offset + 100 >= entries.total}
            onClick={() => setOffset(offset + 100)}
          >
            {t("identitySources.next")}
          </button>
        </div>
      </section>
      <details>
        <summary>{t("identitySources.runs")}</summary>
        <div className="identity-source-table">
          <table>
            <thead>
              <tr>
                <th>{t("identitySources.at")}</th>
                <th>{t("identitySources.status")}</th>
                <th>{t("identitySources.username")}</th>
              </tr>
            </thead>
            <tbody>
              {runs.map((run) => (
                <tr key={run.id}>
                  <td>{new Date(run.at).toLocaleString(i18n.language)}</td>
                  <td>{t("identitySources.states." + run.state)}</td>
                  <td>{run.users}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </details>
    </section>
  );
}
