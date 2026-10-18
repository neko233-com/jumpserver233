import CredentialRecovery from "../components/CredentialRecovery";
import { useCallback, useEffect, useState, type FormEvent } from "react";
import { useTranslation } from "react-i18next";
import { Link } from "react-router-dom";
import { useAuth } from "../auth/AuthContext";
import { usePermissions } from "../auth/usePermissions";
import "../i18n/locales/features/users/register";
import "./users.css";

type User = {
  id: string;
  username: string;
  name?: string;
  comment?: string;
  role: string;
  source?: string;
  is_active: boolean;
  state: string;
  disabled?: boolean;
  date_expired?: string;
  revision: number;
};
type Event = {
  id: string;
  at: string;
  username: string;
  actor: string;
  action: string;
  revision: number;
  fields: string[];
  before: string;
  after: string;
};
type Change = { id: string; revision: number; action: string; [key: string]: unknown };
export default function UsersPage() {
  const { t, i18n } = useTranslation();
  const { accessToken } = useAuth();
  const { systemAllows, ready, userID } = usePermissions();
  const allowed = systemAllows("users.manage"),
    admins = systemAllows("roles.manage");
  const [rows, setRows] = useState<User[]>([]),
    [events, setEvents] = useState<Event[]>([]);
  const [total, setTotal] = useState(0),
    [auditTotal, setAuditTotal] = useState(0);
  const [scope, setScope] = useState("current"),
    [query, setQuery] = useState(""),
    [search, setSearch] = useState("");
  const [offset, setOffset] = useState(0),
    [auditOffset, setAuditOffset] = useState(0),
    [epoch, setEpoch] = useState(0);
  const [selected, setSelected] = useState<string[]>([]),
    [editing, setEditing] = useState<User | null>(null);
  const [recovery,setRecovery]=useState<{user:User;kind:"password"|"mfa"}|null>(null);
  const [expiry, setExpiry] = useState(""),
    [busy, setBusy] = useState(false),
    [loaded, setLoaded] = useState(false);
  const [error, setError] = useState(""),
    [saved, setSaved] = useState(false),
    [pending, setPending] = useState<Change[] | null>(null);
  const request = useCallback(
    async (path: string, init?: RequestInit) => {
      const headers = new Headers(init?.headers);
      if (accessToken) headers.set("Authorization", `Bearer ${accessToken}`);
      if (init?.body) headers.set("Content-Type", "application/json");
      const response = await fetch("/api/v1/users/" + path, { ...init, headers });
      const body = (await response.json()) as { error_code?: string };
      if (!response.ok) throw Error(body.error_code || "user_unavailable");
      return body;
    },
    [accessToken],
  );
  useEffect(() => {
    if (!ready || !allowed) return;
    const controller = new AbortController();
    setLoaded(false);
    void Promise.all([
      request(
        `management?scope=${scope}&q=${encodeURIComponent(search)}&offset=${offset}&limit=25`,
        { signal: controller.signal },
      ),
      request(`audit?offset=${auditOffset}&limit=25`, { signal: controller.signal }),
    ])
      .then(([users, audit]) => {
        if (controller.signal.aborted) return;
        const u = users as unknown as { results: User[]; total: number },
          a = audit as unknown as { results: Event[]; total: number };
        setRows(u.results);
        setTotal(u.total);
        setEvents(a.results);
        setAuditTotal(a.total);
        setSelected([]);
        setLoaded(true);
      })
      .catch((e: unknown) => {
        if (!controller.signal.aborted)
          setError(e instanceof Error ? e.message : "user_unavailable");
      });
    return () => controller.abort();
  }, [request, ready, allowed, scope, search, offset, auditOffset, epoch]);
  async function commit(changes: Change[]) {
    setBusy(true);
    setError("");
    setSaved(false);
    try {
      await request("actions", { method: "POST", body: JSON.stringify({ changes }) });
      setEditing(null);
      setPending(null);
      setSaved(true);
      setEpoch((v) => v + 1);
    } catch (e) {
      setError(e instanceof Error ? e.message : "user_unavailable");
    } finally {
      setBusy(false);
    }
  }
  function action(action: string, users: User[]) {
    setPending(
      users.map((u) => ({
        id: u.id,
        revision: u.revision,
        action: action === "enable" || action === "disable" ? "update" : action,
        ...(action === "enable" || action === "disable" ? { is_active: action === "enable" } : {}),
      })),
    );
    setError("");
    setSaved(false);
  }
  function edit(u: User) {
    setEditing({ ...u });
    setExpiry(u.date_expired ? localDate(u.date_expired) : "");
    setPending(null);
    setSaved(false);
  }
  function save(e: FormEvent) {
    e.preventDefault();
    if (!editing) return;
    const change: Change = {
      id: editing.id,
      revision: editing.revision,
      action: "update",
      name: editing.name || "",
      comment: editing.comment || "",
    };
    const original = rows.find((u) => u.id === editing.id);
    if (original?.role !== editing.role) change.role = editing.role;
    if (original?.disabled !== editing.disabled) change.is_active = !editing.disabled;
    const date = expiry ? new Date(expiry).toISOString() : "";
    if (expiry !== (original?.date_expired ? localDate(original.date_expired) : "")) {
      if (date) change.date_expired = date;
      else change.clear_date_expired = true;
    }
    setPending([change]);
  }
  const editable = (u: User) => u.role !== "admin" || admins;
  const security = (u: User) => editable(u) && u.id !== userID;
  if (!ready) return null;
  if (!allowed) return <p role="alert">{t("identityUsers.denied")}</p>;
  const chosen = rows.filter((u) => selected.includes(u.id));
  return (
    <section className="users-page">
      <h1>{t("identityUsers.title")}</h1>
      <p>{t("identityUsers.hint")}</p>
      <Link to="/console/settings">{t("identityUsers.create")}</Link>
      {error && (
        <p role="alert">
          {t("identityUsers.errors." + (error in errors ? error : "user_unavailable"))}
        </p>
      )}
      {saved && <p role="status">{t("identityUsers.saved")}</p>}
      <form
        className="users-toolbar"
        onSubmit={(e) => {
          e.preventDefault();
          setSearch(query);
          setOffset(0);
          setEditing(null);
          setPending(null);
        }}
      >
        <label>
          {t("identityUsers.search")}
          <input value={query} maxLength={128} onChange={(e) => setQuery(e.target.value)} />
        </label>
        <label>
          {t("identityUsers.scope")}
          <select
            value={scope}
            onChange={(e) => {
              setScope(e.target.value);
              setOffset(0);
              setEditing(null);
              setPending(null);
            }}
          >
            {["current", "archived", "all"].map((v) => (
              <option key={v} value={v}>
                {t("identityUsers." + v)}
              </option>
            ))}
          </select>
        </label>
        <button disabled={busy}>{t("identityUsers.search")}</button>
        <button
          type="button"
          disabled={busy}
          onClick={() => {
            setError("");
            setEpoch((v) => v + 1);
          }}
        >
          {t("identityUsers.refresh")}
        </button>
      </form>
      <div className="users-toolbar" aria-label={t("identityUsers.batch")}>
        <span>{t("identityUsers.selected", { count: selected.length })}</span>
        {["enable", "disable", "revoke", "archive", "restore"].map((a) => (
          <button
            key={a}
            disabled={
              busy ||
              !loaded ||
              !chosen.length ||
              chosen.some(
                (u) =>
                  !security(u) ||
                  (a === "restore" ? u.state !== "archived" : u.state === "archived"),
              )
            }
            onClick={() => action(a, chosen)}
          >
            {t("identityUsers." + a)}
          </button>
        ))}
      </div>
      <div className="users-scroll">
        <table>
          <thead>
            <tr>
              <th>{t("identityUsers.select")}</th>
              {["username", "name", "role", "source", "state", "expiry", "revision", "actions"].map(
                (v) => (
                  <th key={v}>{t("identityUsers." + v)}</th>
                ),
              )}
            </tr>
          </thead>
          <tbody>
            {rows.map((u) => (
              <tr key={u.id}>
                <td>
                  <input
                    type="checkbox"
                    aria-label={t("identityUsers.selectUser", { name: u.username })}
                    checked={selected.includes(u.id)}
                    disabled={busy || !security(u)}
                    onChange={(e) =>
                      setSelected(
                        e.target.checked ? [...selected, u.id] : selected.filter((v) => v !== u.id),
                      )
                    }
                  />
                </td>
                <td>{u.username}</td>
                <td>{u.name}</td>
                <td>{t("identityUsers." + u.role)}</td>
                <td>{u.source || t("identityUsers.local")}</td>
                <td>{t("identityUsers." + u.state)}</td>
                <td>
                  {u.date_expired
                    ? new Date(u.date_expired).toLocaleString(i18n.language)
                    : t("identityUsers.never")}
                </td>
                <td>{u.revision}</td>
                <td>
                  <div className="users-actions">
                    <button
                      disabled={busy || !editable(u) || u.state === "archived"}
                      onClick={() => edit(u)}
                    >
                      {t("identityUsers.edit")}
                    </button>
                    {systemAllows("users.credentials.manage") && u.state!=="archived" && ["password","mfa"].filter(k=>k!=="password"||!u.source).map(kind=><button key={kind} disabled={busy||!security(u)} onClick={()=>{setEditing(null);setPending(null);setRecovery({user:u,kind:kind as "password"|"mfa"})}}>{t("passwordSecurity.reset_"+kind)}</button>)}
 {(u.state === "archived" ? ["restore"] : ["revoke", "archive"]).map((a) => (
                      <button
                        key={a}
                        disabled={busy || !security(u)}
                        onClick={() => action(a, [u])}
                      >
                        {t("identityUsers." + a)}
                      </button>
                    ))}
                  </div>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <Pager
        offset={offset}
        total={total}
        busy={busy}
        change={setOffset}
        label={t("identityUsers.title")}
      />
      {editing && (
        <form className="users-editor" onSubmit={save}>
          <h2>
            {t("identityUsers.edit")}: {editing.username}
          </h2>
          <label>
            {t("identityUsers.name")}
            <input
              maxLength={128}
              value={editing.name || ""}
              onChange={(e) => setEditing({ ...editing, name: e.target.value })}
            />
          </label>
          <label>
            {t("identityUsers.comment")}
            <textarea
              maxLength={2000}
              value={editing.comment || ""}
              onChange={(e) => setEditing({ ...editing, comment: e.target.value })}
            />
          </label>
          <label>
            {t("identityUsers.role")}
            <select
              disabled={!admins || editing.id === userID || !!editing.source}
              value={editing.role}
              onChange={(e) => setEditing({ ...editing, role: e.target.value })}
            >
              {["operator", "admin"].map((r) => (
                <option key={r} value={r}>
                  {t("identityUsers." + r)}
                </option>
              ))}
            </select>
          </label>
          <label>
            <input
              type="checkbox"
              disabled={editing.id === userID}
              checked={!editing.disabled}
              onChange={(e) => setEditing({ ...editing, disabled: !e.target.checked })}
            />
            {t("identityUsers.enabled")}
          </label>
          <label>
            {t("identityUsers.expiry")}
            <input
              type="datetime-local"
              disabled={editing.id === userID}
              value={expiry}
              min="1970-01-01T00:00"
              max="9999-12-31T23:59"
              onChange={(e) => setExpiry(e.target.value)}
            />
          </label>
          <button disabled={busy || !loaded}>{t("identityUsers.review")}</button>
          <button
            type="button"
            disabled={busy}
            onClick={() => {
              setEditing(null);
              setPending(null);
            }}
          >
            {t("identityUsers.cancel")}
          </button>
        </form>
      )}
      {pending && (
        <section className="users-confirm" role="region" aria-label={t("identityUsers.confirm")}>
          <h2>{t("identityUsers.confirm")}</h2>
          <p>{t("identityUsers.warning")}</p>
          <p>{pending.map((c) => rows.find((u) => u.id === c.id)?.username).join(", ")}</p>
          <button disabled={busy || !loaded} onClick={() => void commit(pending)}>
            {t("identityUsers.apply")}
          </button>
          <button disabled={busy} onClick={() => setPending(null)}>
            {t("identityUsers.cancel")}
          </button>
        </section>
      )}
      {recovery && <CredentialRecovery key={recovery.user.id+recovery.kind} user={recovery.user} kind={recovery.kind} done={()=>{setRecovery(null);setEpoch(v=>v+1)}} />}
 <h2>{t("identityUsers.audit")}</h2>
      <p>{t("identityUsers.auditHint")}</p>
      <div className="users-scroll">
        <table>
          <thead>
            <tr>
              {["at", "actor", "username", "action", "fields", "state", "revision"].map((v) => (
                <th key={v}>{t("identityUsers." + v)}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {events.map((e) => (
              <tr key={e.id}>
                <td>{new Date(e.at).toLocaleString(i18n.language)}</td>
                <td>{e.actor}</td>
                <td>{e.username}</td>
                <td>{t("identityUsers." + e.action)}</td>
                <td>{e.fields.map((f) => t("identityUsers.fieldsLabel." + f)).join(", ")}</td>
                <td>
                  {t("identityUsers." + e.before)} → {t("identityUsers." + e.after)}
                </td>
                <td>{e.revision}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <Pager
        offset={auditOffset}
        total={auditTotal}
        busy={busy}
        change={setAuditOffset}
        label={t("identityUsers.audit")}
      />
    </section>
  );
}
const errors = {
  user_revision: 1,
  user_self: 1,
  user_last_admin: 1,
  user_admin: 1,
  user_session: 1,
  user_invalid: 1,
  user_not_found: 1,
  user_unavailable: 1,
};
function Pager({
  offset,
  total,
  busy,
  change,
  label,
}: {
  offset: number;
  total: number;
  busy: boolean;
  change: (v: number) => void;
  label: string;
}) {
  const { t } = useTranslation();
  return (
    <nav className="users-toolbar" aria-label={label}>
      <button disabled={busy || offset === 0} onClick={() => change(Math.max(0, offset - 25))}>
        {t("identityUsers.previous")}
      </button>
      <span>{t("identityUsers.total", { count: total })}</span>
      <button disabled={busy || offset + 25 >= total} onClick={() => change(offset + 25)}>
        {t("identityUsers.next")}
      </button>
    </nav>
  );
}

function localDate(value: string) {
  const date = new Date(value);
  return new Date(date.getTime() - date.getTimezoneOffset() * 60000).toISOString().slice(0, 16);
}
