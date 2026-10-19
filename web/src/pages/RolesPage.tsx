import "../i18n/locales/features/asset-discovery/register";
import "../i18n/locales/features/ssh-password-policy/register";
import { useCallback, useEffect, useState, type FormEvent } from "react";
import { useTranslation } from "react-i18next";
import { useAuth } from "../auth/AuthContext";
import { usePermissions } from "../auth/usePermissions";

type Role = {
  id: string;
  name: string;
  description: string;
  permissions: string[];
  revision: number;
  builtin: boolean;
};
type Binding = { subject_type: string; subject_id: string; role_ids: string[]; revision: number };
type Subject = { id: string; username?: string; name?: string };
type Audit = {
  id: string;
  at: string;
  actor: string;
  action: string;
  target: string;
  before?: unknown;
  after?: unknown;
};
export default function RolesPage({ organization = false }: { organization?: boolean }) {
  const apiPrefix = organization ? "/api/v1/organization-rbac" : "/api/v1/system/rbac";
  const { t, i18n } = useTranslation();
  const { accessToken } = useAuth();
  const { allows, systemAllows, ready, refresh } = usePermissions();
  const canManage = organization ? allows("roles.manage") : systemAllows("roles.manage");
  const [roles, setRoles] = useState<Role[]>([]);
  const [bindings, setBindings] = useState<Binding[]>([]);
  const [catalog, setCatalog] = useState<string[]>([]);
  const [users, setUsers] = useState<Subject[]>([]);
  const [groups, setGroups] = useState<Subject[]>([]);
  const [editing, setEditing] = useState<Role | null>(null);
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [permissions, setPermissions] = useState<string[]>([]);
  const [subjectType, setSubjectType] = useState("user");
  const [subjectID, setSubjectID] = useState("");
  const [roleIDs, setRoleIDs] = useState<string[]>([]);
  const [bindingRevision, setBindingRevision] = useState(0);
  const [audit, setAudit] = useState<Audit[]>([]);
  const [offset, setOffset] = useState(0);
  const [total, setTotal] = useState(0);
  const [selectedAudit, setSelectedAudit] = useState<Audit | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState(false);
  const [saved, setSaved] = useState(false);
  const request = useCallback(
    (path: string, init?: RequestInit) => {
      const headers = new Headers(init?.headers);
      if (accessToken) headers.set("Authorization", `Bearer ${accessToken}`);
      if (init?.body) headers.set("Content-Type", "application/json");
      if (path.startsWith("/api/v1/rbac")) path = path.replace("/api/v1/rbac", apiPrefix);
      if (!organization && (path === "/api/v1/users" || path === "/api/v1/user-groups"))
        path = path.replace("/api/v1/", "/api/v1/system/");
      return fetch(path, { ...init, headers });
    },
    [accessToken, apiPrefix, organization],
  );
  const load = useCallback(
    async (signal?: AbortSignal) => {
      try {
        const responses = await Promise.all(
          [
            "/api/v1/rbac/roles",
            "/api/v1/rbac/bindings",
            "/api/v1/rbac/permissions",
            "/api/v1/users",
            "/api/v1/user-groups",
            `/api/v1/rbac/audit?limit=50&offset=${offset}`,
          ].map((url) => request(url, { signal })),
        );
        if (responses.some((r) => !r.ok)) throw new Error("RBAC unavailable");
        const [rs, bs, cs, us, gs, as] = (await Promise.all(responses.map((r) => r.json()))) as [
          Role[],
          Binding[],
          string[],
          Subject[],
          Subject[],
          { results: Audit[]; total: number },
        ];
        if (signal?.aborted) return;
        setRoles(rs);
        setBindings(bs);
        setCatalog(cs);
        setUsers(us);
        setGroups(gs);
        setAudit(as.results);
        setTotal(as.total);
        setError(false);
      } catch {
        if (!signal?.aborted) setError(true);
      }
    },
    [offset, request],
  );
  useEffect(() => {
    if (!canManage) return;
    const c = new AbortController();
    queueMicrotask(() => {
      if (!c.signal.aborted) void load(c.signal);
    });
    return () => c.abort();
  }, [canManage, load]);
  function edit(role: Role | null) {
    setEditing(role);
    setName(role?.name || "");
    setDescription(role?.description || "");
    setPermissions(role?.permissions || []);
    setSaved(false);
  }
  function chooseSubject(kind: string, id: string) {
    const binding = bindings.find((b) => b.subject_type === kind && b.subject_id === id);
    setSubjectType(kind);
    setSubjectID(id);
    setRoleIDs(binding?.role_ids || []);
    setBindingRevision(binding?.revision || 0);
    setSaved(false);
  }
  async function saveRole(event: FormEvent) {
    event.preventDefault();
    setBusy(true);
    setSaved(false);
    try {
      const response = await request(
        `/api/v1/rbac/roles${editing ? `/${encodeURIComponent(editing.id)}` : ""}`,
        {
          method: editing ? "PUT" : "POST",
          body: JSON.stringify({
            name,
            description,
            permissions,
            revision: editing?.revision || 0,
          }),
        },
      );
      if (!response.ok) throw new Error("save failed");
      edit((await response.json()) as Role);
      await load();
      await refresh();
      setSaved(true);
    } catch {
      setError(true);
    } finally {
      setBusy(false);
    }
  }
  async function deleteRole() {
    if (!editing || editing.builtin || !window.confirm(t("rbac.deleteConfirm"))) return;
    setBusy(true);
    try {
      const response = await request(
        `/api/v1/rbac/roles/${encodeURIComponent(editing.id)}?revision=${editing.revision}`,
        { method: "DELETE" },
      );
      if (!response.ok) throw new Error("delete failed");
      edit(null);
      await load();
      await refresh();
    } catch {
      setError(true);
    } finally {
      setBusy(false);
    }
  }
  async function saveBinding(event: FormEvent) {
    event.preventDefault();
    setBusy(true);
    setSaved(false);
    try {
      const response = await request("/api/v1/rbac/bindings", {
        method: "PUT",
        body: JSON.stringify({
          subject_type: subjectType,
          subject_id: subjectID,
          role_ids: roleIDs,
          revision: bindingRevision,
        }),
      });
      if (!response.ok) throw new Error("binding failed");
      const savedBinding = (await response.json()) as Binding;
      setBindingRevision(savedBinding.revision);
      await load();
      await refresh();
      setSaved(true);
    } catch {
      setError(true);
    } finally {
      setBusy(false);
    }
  }
  const roleName = (role: Role) =>
    role.builtin
      ? t(`${organization ? "organization.builtins" : "rbac.builtins"}.${role.id}`)
      : role.name;
  const subjects = subjectType === "user" ? users : groups;
  if (!ready) return <p className="placeholder">{t("placeholder.skeleton")}</p>;
  if (!canManage)
    return (
      <section className="jobs-page">
        <h1>{t(organization ? "organization.rolesTitle" : "rbac.title")}</h1>
        <p>{t("rbac.denied")}</p>
      </section>
    );
  return (
    <section className="jobs-page rbac-page">
      <header className="jobs-heading">
        <div>
          <h1>{t(organization ? "organization.rolesTitle" : "rbac.title")}</h1>
          <p>{t(organization ? "organization.rolesDescription" : "rbac.description")}</p>
        </div>
        <button
          type="button"
          disabled={busy}
          onClick={() => {
            void load();
            void refresh();
          }}
        >
          {t("rbac.refresh")}
        </button>
      </header>
      {error && (
        <p role="alert" className="login-error">
          {t("rbac.error")}
        </p>
      )}
      {saved && <p role="status">{t("rbac.saved")}</p>}
      <div className="rbac-columns">
        <section>
          <h2>{t("rbac.roles")}</h2>
          <label>
            {t("rbac.editRole")}
            <select
              value={editing?.id || ""}
              onChange={(e) => edit(roles.find((r) => r.id === e.target.value) || null)}
            >
              <option value="">{t("rbac.newRole")}</option>
              {roles.map((r) => (
                <option key={r.id} value={r.id}>
                  {roleName(r)}
                </option>
              ))}
            </select>
          </label>
          <form
            onSubmit={(e) => {
              void saveRole(e);
            }}
            className="rbac-form"
          >
            <label>
              {t("rbac.name")}
              <input
                required
                maxLength={80}
                value={name}
                disabled={editing?.builtin}
                onChange={(e) => setName(e.target.value)}
              />
            </label>
            <label>
              {t("rbac.roleDescription")}
              <input
                maxLength={500}
                value={description}
                disabled={editing?.builtin}
                onChange={(e) => setDescription(e.target.value)}
              />
            </label>
            {editing?.builtin && <p>{t("rbac.immutable")}</p>}
            <fieldset disabled={editing?.builtin}>
              <legend>
                {t(organization ? "organization.permissionsTitle" : "rbac.permissions")}
              </legend>
              {catalog.map((p) => (
                <label className="rbac-check" key={p}>
                  <input
                    type="checkbox"
                    checked={permissions.includes(p)}
                    onChange={(e) =>
                      setPermissions((prev) =>
                        e.target.checked ? [...prev, p] : prev.filter((value) => value !== p),
                      )
                    }
                  />
                  <span>
                    {t(
                      organization && p === "roles.manage"
                        ? "organization.roleManagePermission"
                        : `rbac.permissionsList.${p.replaceAll(".", "_")}`,
                    )}
                    <small>{p}</small>
                  </span>
                </label>
              ))}
            </fieldset>
            <div>
              <button type="submit" disabled={busy || editing?.builtin}>
                {t("rbac.saveRole")}
              </button>
              {editing && !editing.builtin && (
                <button
                  type="button"
                  disabled={busy}
                  onClick={() => {
                    void deleteRole();
                  }}
                >
                  {t("rbac.deleteRole")}
                </button>
              )}
            </div>
          </form>
        </section>
        <section>
          <h2>{t("rbac.bindings")}</h2>
          <p>{t("rbac.bindingHint")}</p>
          <form
            className="rbac-form"
            onSubmit={(e) => {
              void saveBinding(e);
            }}
          >
            <label>
              {t("rbac.subjectType")}
              <select value={subjectType} onChange={(e) => chooseSubject(e.target.value, "")}>
                <option value="user">{t("rbac.user")}</option>
                <option value="group">{t("rbac.group")}</option>
              </select>
            </label>
            <label>
              {t("rbac.subject")}
              <select
                required
                value={subjectID}
                onChange={(e) => chooseSubject(subjectType, e.target.value)}
              >
                <option value="">{t("rbac.chooseSubject")}</option>
                {subjects.map((s) => (
                  <option key={s.id} value={s.id}>
                    {s.username || s.name}
                  </option>
                ))}
              </select>
            </label>
            <fieldset disabled={!subjectID}>
              <legend>{t("rbac.assignedRoles")}</legend>
              {roles.map((r) => (
                <label className="rbac-check" key={r.id}>
                  <input
                    type="checkbox"
                    checked={roleIDs.includes(r.id)}
                    onChange={(e) =>
                      setRoleIDs((prev) =>
                        e.target.checked ? [...prev, r.id] : prev.filter((id) => id !== r.id),
                      )
                    }
                  />
                  {roleName(r)}
                </label>
              ))}
            </fieldset>
            <button type="submit" disabled={busy || !subjectID}>
              {t("rbac.saveBinding")}
            </button>
          </form>
          <h3>{t("rbac.currentBindings")}</h3>
          <ul>
            {bindings
              .filter((b) => b.role_ids.length > 0)
              .map((b) => (
                <li key={`${b.subject_type}:${b.subject_id}`}>
                  <button type="button" onClick={() => chooseSubject(b.subject_type, b.subject_id)}>
                    {(b.subject_type === "user" ? users : groups).find((s) => s.id === b.subject_id)
                      ?.username ||
                      groups.find((s) => s.id === b.subject_id)?.name ||
                      b.subject_id}
                  </button>
                  <p>
                    {b.role_ids
                      .map((id) => {
                        const r = roles.find((r) => r.id === id);
                        return r ? roleName(r) : id;
                      })
                      .join(", ")}
                  </p>
                </li>
              ))}
          </ul>
        </section>
      </div>
      <h2>{t("rbac.audit")}</h2>
      <div className="jobs-table-scroll">
        <table className="jobs-table">
          <thead>
            <tr>
              <th>{t("rbac.time")}</th>
              <th>{t("rbac.actor")}</th>
              <th>{t("rbac.action")}</th>
              <th>{t("rbac.target")}</th>
              <th>{t("jobs.details")}</th>
            </tr>
          </thead>
          <tbody>
            {audit.map((a) => (
              <tr key={a.id}>
                <td>{new Date(a.at).toLocaleString(i18n.language)}</td>
                <td>{a.actor}</td>
                <td>{t(`rbac.actions.${a.action.replace(".", "_")}`)}</td>
                <td>{a.target}</td>
                <td>
                  <button type="button" onClick={() => setSelectedAudit(a)}>
                    {t("jobs.details")}
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <div className="jobs-pagination">
        <button
          type="button"
          disabled={!offset}
          onClick={() => setOffset(Math.max(0, offset - 50))}
        >
          {t("jobs.previous")}
        </button>
        <span>{t("rbac.auditCount", { count: total })}</span>
        <button
          type="button"
          disabled={offset + 50 >= total}
          onClick={() => setOffset(offset + 50)}
        >
          {t("jobs.next")}
        </button>
      </div>
      {selectedAudit && (
        <section className="jobs-detail" aria-label={t("rbac.changeDetails")}>
          <header>
            <h3>{t("rbac.changeDetails")}</h3>
            <button type="button" onClick={() => setSelectedAudit(null)}>
              {t("jobs.close")}
            </button>
          </header>
          <h4>{t("rbac.before")}</h4>
          <pre>{JSON.stringify(selectedAudit.before || null, null, 2)}</pre>
          <h4>{t("rbac.after")}</h4>
          <pre>{JSON.stringify(selectedAudit.after || null, null, 2)}</pre>
        </section>
      )}
    </section>
  );
}
