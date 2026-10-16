import { useCallback, useEffect, useState } from "react";
import { useTranslation } from "react-i18next";
import { useAuth } from "../auth/AuthContext";
import {
  ORGANIZATIONS_CHANGED,
  selectedOrganization,
  switchOrganization,
} from "../auth/organization";

type Organization = {
  id: string;
  name: string;
  description: string;
  enabled: boolean;
  revision: number;
  builtin: boolean;
  archived_at?: string;
  member_role: string;
  can_manage_members: boolean;
};
type Member = {
  user_id: string;
  username: string;
  role: string;
  revision: number;
  implicit: boolean;
};
type Audit = { id: string; at: string; actor_id: string; action: string; user_id?: string };
export default function OrganizationsPage() {
  const { t, i18n } = useTranslation();
  const { accessToken } = useAuth();
  const [rows, setRows] = useState<Organization[]>([]);
  const [canManage, setCanManage] = useState(false);
  const [selected, setSelected] = useState("");
  const [members, setMembers] = useState<Member[]>([]);
  const [audit, setAudit] = useState<Audit[]>([]);
  const [editing, setEditing] = useState<Partial<Organization> | null>(null);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const [memberName, setMemberName] = useState("");
  const [memberRole, setMemberRole] = useState("member");
  const [showArchived, setShowArchived] = useState(false);
  const [confirmation, setConfirmation] = useState<{
    organization: Organization;
    restore: boolean;
  } | null>(null);
  const request = useCallback(
    (path: string, init?: RequestInit) => {
      const headers = new Headers(init?.headers);
      if (accessToken) headers.set("Authorization", `Bearer ${accessToken}`);
      if (init?.body) headers.set("Content-Type", "application/json");
      return fetch(path, { ...init, headers });
    },
    [accessToken],
  );
  const problem = async (response: Response) => {
    const data = (await response.json()) as { code?: string };
    return (data.code || "organization_unavailable").replace("organization_", "");
  };
  const load = useCallback(
    async (signal?: AbortSignal) => {
      const response = await request(`/api/v1/organizations?include_archived=${showArchived}`, {
        signal,
      });
      if (!response.ok) throw new Error("organizations unavailable");
      const data = (await response.json()) as { results: Organization[]; can_manage: boolean };
      if (!signal?.aborted) {
        setRows(data.results);
        setCanManage(data.can_manage);
        window.dispatchEvent(new Event(ORGANIZATIONS_CHANGED));
      }
    },
    [request, showArchived],
  );
  const loadMembers = useCallback(
    async (signal?: AbortSignal) => {
      if (!selected) return;
      const responses = await Promise.all([
        request(`/api/v1/organizations/${selected}/members`, { signal }),
        request(`/api/v1/organizations/${selected}/audit?limit=50&offset=0`, { signal }),
      ]);
      if (responses.some((r) => !r.ok)) throw new Error("organization members unavailable");
      const [users, events] = (await Promise.all(responses.map((r) => r.json()))) as [
        Member[],
        { results: Audit[] },
      ];
      if (!signal?.aborted) {
        setMembers(users);
        setAudit(events.results);
      }
    },
    [request, selected],
  );
  useEffect(() => {
    const c = new AbortController();
    queueMicrotask(() => {
      if (!c.signal.aborted)
        void load(c.signal).catch(() => {
          if (!c.signal.aborted) setError("unavailable");
        });
    });
    return () => c.abort();
  }, [load]);
  useEffect(() => {
    const c = new AbortController();
    queueMicrotask(() => {
      if (!c.signal.aborted)
        void loadMembers(c.signal).catch(() => {
          if (!c.signal.aborted) setError("unavailable");
        });
    });
    return () => c.abort();
  }, [loadMembers]);
  async function save() {
    if (!editing) return;
    setBusy(true);
    setError("");
    try {
      const response = await request(`/api/v1/organizations${editing.id ? "/" + editing.id : ""}`, {
        method: editing.id ? "PUT" : "POST",
        body: JSON.stringify({
          name: editing.name,
          description: editing.description || "",
          enabled: editing.enabled,
          revision: editing.revision || 0,
        }),
      });
      if (!response.ok) {
        setError(await problem(response));
        return;
      }
      setEditing(null);
      await load();
    } catch {
      setError("unavailable");
    } finally {
      setBusy(false);
    }
  }
  async function updateMember(member: Member | undefined, role: string) {
    setBusy(true);
    setError("");
    try {
      const response = await request(`/api/v1/organizations/${selected}/members`, {
        method: "PUT",
        body: JSON.stringify({
          user_id: member?.user_id || "",
          username: member ? undefined : memberName,
          role,
          revision: member?.revision || 0,
        }),
      });
      if (!response.ok) {
        setError(await problem(response));
        return;
      }
      setMemberName("");
      await loadMembers();
      await load();
    } catch {
      setError("unavailable");
    } finally {
      setBusy(false);
    }
  }
  async function archive() {
    if (!confirmation) return;
    setBusy(true);
    setError("");
    try {
      const o = confirmation.organization;
      const response = await request(
        `/api/v1/organizations/${o.id}${confirmation.restore ? "/restore" : ""}?revision=${o.revision}`,
        { method: confirmation.restore ? "POST" : "DELETE" },
      );
      if (!response.ok) {
        setError(await problem(response));
        return;
      }
      setConfirmation(null);
      setSelected("");
      setMembers([]);
      setAudit([]);
      await load();
    } catch {
      setError("unavailable");
    } finally {
      setBusy(false);
    }
  }
  const selectedRow = rows.find((o) => o.id === selected);
  const current = selectedOrganization();
  return (
    <section className="jobs-page organizations-page">
      <header className="jobs-heading">
        <div>
          <h1>{t("organization.title")}</h1>
          <p>{t("organization.description")}</p>
        </div>
        <div className="acl-row-actions">
          <button
            type="button"
            onClick={() => {
              setError("");
              void load().catch(() => setError("unavailable"));
            }}
          >
            {t("acl.refresh")}
          </button>
          {canManage && (
            <button
              type="button"
              onClick={() => setEditing({ name: "", description: "", enabled: true, revision: 0 })}
            >
              {t("organization.create")}
            </button>
          )}
        </div>
      </header>
      {error && (
        <p role="alert" className="login-error">
          {t(
            `organization.errors.${["invalid", "conflict", "not_found", "protected", "capacity", "denied", "system_group"].includes(error) ? error : "unavailable"}`,
          )}
        </p>
      )}
      {canManage && (
        <label>
          <input
            type="checkbox"
            checked={showArchived}
            onChange={(e) => setShowArchived(e.target.checked)}
          />
          {t("organization.showArchived")}
        </label>
      )}
      <div className="jobs-table-scroll">
        <table className="jobs-table" aria-label={t("organization.listLabel")}>
          <thead>
            <tr>
              <th>{t("acl.name")}</th>
              <th>{t("organization.membership")}</th>
              <th>{t("organization.state")}</th>
              <th>{t("acl.operations")}</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((o) => (
              <tr key={o.id}>
                <td>
                  {o.builtin ? t("organization.default") : o.name}
                  <small className="review-request-id">{o.id}</small>
                  <p>{o.description}</p>
                </td>
                <td>{t(`organization.memberRoles.${o.member_role}`)}</td>
                <td>
                  {t(
                    o.archived_at
                      ? "organization.archived"
                      : o.enabled
                        ? "organization.enabled"
                        : "organization.disabled",
                  )}
                </td>
                <td>
                  <div className="acl-row-actions">
                    <button
                      type="button"
                      disabled={!o.enabled || Boolean(o.archived_at) || o.id === current}
                      onClick={() => switchOrganization(o.id)}
                    >
                      {t(o.id === current ? "organization.current" : "organization.switch")}
                    </button>
                    {o.can_manage_members && (
                      <button
                        type="button"
                        onClick={() => {
                          setSelected(o.id);
                          setError("");
                        }}
                      >
                        {t("organization.members")}
                      </button>
                    )}
                    {canManage && !o.archived_at && (
                      <button type="button" onClick={() => setEditing({ ...o })}>
                        {t("acl.edit")}
                      </button>
                    )}
                    {canManage && !o.builtin && (
                      <button
                        type="button"
                        onClick={() =>
                          setConfirmation({ organization: o, restore: Boolean(o.archived_at) })
                        }
                      >
                        {t(o.archived_at ? "organization.restore" : "organization.archive")}
                      </button>
                    )}
                  </div>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      {selectedRow && (
        <section>
          <h2>
            {t("organization.membersTitle", {
              name: selectedRow.builtin ? t("organization.default") : selectedRow.name,
            })}
          </h2>
          <p>{t("organization.memberHint")}</p>
          <form
            className="acl-row-actions"
            onSubmit={(e) => {
              e.preventDefault();
              void updateMember(undefined, memberRole);
            }}
          >
            <label>
              {t("login.username")}
              <input required value={memberName} onChange={(e) => setMemberName(e.target.value)} />
            </label>
            <label>
              {t("organization.membership")}
              <select value={memberRole} onChange={(e) => setMemberRole(e.target.value)}>
                {["member", "auditor", "admin"].map((role) => (
                  <option key={role} value={role}>
                    {t(`organization.memberRoles.${role}`)}
                  </option>
                ))}
              </select>
            </label>
            <button type="submit" disabled={busy}>
              {t("organization.addMember")}
            </button>
          </form>
          <table className="jobs-table" aria-label={t("organization.memberListLabel")}>
            <thead>
              <tr>
                <th>{t("login.username")}</th>
                <th>{t("organization.membership")}</th>
                <th>{t("acl.operations")}</th>
              </tr>
            </thead>
            <tbody>
              {members.map((m) => (
                <tr key={m.user_id}>
                  <td>
                    {m.username}
                    {m.implicit && (
                      <small className="review-request-id">{t("organization.implicit")}</small>
                    )}
                  </td>
                  <td>{t(`organization.memberRoles.${m.role}`)}</td>
                  <td>
                    <select
                      aria-label={t("organization.changeRole", { name: m.username })}
                      value={m.role}
                      disabled={busy}
                      onChange={(e) => {
                        void updateMember(m, e.target.value);
                      }}
                    >
                      {["member", "auditor", "admin", "none"].map((role) => (
                        <option key={role} value={role}>
                          {t(`organization.memberRoles.${role}`)}
                        </option>
                      ))}
                    </select>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
          <h2>{t("organization.audit")}</h2>
          <table className="jobs-table">
            <thead>
              <tr>
                <th>{t("acl.at")}</th>
                <th>{t("acl.action")}</th>
                <th>{t("platformReview.reviewer")}</th>
              </tr>
            </thead>
            <tbody>
              {audit.map((a) => (
                <tr key={a.id}>
                  <td>{new Date(a.at).toLocaleString(i18n.language)}</td>
                  <td>
                    {t(`organization.auditActions.${a.action.replaceAll(".", "_")}`)}
                    {a.user_id && <small className="review-request-id">{a.user_id}</small>}
                  </td>
                  <td>{a.actor_id}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </section>
      )}
      {editing && (
        <div className="asset-modal-backdrop">
          <form
            className="asset-modal"
            role="dialog"
            aria-modal="true"
            aria-label={t("organization.editor")}
            onSubmit={(e) => {
              e.preventDefault();
              void save();
            }}
          >
            <h2>{t(editing.id ? "organization.edit" : "organization.create")}</h2>
            <label>
              {t("acl.name")}
              <input
                required
                maxLength={128}
                value={editing.name || ""}
                onChange={(e) => setEditing({ ...editing, name: e.target.value })}
              />
            </label>
            <label>
              {t("organization.descriptionLabel")}
              <textarea
                maxLength={500}
                value={editing.description || ""}
                onChange={(e) => setEditing({ ...editing, description: e.target.value })}
              />
            </label>
            <label>
              <input
                type="checkbox"
                disabled={editing.builtin}
                checked={editing.enabled || false}
                onChange={(e) => setEditing({ ...editing, enabled: e.target.checked })}
              />
              {t("organization.enabled")}
            </label>
            <p>{t("organization.disableHint")}</p>
            <div className="asset-modal-actions">
              <button type="button" disabled={busy} onClick={() => setEditing(null)}>
                {t("acl.cancel")}
              </button>
              <button type="submit" disabled={busy}>
                {t("organization.save")}
              </button>
            </div>
          </form>
        </div>
      )}
      {confirmation && (
        <div className="asset-modal-backdrop">
          <section
            className="asset-modal"
            role="dialog"
            aria-modal="true"
            aria-label={t(confirmation.restore ? "organization.restore" : "organization.archive")}
          >
            <h2>{t(confirmation.restore ? "organization.restore" : "organization.archive")}</h2>
            <p>{t("organization.archiveHint", { name: confirmation.organization.name })}</p>
            <div className="asset-modal-actions">
              <button type="button" disabled={busy} onClick={() => setConfirmation(null)}>
                {t("acl.cancel")}
              </button>
              <button
                type="button"
                disabled={busy}
                onClick={() => {
                  void archive();
                }}
              >
                {t(confirmation.restore ? "organization.restore" : "organization.archive")}
              </button>
            </div>
          </section>
        </div>
      )}
    </section>
  );
}
