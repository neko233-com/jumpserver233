import { useCallback, useEffect, useState, type FormEvent } from "react";
import { useTranslation } from "react-i18next";
import { useAuth } from "../auth/AuthContext";
import { usePermissions } from "../auth/usePermissions";

type Kind = "login" | "asset" | "method";
type Window = { days: number[]; start: number; end: number };
type Rule = {
  approver_ids: string[];
  approver_group_ids: string[];
  id: string;
  name: string;
  kind: Kind;
  user_id?: string;
  group_id?: string;
  asset_id?: string;
  node_id?: string;
  account?: string;
  sources: string[];
  windows: Window[];
  timezone: string;
  methods: string[];
  action: string;
  priority: number;
  enabled: boolean;
  remark: string;
  revision: number;
};
type Choice = { id: string; name?: string; username?: string };
type Audit = {
  id: string;
  at: string;
  action: string;
  actor_id: string;
  rule_id?: string;
  source_ip?: string;
  method?: string;
  reason?: string;
};
const channels = [
  "rdp",
  "rdp_input",
  "rdp_clipboard_read",
  "rdp_clipboard_write",
  "telnet",
  "kubernetes",
  "database",
  "ssh",
  "sftp",
  "exec",
  "scheduled_exec",
  "credential_rotation",
  "asset_discovery",
  "upload",
  "download",
  "delete",
  "mkdir",
];
const weekdays = [1, 2, 3, 4, 5, 6, 0];
const timeValue = (minute: number) =>
  `${String(Math.floor(minute / 60)).padStart(2, "0")}:${String(minute % 60).padStart(2, "0")}`;
const parseTime = (value: string) => {
  const [hours, minutes] = value.split(":").map(Number);
  return hours * 60 + minutes;
};
const freshRule = (kind: Kind): Rule => ({
  approver_ids: [],
  approver_group_ids: [],
  id: "",
  name: "",
  kind,
  sources: [],
  windows: [],
  timezone: Intl.DateTimeFormat().resolvedOptions().timeZone || "UTC",
  methods: kind === "method" ? ["ssh"] : [],
  action: "deny",
  priority: 50,
  enabled: true,
  remark: "",
  revision: 0,
});

export default function AccessPoliciesPage() {
  const { t, i18n } = useTranslation();
  const { accessToken } = useAuth();
  const { allows, systemAllows, ready } = usePermissions();
  const canManage = allows("access_policies.manage");
  const canPlatform = systemAllows("access_policies.manage");
  const [kind, setKind] = useState<Kind>("login");
  useEffect(() => {
    if (ready && !canPlatform && kind === "login") queueMicrotask(() => setKind("asset"));
  }, [ready, canPlatform, kind]);
  const [rules, setRules] = useState<Rule[]>([]);
  const [users, setUsers] = useState<Choice[]>([]);
  const [groups, setGroups] = useState<Choice[]>([]);
  const [assets, setAssets] = useState<Choice[]>([]);
  const [nodes, setNodes] = useState<Choice[]>([]);
  const [sourceIP, setSourceIP] = useState("");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const [draft, setDraft] = useState<Rule | null>(null);
  const [sources, setSources] = useState("");
  const [subjectType, setSubjectType] = useState("all");
  const [targetType, setTargetType] = useState("all");
  const [deleting, setDeleting] = useState<Rule | null>(null);
  const [audit, setAudit] = useState<Audit[]>([]);
  const [offset, setOffset] = useState(0);
  const [total, setTotal] = useState(0);
  const request = useCallback(
    (path: string, init?: RequestInit) => {
      const headers = new Headers(init?.headers);
      if (accessToken) headers.set("Authorization", `Bearer ${accessToken}`);
      if (init?.body) headers.set("Content-Type", "application/json");
      if (kind === "login") {
        path = path.replace("/api/v1/access-policies", "/api/v1/platform-access-policies");
        if (path === "/api/v1/users" || path === "/api/v1/user-groups")
          path = path.replace("/api/v1/", "/api/v1/system/");
      }
      return fetch(path, { ...init, headers });
    },
    [accessToken, kind],
  );
  const load = useCallback(
    async (signal?: AbortSignal) => {
      const responses = await Promise.all(
        [
          "/api/v1/access-policies",
          "/api/v1/users",
          "/api/v1/user-groups",
          "/api/v1/assets",
          "/api/v1/assets/nodes",
          "/api/v1/access-policies/context",
        ].map((url) => request(url, { signal })),
      );
      if (responses.some((response) => !response.ok)) throw new Error("policy load failed");
      const [policyData, userData, groupData, assetData, nodeData, context] = (await Promise.all(
        responses.map((response) => response.json()),
      )) as [Rule[], Choice[], Choice[], Choice[], Choice[], { source_ip: string }];
      if (signal?.aborted) return;
      setRules(policyData);
      setUsers(userData);
      setGroups(groupData);
      setAssets(assetData);
      setNodes(nodeData);
      setSourceIP(context.source_ip);
    },
    [request],
  );
  const loadAudit = useCallback(
    async (signal?: AbortSignal) => {
      const response = await request(`/api/v1/access-policies/audit?limit=25&offset=${offset}`, {
        signal,
      });
      if (!response.ok) throw new Error("policy audit unavailable");
      const data = (await response.json()) as { results: Audit[]; total: number };
      if (!signal?.aborted) {
        setAudit(data.results);
        setTotal(data.total);
      }
    },
    [request, offset],
  );
  useEffect(() => {
    if (!ready || !canManage || (kind === "login" && !canPlatform)) return;
    const c = new AbortController();
    queueMicrotask(() => {
      if (!c.signal.aborted)
        void load(c.signal).catch(() => {
          if (!c.signal.aborted) setError("unavailable");
        });
    });
    return () => c.abort();
  }, [ready, canManage, load, kind, canPlatform]);
  useEffect(() => {
    if (!ready || !canManage || (kind === "login" && !canPlatform)) return;
    const c = new AbortController();
    queueMicrotask(() => {
      if (!c.signal.aborted)
        void loadAudit(c.signal).catch(() => {
          if (!c.signal.aborted) setError("unavailable");
        });
    });
    return () => c.abort();
  }, [ready, canManage, loadAudit, kind, canPlatform]);
  async function refresh() {
    setError("");
    try {
      await Promise.all([load(), loadAudit()]);
    } catch {
      setError("unavailable");
    }
  }
  function edit(rule: Rule) {
    setDraft(structuredClone(rule));
    setSources(rule.sources.join("\n"));
    setSubjectType(rule.user_id ? "user" : rule.group_id ? "group" : "all");
    setTargetType(rule.asset_id ? "asset" : rule.node_id ? "node" : "all");
    setError("");
  }
  async function write(rule: Rule, remove = false) {
    setBusy(true);
    setError("");
    try {
      const id = rule.id;
      const input = {
        approver_ids: rule.kind === "login" && rule.action === "review" ? rule.approver_ids : [],
        approver_group_ids:
          rule.kind === "login" && rule.action === "review" ? rule.approver_group_ids : [],
        name: rule.name,
        kind: rule.kind,
        user_id: rule.user_id,
        group_id: rule.group_id,
        asset_id: rule.asset_id,
        node_id: rule.node_id,
        account: rule.account,
        sources: rule.sources,
        windows: rule.windows,
        timezone: rule.timezone,
        methods: rule.methods,
        action: rule.action,
        priority: rule.priority,
        enabled: rule.enabled,
        remark: rule.remark,
        revision: rule.revision,
      };
      const response = await request(
        `/api/v1/access-policies${id ? `/${id}` : ""}${remove ? `?revision=${rule.revision}` : ""}`,
        {
          method: remove ? "DELETE" : id ? "PUT" : "POST",
          body: remove ? undefined : JSON.stringify(input),
        },
      );
      if (!response.ok) {
        const result = (await response.json()) as { code?: string };
        const known = ["invalid", "conflict", "lockout", "capacity", "not_found"];
        setError(known.includes(result.code || "") ? result.code! : "unavailable");
        return;
      }
      setDraft(null);
      setDeleting(null);
      await Promise.all([load(), loadAudit()]);
    } catch {
      setError("unavailable");
    } finally {
      setBusy(false);
    }
  }
  function save(event: FormEvent) {
    event.preventDefault();
    if (!draft) return;
    const normalized = {
      ...draft,
      sources: sources
        .split(/[\n,]/)
        .map((value) => value.trim())
        .filter(Boolean),
      user_id: subjectType === "user" ? draft.user_id : "",
      group_id: subjectType === "group" ? draft.group_id : "",
      asset_id: targetType === "asset" && draft.kind === "asset" ? draft.asset_id : "",
      node_id: targetType === "node" && draft.kind === "asset" ? draft.node_id : "",
      account: draft.kind === "asset" ? draft.account : "",
      methods: draft.kind === "login" ? [] : draft.methods,
    };
    void write(normalized);
  }
  const subjectName = (rule: Rule) =>
    users.find((user) => user.id === rule.user_id)?.username ||
    groups.find((group) => group.id === rule.group_id)?.name ||
    rule.user_id ||
    rule.group_id ||
    t("acl.allUsers");
  if (!ready) return <p className="placeholder">{t("placeholder.skeleton")}</p>;
  if (!canManage)
    return (
      <section className="jobs-page">
        <h1>{t("acl.title")}</h1>
        <p>{t("acl.denied")}</p>
      </section>
    );
  return (
    <section className="jobs-page acl-page">
      <header className="jobs-heading">
        <div>
          <h1>{t("acl.title")}</h1>
          <p>{t("acl.description")}</p>
          <p>{t("organization.platformPolicyHint")}</p>
          <p>{t("acl.source", { source: sourceIP })}</p>
        </div>
        <button
          type="button"
          disabled={busy}
          onClick={() => {
            void refresh();
          }}
        >
          {t("acl.refresh")}
        </button>
      </header>
      {error && (
        <p role="alert" className="login-error">
          {t(`acl.errors.${error}`)}
        </p>
      )}
      <div className="acl-tabs" role="group" aria-label={t("acl.kindsLabel")}>
        {((canPlatform ? ["login", "asset", "method"] : ["asset", "method"]) as Kind[]).map(
          (value) => (
            <button
              key={value}
              type="button"
              aria-pressed={kind === value}
              onClick={() => setKind(value)}
            >
              {t(`acl.kinds.${value}`)}
            </button>
          ),
        )}
        <button type="button" onClick={() => edit(freshRule(kind))}>
          {t("acl.new")}
        </button>
      </div>
      <p className="acl-hint">{t("acl.orderHint")}</p>
      <div className="jobs-table-wrap">
        <table className="jobs-table" aria-label={t("acl.rulesLabel")}>
          <thead>
            <tr>
              <th>{t("acl.name")}</th>
              <th>{t("acl.subject")}</th>
              <th>{t("acl.priority")}</th>
              <th>{t("acl.action")}</th>
              <th>{t("acl.enabled")}</th>
              <th>{t("acl.operations")}</th>
            </tr>
          </thead>
          <tbody>
            {rules
              .filter((rule) => rule.kind === kind)
              .map((rule) => (
                <tr key={rule.id}>
                  <td>{rule.name}</td>
                  <td>{subjectName(rule)}</td>
                  <td>{rule.priority}</td>
                  <td>
                    {t(
                      rule.action === "review"
                        ? "platformReview.requireApproval"
                        : rule.action === "notify"
                          ? "platformReview.notify"
                          : `acl.actions.${rule.action}`,
                    )}
                  </td>
                  <td>{t(rule.enabled ? "acl.yes" : "acl.no")}</td>
                  <td>
                    <div className="acl-row-actions">
                      <button type="button" disabled={busy} onClick={() => edit(rule)}>
                        {t("acl.edit")}
                      </button>
                      <button
                        type="button"
                        disabled={busy}
                        onClick={() => {
                          void write({ ...rule, enabled: !rule.enabled });
                        }}
                      >
                        {t(rule.enabled ? "acl.disable" : "acl.enable")}
                      </button>
                      <button
                        type="button"
                        disabled={busy}
                        onClick={() => {
                          setDeleting(rule);
                          setError("");
                        }}
                      >
                        {t("acl.delete")}
                      </button>
                    </div>
                  </td>
                </tr>
              ))}
          </tbody>
        </table>
        {!rules.some((rule) => rule.kind === kind) && <p>{t("acl.empty")}</p>}
      </div>
      <h2>{t("acl.auditTitle")}</h2>
      <p>{t("acl.auditRetention")}</p>
      <div className="jobs-table-wrap">
        <table className="jobs-table">
          <thead>
            <tr>
              <th>{t("acl.at")}</th>
              <th>{t("acl.action")}</th>
              <th>{t("acl.actor")}</th>
              <th>{t("acl.name")}</th>
              <th>{t("acl.sourceLabel")}</th>
              <th>{t("acl.channels")}</th>
            </tr>
          </thead>
          <tbody>
            {audit.map((event) => (
              <tr key={event.id}>
                <td>{new Date(event.at).toLocaleString(i18n.language)}</td>
                <td>{t(`acl.events.${event.action}`)}</td>
                <td>
                  {users.find((user) => user.id === event.actor_id)?.username || event.actor_id}
                </td>
                <td>{rules.find((rule) => rule.id === event.rule_id)?.name || event.rule_id}</td>
                <td>{event.source_ip}</td>
                <td>{event.method ? t(`acl.methods.${event.method}`) : ""}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <div className="acl-row-actions">
        <button
          type="button"
          disabled={offset === 0}
          onClick={() => setOffset(Math.max(0, offset - 25))}
        >
          {t("acl.previous")}
        </button>
        <span>{t("acl.auditCount", { count: total })}</span>
        <button
          type="button"
          disabled={offset + 25 >= total}
          onClick={() => setOffset(offset + 25)}
        >
          {t("acl.next")}
        </button>
      </div>
      {draft && (
        <div className="asset-modal-backdrop">
          <section
            role="dialog"
            aria-modal="true"
            aria-label={t("acl.editor")}
            className="asset-modal acl-editor"
          >
            <h2>{t("acl.editor")}</h2>
            <form className="rbac-form" onSubmit={save}>
              <label>
                {t("acl.name")}
                <input
                  required
                  maxLength={100}
                  value={draft.name}
                  onChange={(e) => setDraft({ ...draft, name: e.target.value })}
                />
              </label>
              <div className="acl-form-grid">
                <label>
                  {t("acl.subject")}
                  <select
                    value={subjectType}
                    onChange={(e) => {
                      setSubjectType(e.target.value);
                      setDraft({ ...draft, user_id: "", group_id: "" });
                    }}
                  >
                    <option value="all">{t("acl.allUsers")}</option>
                    <option value="user">{t("acl.user")}</option>
                    <option value="group">{t("acl.group")}</option>
                  </select>
                </label>
                {subjectType !== "all" && (
                  <label>
                    {t("acl.selectedSubject")}
                    <select
                      required
                      value={subjectType === "user" ? draft.user_id || "" : draft.group_id || ""}
                      onChange={(e) =>
                        setDraft({
                          ...draft,
                          [subjectType === "user" ? "user_id" : "group_id"]: e.target.value,
                        })
                      }
                    >
                      <option value="">{t("acl.choose")}</option>
                      {(subjectType === "user" ? users : groups).map((choice) => (
                        <option key={choice.id} value={choice.id}>
                          {choice.username || choice.name}
                        </option>
                      ))}
                    </select>
                  </label>
                )}
              </div>
              {draft.kind === "asset" && (
                <>
                  <div className="acl-form-grid">
                    <label>
                      {t("acl.target")}
                      <select
                        value={targetType}
                        onChange={(e) => {
                          setTargetType(e.target.value);
                          setDraft({ ...draft, asset_id: "", node_id: "" });
                        }}
                      >
                        <option value="all">{t("acl.allAssets")}</option>
                        <option value="asset">{t("acl.asset")}</option>
                        <option value="node">{t("acl.node")}</option>
                      </select>
                    </label>
                    {targetType !== "all" && (
                      <label>
                        {t("acl.selectedTarget")}
                        <select
                          required
                          value={
                            targetType === "asset" ? draft.asset_id || "" : draft.node_id || ""
                          }
                          onChange={(e) =>
                            setDraft({
                              ...draft,
                              [targetType === "asset" ? "asset_id" : "node_id"]: e.target.value,
                            })
                          }
                        >
                          <option value="">{t("acl.choose")}</option>
                          {(targetType === "asset" ? assets : nodes).map((choice) => (
                            <option key={choice.id} value={choice.id}>
                              {choice.name}
                            </option>
                          ))}
                        </select>
                      </label>
                    )}
                  </div>
                  <label>
                    {t("acl.account")}
                    <input
                      maxLength={128}
                      value={draft.account || ""}
                      onChange={(e) => setDraft({ ...draft, account: e.target.value })}
                    />
                  </label>
                </>
              )}
              <div className="acl-form-grid">
                <label>
                  {t("acl.action")}
                  <select
                    value={draft.action}
                    onChange={(e) => setDraft({ ...draft, action: e.target.value })}
                  >
                    <option value="deny">{t("acl.actions.deny")}</option>
                    <option value="allow">{t("acl.actions.allow")}</option>
                    {draft.kind === "login" && (
                      <>
                        <option value="review">{t("platformReview.requireApproval")}</option>
                        <option value="notify">{t("platformReview.notify")}</option>
                      </>
                    )}
                  </select>
                </label>
                <label>
                  {t("acl.priority")}
                  <input
                    type="number"
                    min={0}
                    max={10000}
                    required
                    value={draft.priority}
                    onChange={(e) => setDraft({ ...draft, priority: Number(e.target.value) })}
                  />
                </label>
              </div>
              {draft.kind === "login" && draft.action === "review" && (
                <fieldset>
                  <legend>{t("platformReview.approvers")}</legend>
                  <p className="acl-hint">{t("platformReview.approversHint")}</p>
                  <label>
                    {t("platformReview.approverUsers")}
                    <select
                      multiple
                      value={draft.approver_ids}
                      onChange={(e) =>
                        setDraft({
                          ...draft,
                          approver_ids: Array.from(
                            e.target.selectedOptions,
                            (option) => option.value,
                          ),
                        })
                      }
                    >
                      {users.map((user) => (
                        <option key={user.id} value={user.id}>
                          {user.username}
                        </option>
                      ))}
                    </select>
                  </label>
                  <label>
                    {t("platformReview.approverGroups")}
                    <select
                      multiple
                      value={draft.approver_group_ids}
                      onChange={(e) =>
                        setDraft({
                          ...draft,
                          approver_group_ids: Array.from(
                            e.target.selectedOptions,
                            (option) => option.value,
                          ),
                        })
                      }
                    >
                      {groups.map((group) => (
                        <option key={group.id} value={group.id}>
                          {group.name}
                        </option>
                      ))}
                    </select>
                  </label>
                </fieldset>
              )}
              <label>
                {t("acl.sources")}
                <textarea
                  value={sources}
                  rows={3}
                  onChange={(e) => setSources(e.target.value)}
                  placeholder={t("acl.sourcesExample")}
                />
              </label>
              <p className="acl-hint">{t("acl.sourcesHint")}</p>
              {draft.kind !== "login" && (
                <fieldset>
                  <legend>{t("acl.channels")}</legend>
                  <p className="acl-hint">{t("acl.channelsHint")}</p>
                  <div className="acl-checks">
                    {channels.map((channel) => (
                      <label key={channel}>
                        <input
                          type="checkbox"
                          checked={draft.methods.includes(channel)}
                          onChange={(e) =>
                            setDraft({
                              ...draft,
                              methods: e.target.checked
                                ? [...draft.methods, channel]
                                : draft.methods.filter((value) => value !== channel),
                            })
                          }
                        />
                        {t(`acl.methods.${channel}`)}
                      </label>
                    ))}
                  </div>
                </fieldset>
              )}
              <details>
                <summary>{t("acl.weekly")}</summary>
                <label>
                  {t("acl.timezone")}
                  <input
                    required
                    value={draft.timezone}
                    maxLength={100}
                    onChange={(e) => setDraft({ ...draft, timezone: e.target.value })}
                  />
                </label>
                <p className="acl-hint">{t("acl.weeklyHint")}</p>
                {draft.windows.map((window, index) => (
                  <fieldset key={index}>
                    <legend>{t("acl.window", { index: index + 1 })}</legend>
                    <div className="acl-checks">
                      {weekdays.map((day) => (
                        <label key={day}>
                          <input
                            type="checkbox"
                            checked={window.days.includes(day)}
                            onChange={(e) =>
                              setDraft({
                                ...draft,
                                windows: draft.windows.map((item, i) =>
                                  i !== index
                                    ? item
                                    : {
                                        ...item,
                                        days: e.target.checked
                                          ? [...item.days, day]
                                          : item.days.filter((value) => value !== day),
                                      },
                                ),
                              })
                            }
                          />
                          {t(`acl.days.${day}`)}
                        </label>
                      ))}
                    </div>
                    <div className="acl-form-grid">
                      <label>
                        {t("acl.start")}
                        <input
                          type="time"
                          required
                          value={timeValue(window.start)}
                          onChange={(e) =>
                            setDraft({
                              ...draft,
                              windows: draft.windows.map((item, i) =>
                                i !== index ? item : { ...item, start: parseTime(e.target.value) },
                              ),
                            })
                          }
                        />
                      </label>
                      <label>
                        {t("acl.end")}
                        <select
                          value={window.end === 1440 ? "midnight" : "time"}
                          onChange={(e) =>
                            setDraft({
                              ...draft,
                              windows: draft.windows.map((item, i) =>
                                i !== index
                                  ? item
                                  : { ...item, end: e.target.value === "midnight" ? 1440 : 1080 },
                              ),
                            })
                          }
                        >
                          <option value="time">{t("acl.specificTime")}</option>
                          <option value="midnight">{t("acl.midnight")}</option>
                        </select>
                        {window.end !== 1440 && (
                          <input
                            type="time"
                            required
                            aria-label={t("acl.endTime", { index: index + 1 })}
                            value={timeValue(window.end)}
                            onChange={(e) =>
                              setDraft({
                                ...draft,
                                windows: draft.windows.map((item, i) =>
                                  i !== index ? item : { ...item, end: parseTime(e.target.value) },
                                ),
                              })
                            }
                          />
                        )}
                      </label>
                    </div>
                    <button
                      type="button"
                      onClick={() =>
                        setDraft({ ...draft, windows: draft.windows.filter((_, i) => i !== index) })
                      }
                    >
                      {t("acl.removeWindow")}
                    </button>
                  </fieldset>
                ))}
                <button
                  type="button"
                  disabled={draft.windows.length >= 32}
                  onClick={() =>
                    setDraft({
                      ...draft,
                      windows: [...draft.windows, { days: [1, 2, 3, 4, 5], start: 540, end: 1080 }],
                    })
                  }
                >
                  {t("acl.addWindow")}
                </button>
              </details>
              <label>
                {t("acl.remark")}
                <textarea
                  maxLength={500}
                  value={draft.remark}
                  onChange={(e) => setDraft({ ...draft, remark: e.target.value })}
                />
              </label>
              <label>
                <input
                  type="checkbox"
                  checked={draft.enabled}
                  onChange={(e) => setDraft({ ...draft, enabled: e.target.checked })}
                />
                {t("acl.enabled")}
              </label>
              {error && (
                <p role="alert" className="login-error">
                  {t(`acl.errors.${error}`)}
                </p>
              )}
              <div className="asset-modal-actions">
                <button
                  type="button"
                  disabled={busy}
                  onClick={() => {
                    setDraft(null);
                    setError("");
                  }}
                >
                  {t("acl.cancel")}
                </button>
                <button type="submit" disabled={busy}>
                  {t("acl.save")}
                </button>
              </div>
            </form>
          </section>
        </div>
      )}
      {deleting && (
        <div className="asset-modal-backdrop">
          <section
            role="dialog"
            aria-modal="true"
            aria-label={t("acl.deleteTitle")}
            className="asset-modal"
          >
            <h2>{t("acl.deleteTitle")}</h2>
            <p>{t("acl.deleteConfirm", { name: deleting.name })}</p>
            <div className="asset-modal-actions">
              <button type="button" disabled={busy} onClick={() => setDeleting(null)}>
                {t("acl.cancel")}
              </button>
              <button
                type="button"
                disabled={busy}
                onClick={() => {
                  void write(deleting, true);
                }}
              >
                {t("acl.deleteTitle")}
              </button>
            </div>
          </section>
        </div>
      )}
    </section>
  );
}
