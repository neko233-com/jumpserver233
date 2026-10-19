import {
  useCallback,
  useEffect,
  useId,
  useRef,
  useState,
  type FormEvent,
  type ReactNode,
} from "react";
import { useTranslation } from "react-i18next";
import { Link } from "react-router-dom";
import { useAuth } from "../auth/AuthContext";
import { usePermissions } from "../auth/usePermissions";
import OperationScheduleFields from "../components/OperationScheduleFields";
import {
  scheduleDraft,
  schedulePayload,
  type Schedule,
  type ScheduleDraft,
} from "../components/operationSchedules";
import "../i18n/locales/features/asset-discovery/register";
import "./asset-discovery.css";

type Template = {
  protocol: string;
  username: string;
  credential_type?: string;
  key_rotation_enabled?: boolean;
  [key: string]: unknown;
};
type Source = {
  id: string;
  revision: number;
  name: string;
  description: string;
  enabled: boolean;
  targets: string[];
  exclude: string[];
  ports: number[];
  timeout_ms: number;
  concurrency: number;
  gateway_id?: string;
  template: Template;
  credential_configured: boolean;
  address_count: number;
};
type Policy = {
  id: string;
  revision: number;
  source_id: string;
  source_revision: number;
  name: string;
  enabled: boolean;
  name_prefix: string;
  node_id?: string;
  group: string;
  match_cidrs: string[];
  update_existing: boolean;
  overwrite_manual_changes: boolean;
  auto_import: boolean;
  trust_new_ssh_keys: boolean;
  missing_action: string;
  missing_threshold: number;
  schedule?: Schedule;
  next_run_at?: string;
  last_schedule_error?: string;
  skipped_triggers: number;
};
type Finding = {
  id: string;
  revision: number;
  source_revision: number;
  host: string;
  port: number;
  protocol: string;
  open: boolean;
  ssh_verified: boolean;
  host_key_fingerprint?: string;
  last_scanned: string;
  latency_ms: number;
  consecutive_misses: number;
  asset_id?: string;
  sync_state: string;
  sync_error?: string;
};
type Run = {
  id: string;
  source_id: string;
  state: string;
  total: number;
  completed: number;
  reachable: number;
  imported: number;
  updated: number;
  conflicts: number;
  error_code?: string;
  review_id?: string;
  started_at: string;
};
type Audit = {
  at: string;
  actor: { name: string };
  action: string;
  source_id?: string;
  policy_id?: string;
  revision?: number;
  count?: number;
  before?: unknown;
  after?: unknown;
  credential_changed: boolean;
};
type Page<T> = { results: T[]; total: number };
type Draft = Omit<Source, "id" | "address_count" | "credential_configured"> & {
  id?: string;
  request_id: string;
  password: string;
  private_key: string;
  private_key_passphrase: string;
  replace_credential: boolean;
  clear_credential: boolean;
};
type PolicyDraft = Omit<Policy, "id" | "skipped_triggers"> & { id?: string; request_id: string };
type Preview = { token: string; expires_at: string; results: Finding[] };
const root = "/api/v1/asset-discovery";
const protocols = [
  "ssh",
  "rdp",
  "telnet",
  "postgresql",
  "mysql",
  "mariadb",
  "sqlserver",
  "clickhouse",
  "redis",
  "mongodb",
  "kubernetes",
];
const lines = (value: string) =>
  value
    .split(/\r?\n/)
    .map((v) => v.trim())
    .filter(Boolean);
const fresh = (): Draft => ({
  revision: 0,
  request_id: crypto.randomUUID(),
  name: "",
  description: "",
  enabled: true,
  targets: [],
  exclude: [],
  ports: [22],
  timeout_ms: 1000,
  concurrency: 16,
  gateway_id: "",
  template: { protocol: "ssh", username: "", credential_type: "password" },
  password: "",
  private_key: "",
  private_key_passphrase: "",
  replace_credential: false,
  clear_credential: false,
});
const active = (r: Run) => ["scanning", "syncing", "waiting_review"].includes(r.state);

export default function AssetDiscoveryPage() {
  const [previewExpired, setPreviewExpired] = useState(false);
  const { t, i18n } = useTranslation(),
    { accessToken } = useAuth(),
    { allows, ready } = usePermissions(),
    id = useId();
  const [tab, setTab] = useState("sources"),
    [sources, setSources] = useState<Source[]>([]),
    [policies, setPolicies] = useState<Policy[]>([]),
    [runs, setRuns] = useState<Run[]>([]),
    [findings, setFindings] = useState<Finding[]>([]),
    [audit, setAudit] = useState<Audit[]>([]);
  const [sourceID, setSourceID] = useState(""),
    [policyID, setPolicyID] = useState(""),
    [selected, setSelected] = useState<string[]>([]),
    [draft, setDraft] = useState<Draft | null>(null),
    [policyDraft, setPolicyDraft] = useState<PolicyDraft | null>(null),
    [schedule, setSchedule] = useState<ScheduleDraft>(scheduleDraft()),
    [scheduled, setScheduled] = useState(false);
  const [nodes, setNodes] = useState<{ id: string; name: string }[]>([]),
    [gateways, setGateways] = useState<
      { id: string; name: string; protocol?: string; account_disabled?: boolean }[]
    >([]);
  const [busy, setBusy] = useState(false),
    [error, setError] = useState(""),
    [notice, setNotice] = useState(""),
    [preview, setPreview] = useState<Preview | null>(null),
    [confirmTrust, setConfirmTrust] = useState(false),
    [remove, setRemove] = useState<{
      kind: string;
      id: string;
      revision: number;
      name: string;
    } | null>(null),
    [page, setPage] = useState(0),
    [total, setTotal] = useState(0);
  const importRequest = useRef(""),
    runRequest = useRef<{ key: string; value: string } | null>(null),
    lifetime = useRef<AbortController | null>(null);
  useEffect(() => {
    if (!preview) return;
    const timer = window.setTimeout(
      () => setPreviewExpired(true),
      Math.max(0, new Date(preview.expires_at).getTime() - Date.now()),
    );
    return () => window.clearTimeout(timer);
  }, [preview]);
  const canView = allows("assets.discovery.view") && allows("assets.view_all"),
    canManage = allows("assets.discovery.manage"),
    canImport = allows("assets.discovery.import") && allows("assets.manage");
  const label = (key: string) => t(`assetDiscovery.${key}`);
  const stateLabel = (value: string) =>
    t(`assetDiscovery.states.${value}`, { defaultValue: label("unknown") });
  const date = (value?: string) => (value ? new Date(value).toLocaleString(i18n.language) : "—");
  const request = useCallback(
    (path: string, init?: RequestInit) => {
      const headers = new Headers(init?.headers);
      if (accessToken) headers.set("Authorization", `Bearer ${accessToken}`);
      if (init?.body) headers.set("Content-Type", "application/json");
      const signals = [AbortSignal.timeout(30_000)];
      if (init?.signal) signals.push(init.signal);
      if (lifetime.current) signals.push(lifetime.current.signal);
      const target = path === "/api/v1/ops/schedules/preview" ? `${root}/schedules/preview` : path;
      return fetch(target, { ...init, headers, signal: AbortSignal.any(signals) });
    },
    [accessToken],
  );
  const json = useCallback(
    async <T,>(path: string, init?: RequestInit): Promise<T> => {
      const response = await request(path, init);
      if (!response.ok) {
        const body = (await response.json().catch(() => ({}))) as { error_code?: string };
        throw new Error(body.error_code || "discovery_unavailable");
      }
      return response.status === 204 ? (undefined as T) : (response.json() as Promise<T>);
    },
    [request],
  );
  const load = useCallback(
    async (signal?: AbortSignal) => {
      if (!canView) return;
      const [ss, ps, rr] = await Promise.all([
        json<Page<Source>>(`${root}/sources`, { signal }),
        json<Page<Policy>>(`${root}/policies`, { signal }),
        json<Page<Run>>(`${root}/runs?limit=100${sourceID ? `&source_id=${sourceID}` : ""}`, {
          signal,
        }),
      ]);
      if (signal?.aborted) return;
      setSources(ss.results);
      setPolicies(ps.results);
      setRuns(rr.results);
      if (sourceID && tab === "findings") {
        const ff = await json<Page<Finding>>(
          `${root}/findings?source_id=${sourceID}&offset=${page * 100}&limit=100`,
          { signal },
        );
        if (!signal?.aborted) {
          setFindings(ff.results);
          setTotal(ff.total);
        }
      }
      if (tab === "audit") {
        const aa = await json<Page<Audit>>(`${root}/audit?offset=${page * 100}&limit=100`, {
          signal,
        });
        if (!signal?.aborted) {
          setAudit(aa.results);
          setTotal(aa.total);
        }
      }
    },
    [canView, json, page, sourceID, tab],
  );
  useEffect(() => {
    const owner = new AbortController();
    lifetime.current = owner;
    return () => {
      owner.abort();
      lifetime.current = null;
    };
  }, []);
  useEffect(() => {
    const controller = new AbortController();
    let pending = false;
    const refresh = async () => {
      if (pending || controller.signal.aborted) return;
      pending = true;
      try {
        await load(controller.signal);
      } catch {
        if (!controller.signal.aborted) setError("discovery_unavailable");
      } finally {
        pending = false;
      }
    };
    void refresh();
    const timer = window.setInterval(() => {
      if (document.visibilityState === "visible") void refresh();
    }, 3000);
    return () => {
      controller.abort();
      window.clearInterval(timer);
    };
  }, [load]);
  useEffect(() => {
    if (!canManage) return;
    const controller = new AbortController();
    void Promise.all([
      json<{ id: string; name: string }[]>("/api/v1/assets/nodes", { signal: controller.signal }),
      json<{ id: string; name: string; protocol?: string; account_disabled?: boolean }[]>(
        "/api/v1/assets",
        { signal: controller.signal },
      ),
    ])
      .then(([nn, gg]) => {
        if (!controller.signal.aborted) {
          setNodes(nn);
          setGateways(
            gg.filter((g) => (!g.protocol || g.protocol === "ssh") && !g.account_disabled),
          );
        }
      })
      .catch(() => undefined);
    return () => controller.abort();
  }, [canManage, json]);
  async function mutate(work: () => Promise<void>) {
    if (busy) return;
    setBusy(true);
    setError("");
    setNotice("");
    try {
      await work();
      await load();
    } catch (e) {
      if (!lifetime.current?.signal.aborted)
        setError(e instanceof Error ? e.message : "discovery_unavailable");
    } finally {
      setBusy(false);
    }
  }
  function selectSource(value: string) {
    setSourceID(value);
    setPolicyID("");
    setFindings([]);
    setSelected([]);
    setPreview(null);
    setPage(0);
  }
  function edit(source?: Source) {
    setPolicyDraft(null);
    setDraft(
      source
        ? {
            ...fresh(),
            ...source,
            request_id: crypto.randomUUID(),
            template: { ...source.template },
          }
        : fresh(),
    );
  }
  function editPolicy(policy?: Policy) {
    const source = sources.find((s) => s.id === (policy?.source_id || sourceID));
    if (!source) {
      setError("discovery_source_required");
      return;
    }
    setDraft(null);
    setPolicyDraft(
      policy
        ? { ...policy, source_revision: source.revision, request_id: crypto.randomUUID() }
        : {
            revision: 0,
            source_id: source.id,
            source_revision: source.revision,
            request_id: crypto.randomUUID(),
            name: "",
            enabled: true,
            name_prefix: "",
            group: "",
            match_cidrs: [],
            update_existing: false,
            overwrite_manual_changes: false,
            auto_import: false,
            trust_new_ssh_keys: false,
            missing_action: "retain",
            missing_threshold: 2,
          },
    );
    setScheduled(Boolean(policy?.schedule));
    setSchedule(scheduleDraft(policy?.schedule || { kind: "interval", interval_seconds: 3600 }));
  }
  async function saveSource(e: FormEvent) {
    e.preventDefault();
    if (!draft) return;
    const {
      id: source,
      password,
      private_key,
      private_key_passphrase,
      replace_credential,
      clear_credential,
      ...input
    } = draft;
    await mutate(async () => {
      const saved = await json<Source>(`${root}/sources${source ? `/${source}` : ""}`, {
        method: source ? "PUT" : "POST",
        body: JSON.stringify({
          provider: "lan",
          revision: input.revision,
          request_id: input.request_id,
          name: input.name,
          description: input.description,
          enabled: input.enabled,
          targets: input.targets.map((v) => v.trim()).filter(Boolean),
          exclude: input.exclude.map((v) => v.trim()).filter(Boolean),
          ports: input.ports,
          timeout_ms: input.timeout_ms,
          concurrency: input.concurrency,
          gateway_id: input.gateway_id,
          template: input.template,
          ...(clear_credential
            ? { credential: {} }
            : replace_credential
              ? { credential: { password, private_key, private_key_passphrase } }
              : {}),
        }),
      });
      selectSource(saved.id);
      setDraft(null);
      setNotice("saved");
    });
  }
  async function savePolicy(e: FormEvent) {
    e.preventDefault();
    if (!policyDraft) return;
    const { id: policy, ...input } = policyDraft;
    await mutate(async () => {
      const saved = await json<Policy>(`${root}/policies${policy ? `/${policy}` : ""}`, {
        method: policy ? "PUT" : "POST",
        body: JSON.stringify({
          revision: input.revision,
          request_id: input.request_id,
          source_id: input.source_id,
          source_revision: input.source_revision,
          name: input.name,
          enabled: input.enabled,
          name_prefix: input.name_prefix,
          group: input.group,
          node_id: input.node_id,
          match_cidrs: input.match_cidrs.map((v) => v.trim()).filter(Boolean),
          update_existing: input.update_existing,
          overwrite_manual_changes: input.overwrite_manual_changes,
          auto_import: input.auto_import,
          trust_new_ssh_keys: input.trust_new_ssh_keys,
          missing_action: input.missing_action,
          missing_threshold: input.missing_threshold,
          schedule: scheduled ? schedulePayload(schedule) : null,
        }),
      });
      setPolicyID(saved.id);
      setPolicyDraft(null);
      setNotice("saved");
    });
  }
  async function scan() {
    const source = sources.find((s) => s.id === sourceID),
      policy = policies.find((p) => p.id === policyID);
    if (!source) return;
    const key = `${source.id}:${source.revision}:${policy?.id}:${policy?.revision}`;
    if (runRequest.current?.key !== key) runRequest.current = { key, value: crypto.randomUUID() };
    await mutate(async () => {
      await json<Run>(`${root}/runs`, {
        method: "POST",
        body: JSON.stringify({
          source_id: source.id,
          source_revision: source.revision,
          policy_id: policy?.id,
          policy_revision: policy?.revision,
          request_id: runRequest.current!.value,
        }),
      });
      runRequest.current = null;
      setTab("runs");
      setPage(0);
    });
  }
  async function prepare() {
    const source = sources.find((s) => s.id === sourceID),
      policy = policies.find((p) => p.id === policyID);
    if (!source || !policy) return;
    await mutate(async () => {
      const result = await json<Preview>(`${root}/import-preview`, {
        method: "POST",
        body: JSON.stringify({
          source_id: source.id,
          source_revision: source.revision,
          policy_id: policy.id,
          policy_revision: policy.revision,
          findings: findings
            .filter((f) => selected.includes(f.id))
            .map((f) => ({
              id: f.id,
              revision: f.revision,
              host_key_fingerprint: f.host_key_fingerprint,
            })),
        }),
      });
      importRequest.current = crypto.randomUUID();
      setPreviewExpired(false);
      setPreview(result);
      setConfirmTrust(false);
    });
  }
  async function commit() {
    if (!preview) return;
    await mutate(async () => {
      const result = await json<{ imported: number; updated: number; results: Finding[] }>(
        `${root}/import`,
        {
          method: "POST",
          body: JSON.stringify({ token: preview.token, request_id: importRequest.current }),
        },
      );
      setFindings((old) => old.map((f) => result.results.find((r) => r.id === f.id) || f));
      setPreview(null);
      setSelected([]);
      setNotice(result.results.some((f) => f.sync_error) ? "partial" : "imported");
    });
  }
  async function exportCSV() {
    await mutate(async () => {
      const response = await request(`${root}/findings.csv?source_id=${sourceID}`);
      if (!response.ok) throw new Error("discovery_unavailable");
      const url = URL.createObjectURL(await response.blob());
      const a = document.createElement("a");
      a.href = url;
      a.download = "asset-discovery.csv";
      a.click();
      window.setTimeout(() => URL.revokeObjectURL(url), 1000);
    });
  }
  const field = (name: string, control: ReactNode) => (
    <label className="discovery-field">
      {label(name)}
      {control}
    </label>
  );
  const check = (name: string, value: boolean, change: (v: boolean) => void) => (
    <label className="discovery-check">
      <input type="checkbox" checked={value} onChange={(e) => change(e.target.checked)} />
      {label(name)}
    </label>
  );
  if (!ready) return <p role="status">{label("loading")}</p>;
  if (!canView) return <p role="alert">{label("denied")}</p>;
  return (
    <main className="asset-discovery">
      <header>
        <h1>{label("title")}</h1>
        <p>{label("hint")}</p>
      </header>
      {error && (
        <p role="alert">{t(`assetDiscovery.errors.${error}`, { defaultValue: label("failed") })}</p>
      )}
      {notice && <p role="status">{label(notice)}</p>}
      <nav className="discovery-tabs" aria-label={label("sections")}>
        {["sources", "policies", "runs", "findings", "audit"].map((value) => (
          <button
            key={value}
            type="button"
            aria-current={tab === value ? "page" : undefined}
            onClick={() => {
              setTab(value);
              setPage(0);
              setPreview(null);
              setSelected([]);
            }}
          >
            {label(value)}
          </button>
        ))}
      </nav>
      <div className="discovery-toolbar">
        {field(
          "source",
          <select value={sourceID} onChange={(e) => selectSource(e.target.value)}>
            <option value="">{label("chooseSource")}</option>
            {sources.map((s) => (
              <option key={s.id} value={s.id}>
                {s.name}
              </option>
            ))}
          </select>,
        )}
        {field(
          "policy",
          <select
            value={policyID}
            onChange={(e) => {
              setPolicyID(e.target.value);
              setPreview(null);
            }}
          >
            <option value="">{label("scanOnly")}</option>
            {policies
              .filter((p) => p.source_id === sourceID && p.enabled)
              .map((p) => (
                <option key={p.id} value={p.id}>
                  {p.name}
                </option>
              ))}
          </select>,
        )}
        <button
          type="button"
          disabled={
            busy ||
            !sourceID ||
            !allows("assets.discovery.execute") ||
            runs.some((r) => r.source_id === sourceID && active(r))
          }
          onClick={() => void scan()}
        >
          {label("scan")}
        </button>
        <button type="button" disabled={busy} onClick={() => void mutate(async () => undefined)}>
          {label("refresh")}
        </button>
      </div>
      {tab === "sources" && (
        <section>
          <div className="discovery-toolbar">
            {canManage && <button onClick={() => edit()}>{label("addSource")}</button>}
          </div>
          <div className="discovery-scroll">
            <table>
              <thead>
                <tr>
                  {["name", "targets", "ports", "credential", "revision", "controls"].map((k) => (
                    <th key={k}>{label(k)}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {sources.map((s) => (
                  <tr key={s.id}>
                    <th scope="row">
                      {s.name}
                      {!s.enabled && <small>{label("disabled")}</small>}
                    </th>
                    <td>
                      {s.targets.join(", ")}
                      <small>
                        {label("addressCount")} {s.address_count}
                      </small>
                    </td>
                    <td>{s.ports.join(", ")}</td>
                    <td>{label(s.credential_configured ? "configured" : "discoveryOnly")}</td>
                    <td>{s.revision}</td>
                    <td>
                      <button
                        onClick={() => {
                          selectSource(s.id);
                          setTab("findings");
                        }}
                      >
                        {label("findings")}
                      </button>
                      {canManage && (
                        <>
                          <button onClick={() => edit(s)}>{label("edit")}</button>
                          <button
                            onClick={() =>
                              setRemove({
                                kind: "sources",
                                id: s.id,
                                revision: s.revision,
                                name: s.name,
                              })
                            }
                          >
                            {label("delete")}
                          </button>
                        </>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          {!sources.length && <p>{label("empty")}</p>}
        </section>
      )}
      {tab === "policies" && (
        <section>
          {canManage && (
            <button disabled={!sourceID} onClick={() => editPolicy()}>
              {label("addPolicy")}
            </button>
          )}
          <div className="discovery-scroll">
            <table>
              <thead>
                <tr>
                  {["name", "source", "mode", "nextRun", "controls"].map((k) => (
                    <th key={k}>{label(k)}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {policies
                  .filter((p) => !sourceID || p.source_id === sourceID)
                  .map((p) => (
                    <tr key={p.id}>
                      <th scope="row">
                        {p.name}
                        <small>{p.enabled ? label("enabled") : label("disabled")}</small>
                      </th>
                      <td>
                        {sources.find((s) => s.id === p.source_id)?.name} · {p.source_revision}
                      </td>
                      <td>
                        {label(p.auto_import ? "automatic" : "manual")}
                        <small>{p.last_schedule_error && stateLabel(p.last_schedule_error)}</small>
                      </td>
                      <td>
                        {date(p.next_run_at)}
                        <small>
                          {label("skipped")} {p.skipped_triggers}
                        </small>
                      </td>
                      <td>
                        {canManage && (
                          <>
                            <button onClick={() => editPolicy(p)}>{label("edit")}</button>
                            <button
                              onClick={() =>
                                setRemove({
                                  kind: "policies",
                                  id: p.id,
                                  revision: p.revision,
                                  name: p.name,
                                })
                              }
                            >
                              {label("delete")}
                            </button>
                          </>
                        )}
                      </td>
                    </tr>
                  ))}
              </tbody>
            </table>
          </div>
        </section>
      )}
      {tab === "runs" && (
        <div className="discovery-scroll">
          <table>
            <thead>
              <tr>
                {["started", "state", "progress", "results", "controls"].map((k) => (
                  <th key={k}>{label(k)}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {runs.map((r) => (
                <tr key={r.id}>
                  <td>
                    {date(r.started_at)}
                    <small>
                      <code>{r.id}</code>
                    </small>
                  </td>
                  <td>
                    {stateLabel(r.state)}
                    {r.error_code && <small>{stateLabel(r.error_code)}</small>}
                  </td>
                  <td>
                    <progress
                      max={Math.max(r.total, 1)}
                      value={r.completed}
                      aria-label={label("progress")}
                    />{" "}
                    {r.completed}/{r.total}
                  </td>
                  <td>
                    {label("reachable")} {r.reachable} · {label("importedCount")} {r.imported} ·{" "}
                    {label("updated")} {r.updated} · {label("conflicts")} {r.conflicts}
                  </td>
                  <td>
                    {r.review_id && <Link to="/console/settings">{label("review")}</Link>}
                    {active(r) && allows("assets.discovery.execute") && (
                      <button
                        disabled={busy}
                        onClick={() =>
                          void mutate(async () => {
                            await json(`${root}/runs/${r.id}/cancel`, { method: "POST" });
                          })
                        }
                      >
                        {label("cancelRun")}
                      </button>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      {tab === "findings" && (
        <section>
          <p>{label("probeHint")}</p>
          <div className="discovery-toolbar">
            <button
              disabled={!canImport || busy || !selected.length || !policyID}
              onClick={() => void prepare()}
            >
              {label("preview")}
            </button>
            {allows("assets.discovery.export") && (
              <button disabled={busy || !sourceID} onClick={() => void exportCSV()}>
                {label("export")}
              </button>
            )}
            <span>
              {label("selected")} {selected.length}
            </span>
          </div>
          <div className="discovery-scroll">
            <table>
              <thead>
                <tr>
                  <th>{label("select")}</th>
                  {["host", "protocol", "fingerprint", "state", "lastScanned"].map((k) => (
                    <th key={k}>{label(k)}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {findings.map((f) => (
                  <tr key={f.id}>
                    <td>
                      <input
                        type="checkbox"
                        aria-label={`${label("select")} ${f.host}:${f.port}`}
                        checked={selected.includes(f.id)}
                        disabled={
                          !canImport ||
                          !f.open ||
                          (f.protocol === "ssh" && !f.ssh_verified) ||
                          f.source_revision !== sources.find((s) => s.id === sourceID)?.revision
                        }
                        onChange={(e) => {
                          setSelected((old) =>
                            e.target.checked ? [...old, f.id] : old.filter((v) => v !== f.id),
                          );
                          setPreview(null);
                        }}
                      />
                    </td>
                    <th scope="row">
                      {f.host}:{f.port}
                      <small>{f.latency_ms} ms</small>
                    </th>
                    <td>{f.protocol}</td>
                    <td>
                      <code>{f.host_key_fingerprint || "—"}</code>
                    </td>
                    <td>
                      {stateLabel(f.sync_state)}
                      <small>
                        {label(f.open ? "reachable" : "unreachable")}
                        {f.sync_error && ` · ${stateLabel(f.sync_error)}`}
                      </small>
                      {f.asset_id && <Link to="/console">{label("inventory")}</Link>}
                    </td>
                    <td>{date(f.last_scanned)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          {!sourceID && <p>{label("chooseSource")}</p>}
        </section>
      )}
      {preview && (
        <section className="discovery-preview" aria-labelledby={`${id}-preview`}>
          <h2 id={`${id}-preview`}>{label("preview")}</h2>
          <p>
            {label("previewHint")} {date(preview.expires_at)}
          </p>
          <ul>
            {preview.results.map((f) => (
              <li key={f.id}>
                {f.host}:{f.port} · <code>{f.host_key_fingerprint || f.protocol}</code>
              </li>
            ))}
          </ul>
          {check("acceptPins", confirmTrust, setConfirmTrust)}
          <button disabled={busy || !confirmTrust || previewExpired} onClick={() => void commit()}>
            {label("commit")}
          </button>
          <button disabled={busy} onClick={() => setPreview(null)}>
            {label("close")}
          </button>
        </section>
      )}
      {tab === "audit" && (
        <div className="discovery-scroll">
          <table>
            <thead>
              <tr>
                {["time", "operator", "action", "results"].map((k) => (
                  <th key={k}>{label(k)}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {audit.map((a, i) => (
                <tr key={`${a.at}-${i}`}>
                  <td>{date(a.at)}</td>
                  <td>{a.actor.name}</td>
                  <td>
                    {t(`assetDiscovery.actions.${a.action}`, { defaultValue: label("unknown") })}
                    {a.credential_changed && <small>{label("credentialChanged")}</small>}
                  </td>
                  <td>
                    {a.revision} {a.count}
                    {Boolean(a.before || a.after) && (
                      <details>
                        <summary>{label("changes")}</summary>
                        <pre>{JSON.stringify({ before: a.before, after: a.after }, null, 2)}</pre>
                      </details>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      {["audit", "findings"].includes(tab) && (
        <div className="discovery-toolbar">
          <button
            disabled={page === 0}
            onClick={() => {
              setPage((p) => p - 1);
              setSelected([]);
              setPreview(null);
            }}
          >
            {label("previous")}
          </button>
          <span>
            {page + 1} / {Math.max(1, Math.ceil(total / 100))}
          </span>
          <button
            disabled={(page + 1) * 100 >= total}
            onClick={() => {
              setPage((p) => p + 1);
              setSelected([]);
              setPreview(null);
            }}
          >
            {label("next")}
          </button>
        </div>
      )}
      {remove && (
        <section role="alert" className="discovery-preview">
          <p>
            {label("deleteConfirm")} <strong>{remove.name}</strong>
          </p>
          <button
            disabled={busy}
            onClick={() =>
              void mutate(async () => {
                await json(`${root}/${remove.kind}/${remove.id}?revision=${remove.revision}`, {
                  method: "DELETE",
                });
                setRemove(null);
                if (sourceID === remove.id) selectSource("");
              })
            }
          >
            {label("delete")}
          </button>
          <button disabled={busy} onClick={() => setRemove(null)}>
            {label("close")}
          </button>
        </section>
      )}
      {draft && (
        <form className="discovery-editor" onSubmit={(e) => void saveSource(e)}>
          <h2>{label(draft.id ? "editSource" : "addSource")}</h2>
          <fieldset disabled={busy}>
            <div className="discovery-grid">
              {field(
                "name",
                <input
                  required
                  maxLength={120}
                  value={draft.name}
                  onChange={(e) => setDraft({ ...draft, name: e.target.value })}
                />,
              )}
              {field(
                "description",
                <input
                  maxLength={500}
                  value={draft.description}
                  onChange={(e) => setDraft({ ...draft, description: e.target.value })}
                />,
              )}
              {field(
                "targets",
                <textarea
                  required
                  rows={3}
                  value={draft.targets.join("\n")}
                  onChange={(e) => setDraft({ ...draft, targets: e.target.value.split(/\r?\n/) })}
                />,
              )}
              {field(
                "exclude",
                <textarea
                  rows={3}
                  value={draft.exclude.join("\n")}
                  onChange={(e) => setDraft({ ...draft, exclude: e.target.value.split(/\r?\n/) })}
                />,
              )}
              {field(
                "ports",
                <input
                  required
                  value={draft.ports.join(",")}
                  onChange={(e) =>
                    setDraft({ ...draft, ports: e.target.value.split(",").map(Number) })
                  }
                />,
              )}
              {field(
                "protocol",
                <select
                  value={draft.template.protocol}
                  onChange={(e) =>
                    setDraft({
                      ...draft,
                      template: {
                        protocol: e.target.value,
                        username: draft.template.username,
                        credential_type: "password",
                      },
                    })
                  }
                >
                  {protocols.map((p) => (
                    <option key={p} value={p}>
                      {t(`assetDiscovery.protocols.${p}`)}
                    </option>
                  ))}
                </select>,
              )}
              {field(
                "username",
                <input
                  maxLength={128}
                  autoComplete="off"
                  value={draft.template.username}
                  onChange={(e) =>
                    setDraft({
                      ...draft,
                      template: { ...draft.template, username: e.target.value },
                    })
                  }
                />,
              )}
              {field(
                "gateway",
                <select
                  value={draft.gateway_id || ""}
                  onChange={(e) => setDraft({ ...draft, gateway_id: e.target.value })}
                >
                  <option value="">{label("direct")}</option>
                  {gateways.map((g) => (
                    <option key={g.id} value={g.id}>
                      {g.name}
                    </option>
                  ))}
                </select>,
              )}
            </div>
            <p>{label("rangeHint")}</p>
            {check("enabled", draft.enabled, (v) => setDraft({ ...draft, enabled: v }))}
            <details>
              <summary>{label("advanced")}</summary>
              <div className="discovery-grid">
                {field(
                  "timeout",
                  <input
                    type="number"
                    min={100}
                    max={5000}
                    value={draft.timeout_ms}
                    onChange={(e) => setDraft({ ...draft, timeout_ms: +e.target.value })}
                  />,
                )}
                {field(
                  "concurrency",
                  <input
                    type="number"
                    min={1}
                    max={32}
                    value={draft.concurrency}
                    onChange={(e) => setDraft({ ...draft, concurrency: +e.target.value })}
                  />,
                )}
                <ProtocolFields
                  value={draft.template}
                  onChange={(value) => setDraft({ ...draft, template: value })}
                />
              </div>
            </details>
            <fieldset>
              <legend>{label("credential")}</legend>
              <p>{label("credentialHint")}</p>
              {check("replaceCredential", draft.replace_credential, (v) =>
                setDraft({ ...draft, replace_credential: v, clear_credential: false }),
              )}
              {draft.id &&
                check("clearCredential", draft.clear_credential, (v) =>
                  setDraft({
                    ...draft,
                    clear_credential: v,
                    replace_credential: false,
                    password: "",
                    private_key: "",
                    private_key_passphrase: "",
                  }),
                )}
              {draft.replace_credential && (
                <div className="discovery-grid">
                  {draft.template.protocol === "ssh" &&
                    field(
                      "credentialType",
                      <select
                        value={draft.template.credential_type}
                        onChange={(e) =>
                          setDraft({
                            ...draft,
                            template: { ...draft.template, credential_type: e.target.value },
                            password: "",
                            private_key: "",
                            private_key_passphrase: "",
                          })
                        }
                      >
                        <option value="password">{label("password")}</option>
                        <option value="ssh_key">{label("privateKey")}</option>
                      </select>,
                    )}
                  {draft.template.credential_type === "ssh_key" ? (
                    <>
                      {field(
                        "privateKey",
                        <textarea
                          required
                          autoComplete="off"
                          spellCheck={false}
                          value={draft.private_key}
                          onChange={(e) => setDraft({ ...draft, private_key: e.target.value })}
                        />,
                      )}
                      {field(
                        "passphrase",
                        <input
                          type="password"
                          autoComplete="new-password"
                          value={draft.private_key_passphrase}
                          onChange={(e) =>
                            setDraft({ ...draft, private_key_passphrase: e.target.value })
                          }
                        />,
                      )}
                      {check("keyRotation", Boolean(draft.template.key_rotation_enabled), (v) =>
                        setDraft({
                          ...draft,
                          template: { ...draft.template, key_rotation_enabled: v },
                        }),
                      )}
                    </>
                  ) : (
                    field(
                      "password",
                      <input
                        required
                        type="password"
                        autoComplete="new-password"
                        value={draft.password}
                        onChange={(e) => setDraft({ ...draft, password: e.target.value })}
                      />,
                    )
                  )}
                </div>
              )}
            </fieldset>
            <p>{label("sourceChangeHint")}</p>
            <button type="submit">{label("save")}</button>
            <button type="button" onClick={() => setDraft(null)}>
              {label("close")}
            </button>
          </fieldset>
        </form>
      )}
      {policyDraft && (
        <form className="discovery-editor" onSubmit={(e) => void savePolicy(e)}>
          <h2>{label("editPolicy")}</h2>
          <fieldset disabled={busy}>
            <p>
              {label("pinnedSource")} {sources.find((s) => s.id === policyDraft.source_id)?.name} ·{" "}
              {policyDraft.source_revision}
            </p>
            <div className="discovery-grid">
              {field(
                "name",
                <input
                  required
                  maxLength={120}
                  value={policyDraft.name}
                  onChange={(e) => setPolicyDraft({ ...policyDraft, name: e.target.value })}
                />,
              )}
              {field(
                "prefix",
                <input
                  maxLength={40}
                  value={policyDraft.name_prefix}
                  onChange={(e) => setPolicyDraft({ ...policyDraft, name_prefix: e.target.value })}
                />,
              )}
              {field(
                "group",
                <input
                  maxLength={120}
                  value={policyDraft.group}
                  onChange={(e) => setPolicyDraft({ ...policyDraft, group: e.target.value })}
                />,
              )}
              {field(
                "node",
                <select
                  value={policyDraft.node_id || ""}
                  onChange={(e) => setPolicyDraft({ ...policyDraft, node_id: e.target.value })}
                >
                  <option value="">{label("noNode")}</option>
                  {nodes.map((n) => (
                    <option key={n.id} value={n.id}>
                      {n.name}
                    </option>
                  ))}
                </select>,
              )}
              {field(
                "matchCIDRs",
                <textarea
                  value={policyDraft.match_cidrs.join("\n")}
                  onChange={(e) =>
                    setPolicyDraft({ ...policyDraft, match_cidrs: e.target.value.split(/\r?\n/) })
                  }
                />,
              )}
            </div>
            {check("enabled", policyDraft.enabled, (v) =>
              setPolicyDraft({ ...policyDraft, enabled: v }),
            )}
            {check("updateExisting", policyDraft.update_existing, (v) =>
              setPolicyDraft({
                ...policyDraft,
                update_existing: v,
                overwrite_manual_changes: v && policyDraft.overwrite_manual_changes,
              }),
            )}
            {policyDraft.update_existing &&
              check("overwrite", policyDraft.overwrite_manual_changes, (v) =>
                setPolicyDraft({ ...policyDraft, overwrite_manual_changes: v }),
              )}
            {check("autoImport", policyDraft.auto_import, (v) =>
              setPolicyDraft({ ...policyDraft, auto_import: v }),
            )}
            {policyDraft.auto_import &&
              check("trustNewKeys", policyDraft.trust_new_ssh_keys, (v) =>
                setPolicyDraft({ ...policyDraft, trust_new_ssh_keys: v }),
              )}
            {field(
              "missing",
              <select
                value={policyDraft.missing_action}
                onChange={(e) => setPolicyDraft({ ...policyDraft, missing_action: e.target.value })}
              >
                <option value="retain">{label("retain")}</option>
                <option value="disable">{label("disableMissing")}</option>
              </select>,
            )}
            {policyDraft.missing_action === "disable" &&
              field(
                "misses",
                <input
                  type="number"
                  min={1}
                  max={10}
                  value={policyDraft.missing_threshold}
                  onChange={(e) =>
                    setPolicyDraft({ ...policyDraft, missing_threshold: +e.target.value })
                  }
                />,
              )}
            <p>{label("policyHint")}</p>
            {check("scheduled", scheduled, setScheduled)}
            {scheduled && (
              <OperationScheduleFields
                allowBatch={false}
                value={schedule}
                onChange={setSchedule}
                request={request}
              />
            )}
            <button type="submit">{label("save")}</button>
            <button type="button" onClick={() => setPolicyDraft(null)}>
              {label("close")}
            </button>
          </fieldset>
        </form>
      )}
    </main>
  );
}

function ProtocolFields({
  value,
  onChange,
}: {
  value: Template;
  onChange: (value: Template) => void;
}) {
  const { t } = useTranslation();
  const protocol = value.protocol,
    db = !["ssh", "rdp", "telnet", "kubernetes"].includes(protocol),
    key = protocol === "mariadb" ? "mysql" : protocol;
  const settings = (value[key] || {}) as Record<string, unknown>,
    patch = (change: Record<string, unknown>) =>
      onChange({ ...value, [key]: { ...settings, ...change } });
  const field = (name: string, kind = "text") => (
    <label className="discovery-field" key={name}>
      {t(`assetDiscovery.fields.${name}`)}
      <input
        type={kind}
        value={String(settings[name] || "")}
        onChange={(e) => patch({ [name]: e.target.value })}
      />
    </label>
  );
  if (protocol === "ssh") return null;
  return (
    <>
      {db && (
        <>
          {field("database")}
          {protocol === "mongodb" && field("auth_database")}
          <label className="discovery-field">
            {t("assetDiscovery.fields.tls_mode")}
            <select
              value={String(settings.tls_mode || "verify-full")}
              onChange={(e) => patch({ tls_mode: e.target.value })}
            >
              <option value="verify-full">{t("assetDiscovery.verifyTLS")}</option>
              <option value="disable">{t("assetDiscovery.disableTLS")}</option>
            </select>
          </label>
        </>
      )}
      {field("server_name")}
      <label className="discovery-field">
        {t("assetDiscovery.fields.root_ca_pem")}
        <textarea
          value={String(settings.root_ca_pem || "")}
          onChange={(e) => patch({ root_ca_pem: e.target.value })}
        />
      </label>
      {protocol === "rdp" && (
        <>
          {field("domain")}
          <label className="discovery-field">
            {t("assetDiscovery.fields.security")}
            <select
              value={String(settings.security || "nla")}
              onChange={(e) => patch({ security: e.target.value })}
            >
              <option value="nla">NLA</option>
              <option value="tls">TLS</option>
            </select>
          </label>
        </>
      )}
      {protocol === "telnet" && (
        <>
          {["login_prompt", "password_prompt", "success_prompt"].map((name) => field(name))}
          <label className="discovery-field">
            {t("assetDiscovery.fields.tls_mode")}
            <select
              value={String(settings.tls_mode || "verify-full")}
              onChange={(e) => patch({ tls_mode: e.target.value })}
            >
              <option value="verify-full">{t("assetDiscovery.verifyTLS")}</option>
              <option value="disable">{t("assetDiscovery.disableTLS")}</option>
            </select>
          </label>
        </>
      )}
      {protocol === "kubernetes" && (
        <>
          {["namespaces", "shell"].map((name) => (
            <label key={name} className="discovery-field">
              {t(`assetDiscovery.fields.${name}`)}
              <textarea
                value={((settings[name] || []) as string[]).join("\n")}
                onChange={(e) => patch({ [name]: lines(e.target.value) })}
              />
            </label>
          ))}
        </>
      )}
    </>
  );
}
