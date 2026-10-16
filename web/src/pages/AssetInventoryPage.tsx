import { lazy, Suspense, useCallback, useEffect, useMemo, useState, type FormEvent } from "react";
import { useTranslation } from "react-i18next";
import { usePermissions } from "../auth/usePermissions";
import { useAuth } from "../auth/AuthContext";

import RDPSettingsFields, { defaultRDP, type RDPSettings } from "../components/RDPSettingsFields";
const HostPluginsDialog = lazy(() => import("../components/HostPluginsDialog"));
const RDPDesktopDialog = lazy(() => import("../components/RDPDesktopDialog"));
const DatabaseConsoleDialog = lazy(() => import("../components/DatabaseConsoleDialog"));
const KubernetesTerminalDialog = lazy(() => import("../components/KubernetesTerminalDialog"));
const isSSHProtocol = (protocol?: string) => !protocol || protocol === "ssh";
type TelnetSettings = {
  tls_mode: string;
  server_name: string;
  root_ca_pem: string;
  login_prompt: string;
  password_prompt: string;
  success_prompt: string;
};
const defaultTelnet: TelnetSettings = {
  tls_mode: "verify-full",
  server_name: "",
  root_ca_pem: "",
  login_prompt: String.raw`(?im)(?:login|username)\s*:\s*$`,
  password_prompt: String.raw`(?im)password\s*:\s*$`,
  success_prompt: String.raw`(?m)(?:^|[\r\n])[^\r\n]{0,128}[#$>]\s*$`,
};
type KubernetesSettings = {
  namespaces: string[];
  shell: string[];
  server_name: string;
  root_ca_pem: string;
};
const defaultKubernetes: KubernetesSettings = {
  namespaces: ["default"],
  shell: ["/bin/sh"],
  server_name: "",
  root_ca_pem: "",
};
const SSHTerminalDialog = lazy(() => import("../components/SSHTerminalDialog"));
const SFTPFileManagerDialog = lazy(() => import("../components/SFTPFileManagerDialog"));
const CredentialBackupsDialog = lazy(() => import("../components/CredentialBackupsDialog"));

type Metrics = {
  latency_ms: number;
  cpu_cores: number;
  cpu_percent: number;
  memory_total_bytes: number;
  memory_used_bytes: number;
  memory_percent: number;
  network_received_bytes: number;
  network_sent_bytes: number;
  disk_total_bytes: number;
  disk_used_bytes: number;
  disk_percent: number;
};

type Monitor = {
  latency_ms?: number;
  state: "unknown" | "online" | "offline";
  error_code?: string;
  metrics?: Metrics;
  network_received_bytes_per_second: number;
  network_sent_bytes_per_second: number;
};

type PasswordRotation = {
  shared?: boolean;
  state: "scheduled" | "due" | "rotating" | "failed" | "recovery_required";
  last_rotated_at: string;
  next_rotation_at: string;
  error_code?: string;
};

type AssetNode = { id: string; name: string; parent_id?: string };

type SSHKeyRotation = {
  shared?: boolean;
  state: string;
  enabled: boolean;
  pending: boolean;
  can_cancel: boolean;
  request_id?: string;
  operation_id?: string;
  expected_revision?: number;
  next_rotation_at?: string;
  error_code?: string;
};
const isDatabaseProtocol = (protocol?: string) =>
  ["postgresql", "mysql", "mariadb", "sqlserver", "clickhouse", "redis", "mongodb"].includes(
    protocol ?? "",
  );
const databaseEngine = (protocol?: string) =>
  protocol === "mysql"
    ? "MySQL"
    : protocol === "mariadb"
      ? "MariaDB"
      : protocol === "sqlserver"
        ? "SQL Server"
        : protocol === "clickhouse"
          ? "ClickHouse"
          : protocol === "redis"
            ? "Redis"
            : protocol === "mongodb"
              ? "MongoDB"
              : "PostgreSQL";

type PostgreSQLSettings = {
  database: string;
  auth_database?: string;
  tls_mode: string;
  server_name: string;
  root_ca_pem: string;
  read_only: boolean;
};
const defaultPostgreSQL: PostgreSQLSettings = {
  database: "postgres",
  auth_database: "",
  tls_mode: "verify-full",
  server_name: "",
  root_ca_pem: "",
  read_only: true,
};

type Asset = {
  rdp?: RDPSettings;
  telnet?: TelnetSettings;
  kubernetes?: KubernetesSettings;
  protocol?: string;
  postgresql?: PostgreSQLSettings;
  mysql?: PostgreSQLSettings;
  sqlserver?: PostgreSQLSettings;
  clickhouse?: PostgreSQLSettings;
  redis?: PostgreSQLSettings;
  mongodb?: PostgreSQLSettings;
  credential_revision: number;
  key_rotation_enabled?: boolean;
  ssh_key_rotation?: SSHKeyRotation;
  credential_type?: "password" | "ssh_key";
  key_fingerprint?: string;
  id: string;
  name: string;
  host: string;
  port: number;
  group: string;
  node_id?: string;
  username: string;
  host_key_fingerprint: string;
  gateway_id?: string;
  remark: string;
  login_review_required?: boolean;
  monitor: Monitor;
  permissions: string[];
  password_rotation?: PasswordRotation;
};

type AssetForm = {
  rdp_settings: RDPSettings;
  telnet_settings: TelnetSettings;
  kubernetes_settings: KubernetesSettings;
  protocol: string;
  database_settings: PostgreSQLSettings;
  key_rotation_enabled: boolean;
  credential_type: "password" | "ssh_key";
  private_key: string;
  private_key_passphrase: string;
  name: string;
  host: string;
  port: string;
  group: string;
  node_id: string;
  username: string;
  password: string;
  host_key_fingerprint: string;
  gateway_id: string;
  remark: string;
  login_review_required: boolean;
};

const emptyForm: AssetForm = {
  telnet_settings: defaultTelnet,
  rdp_settings: defaultRDP,
  kubernetes_settings: defaultKubernetes,
  protocol: "ssh",
  database_settings: defaultPostgreSQL,
  key_rotation_enabled: false,
  credential_type: "password",
  private_key: "",
  private_key_passphrase: "",
  name: "",
  host: "",
  port: "22",
  group: "",
  node_id: "",
  username: "",
  password: "",
  host_key_fingerprint: "",
  gateway_id: "",
  remark: "",
  login_review_required: false,
};

const unassignedNode = "__unassigned__";

function nodeAncestors(nodes: AssetNode[], nodeID?: string) {
  const byID = new Map(nodes.map((node) => [node.id, node]));
  const result: AssetNode[] = [];
  const seen = new Set<string>();
  let current = nodeID ? byID.get(nodeID) : undefined;
  while (current && !seen.has(current.id)) {
    seen.add(current.id);
    result.push(current);
    current = current.parent_id ? byID.get(current.parent_id) : undefined;
  }
  return result.reverse();
}

function descendantIDs(nodes: AssetNode[], rootID: string) {
  const result = new Set([rootID]);
  let changed = true;
  while (changed) {
    changed = false;
    for (const node of nodes) {
      if (node.parent_id && result.has(node.parent_id) && !result.has(node.id)) {
        result.add(node.id);
        changed = true;
      }
    }
  }
  return result;
}

function formatBytes(bytes: number, perSecond = false) {
  if (!Number.isFinite(bytes) || bytes < 0) return "—";
  const units = perSecond ? ["B/s", "KB/s", "MB/s", "GB/s"] : ["B", "KB", "MB", "GB", "TB"];
  let value = bytes;
  let unit = 0;
  while (value >= 1024 && unit < units.length - 1) {
    value /= 1024;
    unit++;
  }
  return `${value < 10 && unit > 0 ? value.toFixed(1) : Math.round(value)} ${units[unit]}`;
}

function MetricBar({ label, percent, detail }: { label: string; percent: number; detail: string }) {
  const safePercent = Math.max(0, Math.min(100, Number.isFinite(percent) ? percent : 0));
  return (
    <div className="metric-bar-row">
      <span className="metric-label">{label}</span>
      <span className="metric-track" aria-label={`${label} ${safePercent.toFixed(1)}%`}>
        <span
          className={safePercent >= 90 ? "metric-fill warning" : "metric-fill"}
          style={{ width: `${safePercent}%` }}
        />
      </span>
      <span className="metric-detail">{detail}</span>
    </div>
  );
}

function closeDetails(target: HTMLElement) {
  const details = target.closest<HTMLDetailsElement>("details");
  if (details) details.open = false;
}

export default function AssetInventoryPage() {
  const { t, i18n } = useTranslation();
  const { accessToken, setAccessToken } = useAuth();
  const [assets, setAssets] = useState<Asset[]>([]);
  const [nodes, setNodes] = useState<AssetNode[]>([]);
  const [selectedGroup, setSelectedGroup] = useState("");
  const [selectedNode, setSelectedNode] = useState("");
  const [search, setSearch] = useState("");
  const [loading, setLoading] = useState(true);
  const [loadFailed, setLoadFailed] = useState(false);
  const [tokenRequired, setTokenRequired] = useState(false);
  const [tokenRejected, setTokenRejected] = useState(false);
  const [tokenDraft, setTokenDraft] = useState("");
  const [dialogOpen, setDialogOpen] = useState(false);
  const [editingAsset, setEditingAsset] = useState<Asset | null>(null);
  const [form, setForm] = useState<AssetForm>(emptyForm);
  const [saving, setSaving] = useState(false);
  const [saveFailed, setSaveFailed] = useState(false);
  const [saveConflict, setSaveConflict] = useState(false);
  const [rotationConflict, setRotationConflict] = useState(false);
  const [probingId, setProbingId] = useState("");
  const [rotationBusyId, setRotationBusyId] = useState("");
  const [keyBusyId, setKeyBusyId] = useState("");
  const [keyFailed, setKeyFailed] = useState(false);
  const [rotationFailed, setRotationFailed] = useState(false);
  const [credentialBackupsAsset, setCredentialBackupsAsset] = useState<Asset | null>(null);
  const [pluginAsset, setPluginAsset] = useState<Asset | null>(null);
  const [rdpAsset, setRDPAsset] = useState<Asset | null>(null);
  const [kubernetesAsset, setKubernetesAsset] = useState<Asset | null>(null);
  const [terminalAsset, setTerminalAsset] = useState<Asset | null>(null);
  const [databaseAsset, setDatabaseAsset] = useState<Asset | null>(null);
  const [fileAsset, setFileAsset] = useState<Asset | null>(null);
  const { allows } = usePermissions();

  const request = useCallback(
    (url: string, init?: RequestInit) => {
      const headers = new Headers(init?.headers);
      if (accessToken) headers.set("Authorization", `Bearer ${accessToken}`);
      return fetch(url, { ...init, headers });
    },
    [accessToken],
  );

  const loadAssets = useCallback(async () => {
    try {
      const [response, nodeResponse] = await Promise.all([
        request("/api/v1/assets"),
        request("/api/v1/assets/nodes"),
      ]);
      if (response.status === 401) {
        setTokenRequired(true);
        setTokenRejected(Boolean(accessToken));
        setAssets([]);
        setNodes([]);
        setLoadFailed(false);
        return;
      }
      if (!response.ok || !nodeResponse.ok) throw new Error("asset inventory request failed");
      const [result, nextNodes] = await Promise.all([
        response.json() as Promise<Asset[]>,
        nodeResponse.json() as Promise<AssetNode[]>,
      ]);
      setAssets(result);
      setNodes(nextNodes);
      setTokenRequired(false);
      setTokenRejected(false);
      setLoadFailed(false);
    } catch {
      setLoadFailed(true);
    } finally {
      setLoading(false);
    }
  }, [accessToken, request]);

  useEffect(() => {
    // The initial fetch synchronizes the page with server-owned inventory state.
    // eslint-disable-next-line react/set-state-in-effect
    void loadAssets();
    const timer = window.setInterval(() => void loadAssets(), 15_000);
    return () => window.clearInterval(timer);
  }, [loadAssets]);

  const groups = useMemo(() => {
    const counts = new Map<string, number>();
    for (const asset of assets) counts.set(asset.group, (counts.get(asset.group) ?? 0) + 1);
    return [...counts.entries()].sort(([a], [b]) => a.localeCompare(b));
  }, [assets]);

  const treeNodes = useMemo(() => {
    const ordered: Array<{ node: AssetNode; depth: number }> = [];
    const visit = (parentID: string, depth: number) => {
      for (const node of nodes.filter((candidate) => (candidate.parent_id ?? "") === parentID)) {
        ordered.push({ node, depth });
        visit(node.id, depth + 1);
      }
    };
    visit("", 0);
    return ordered;
  }, [nodes]);

  const visibleAssets = useMemo(() => {
    const query = search.trim().toLocaleLowerCase();
    return assets.filter((asset) => {
      if (selectedGroup && asset.group !== selectedGroup) return false;
      if (selectedNode === unassignedNode && asset.node_id) return false;
      if (
        selectedNode &&
        selectedNode !== unassignedNode &&
        (!asset.node_id || !descendantIDs(nodes, selectedNode).has(asset.node_id))
      )
        return false;
      if (!query) return true;
      return `${asset.name} ${asset.host} ${asset.remark}`.toLocaleLowerCase().includes(query);
    });
  }, [assets, nodes, search, selectedGroup, selectedNode]);

  function openCreate() {
    setEditingAsset(null);
    setForm(emptyForm);
    setSaveFailed(false);
    setDialogOpen(true);
  }

  function openEdit(asset: Asset) {
    setEditingAsset(asset);
    setForm({
      protocol: asset.protocol ?? "ssh",
      kubernetes_settings: asset.kubernetes ?? defaultKubernetes,
      telnet_settings: asset.telnet ?? defaultTelnet,
      rdp_settings: asset.rdp ?? defaultRDP,
      database_settings:
        asset.postgresql ??
        asset.mysql ??
        asset.sqlserver ??
        asset.clickhouse ??
        asset.redis ??
        asset.mongodb ??
        defaultPostgreSQL,
      key_rotation_enabled: Boolean(asset.key_rotation_enabled),
      credential_type: asset.credential_type ?? "password",
      private_key: "",
      private_key_passphrase: "",
      name: asset.name,
      host: asset.host,
      port: String(asset.port),
      group: asset.group,
      node_id: asset.node_id ?? "",
      username: asset.username,
      password: "",
      host_key_fingerprint: asset.host_key_fingerprint,
      gateway_id: asset.gateway_id ?? "",
      remark: asset.remark,
      login_review_required: Boolean(asset.login_review_required),
    });
    setSaveFailed(false);
    setDialogOpen(true);
  }

  async function saveAsset(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setSaving(true);
    setSaveFailed(false);
    setSaveConflict(false);
    const { database_settings, kubernetes_settings, telnet_settings, rdp_settings, ...identity } =
      form;
    const payload = {
      ...identity,
      rdp: form.protocol === "rdp" ? rdp_settings : undefined,
      kubernetes: form.protocol === "kubernetes" ? kubernetes_settings : undefined,
      telnet: form.protocol === "telnet" ? telnet_settings : undefined,
      port:
        Number(form.port) ||
        (form.protocol === "rdp"
          ? 3389
          : form.protocol === "kubernetes"
            ? 6443
            : form.protocol === "postgresql"
              ? 5432
              : form.protocol === "sqlserver"
                ? 1433
                : form.protocol === "clickhouse"
                  ? 8443
                  : form.protocol === "redis"
                    ? 6379
                    : form.protocol === "mongodb"
                      ? 27017
                      : isDatabaseProtocol(form.protocol)
                        ? 3306
                        : form.protocol === "telnet"
                          ? telnet_settings.tls_mode === "disable"
                            ? 23
                            : 992
                          : 22),
      postgresql: form.protocol === "postgresql" ? database_settings : undefined,
      mysql:
        form.protocol === "mysql" || form.protocol === "mariadb" ? database_settings : undefined,
      sqlserver: form.protocol === "sqlserver" ? database_settings : undefined,
      clickhouse: form.protocol === "clickhouse" ? database_settings : undefined,
      redis: form.protocol === "redis" ? database_settings : undefined,
      mongodb: form.protocol === "mongodb" ? database_settings : undefined,
    };
    if (editingAsset && !payload.password) delete (payload as Partial<typeof payload>).password;
    try {
      const response = await request(
        editingAsset ? `/api/v1/assets/${editingAsset.id}` : "/api/v1/assets",
        {
          method: editingAsset ? "PUT" : "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(payload),
        },
      );
      if (!response.ok) {
        setSaveConflict((await response.json()).detail === "shared_credential_conflict");
        throw new Error("asset save failed");
      }
      closeAssetDialog();
      await loadAssets();
    } catch {
      setSaveFailed(true);
    } finally {
      setSaving(false);
    }
  }

  function closeAssetDialog() {
    setDialogOpen(false);
    setForm(emptyForm);
    setEditingAsset(null);
  }
  async function probeAsset(asset: Asset) {
    setProbingId(asset.id);
    try {
      const response = await request(`/api/v1/assets/${asset.id}/probe`, { method: "POST" });
      if (!response.ok) throw new Error("asset probe failed");
      await loadAssets();
    } catch {
      setLoadFailed(true);
    } finally {
      setProbingId("");
    }
  }

  async function deleteAsset(asset: Asset) {
    if (!window.confirm(t("assets.deleteConfirm"))) return;
    try {
      const response = await request(`/api/v1/assets/${asset.id}`, { method: "DELETE" });
      if (!response.ok) throw new Error("asset delete failed");
      await loadAssets();
    } catch {
      setLoadFailed(true);
    }
  }

  async function changeSSHKey(asset: Asset, cancel = false) {
    const pending = asset.ssh_key_rotation;
    if (cancel) {
      if (!window.confirm(t("assets.keyCancelConfirm"))) return;
    } else if (
      !pending?.pending &&
      !window.confirm(
        t(
          asset.credential_type === "ssh_key"
            ? asset.ssh_key_rotation?.shared
              ? "assets.sharedKeyRotateConfirm"
              : "assets.keyRotateConfirm"
            : "assets.keyInstallConfirm",
          { name: asset.name },
        ),
      )
    )
      return;
    setKeyBusyId(asset.id);
    setKeyFailed(false);
    try {
      const response = await request(
        `/api/v1/assets/${asset.id}/ssh-key-rotation${cancel ? "/cancel" : ""}`,
        {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(
            cancel
              ? { operation_id: pending?.operation_id }
              : {
                  request_id: pending?.pending ? pending.request_id : crypto.randomUUID(),
                  expected_revision: pending?.pending
                    ? pending.expected_revision
                    : asset.credential_revision,
                },
          ),
        },
      );
      if (!response.ok) throw new Error("SSH key change failed");
    } catch {
      setKeyFailed(true);
    } finally {
      await loadAssets();
      setKeyBusyId("");
    }
  }
  async function rotateAssetPassword(asset: Asset) {
    if (
      !window.confirm(
        t(asset.password_rotation?.shared ? "assets.sharedRotateConfirm" : "assets.rotateConfirm", {
          name: asset.name,
        }),
      )
    )
      return;
    setRotationBusyId(asset.id);
    setRotationFailed(false);
    setRotationConflict(false);
    try {
      const response = await request(`/api/v1/assets/${asset.id}/password-rotation`, {
        method: "POST",
      });
      if (!response.ok) {
        setRotationConflict((await response.json()).detail === "shared_credential_conflict");
        throw new Error("password rotation failed");
      }
      await loadAssets();
    } catch {
      setRotationFailed(true);
    } finally {
      setRotationBusyId("");
    }
  }

  function formatRotationDate(value: string) {
    const date = new Date(value);
    if (Number.isNaN(date.getTime())) return "—";
    const locale = i18n.language === "zh-CN" ? "zh-CN" : "en";
    return new Intl.DateTimeFormat(locale, { dateStyle: "medium" }).format(date);
  }

  function applyToken(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setAccessToken(tokenDraft.trim());
    setTokenRejected(false);
  }

  const closeTerminal = useCallback(() => setTerminalAsset(null), []);
  const closeFileManager = useCallback(() => setFileAsset(null), []);
  const canManage = allows("assets.manage");

  return (
    <section className="asset-inventory">
      <aside className="asset-groups">
        <div className="asset-groups-heading">{t("assets.nodes")}</div>
        <button
          type="button"
          className={!selectedGroup && !selectedNode ? "asset-group active" : "asset-group"}
          onClick={() => {
            setSelectedGroup("");
            setSelectedNode("");
          }}
        >
          <span>{t("assets.allGroups")}</span>
          <span className="group-count">{assets.length}</span>
        </button>
        {treeNodes.map(({ node, depth }) => {
          const inScope = descendantIDs(nodes, node.id);
          const count = assets.filter(
            (asset) => asset.node_id && inScope.has(asset.node_id),
          ).length;
          return (
            <button
              type="button"
              key={node.id}
              className={selectedNode === node.id ? "asset-group active" : "asset-group"}
              style={{ paddingLeft: `${10 + depth * 14}px` }}
              onClick={() => {
                setSelectedNode(node.id);
                setSelectedGroup("");
              }}
            >
              <span className="group-name">{node.name}</span>
              <span className="group-count">{count}</span>
            </button>
          );
        })}
        <button
          type="button"
          className={selectedNode === unassignedNode ? "asset-group active" : "asset-group"}
          onClick={() => {
            setSelectedNode(unassignedNode);
            setSelectedGroup("");
          }}
        >
          <span>{t("assets.unassignedNode")}</span>
          <span className="group-count">{assets.filter((asset) => !asset.node_id).length}</span>
        </button>
        <div className="asset-groups-heading">{t("assets.groups")}</div>
        {groups.map(([group, count]) => (
          <button
            type="button"
            key={group}
            className={selectedGroup === group ? "asset-group active" : "asset-group"}
            onClick={() => {
              setSelectedGroup(group);
              setSelectedNode("");
            }}
          >
            <span className="group-name">{group}</span>
            <span className="group-count">{count}</span>
          </button>
        ))}
      </aside>

      <div className="asset-list-panel">
        <div className="asset-heading-row">
          <div>
            <h2>{t("assets.title")}</h2>
            <p>{t("assets.subtitle")}</p>
          </div>
          <div className="asset-toolbar">
            <label className="asset-search">
              <span aria-hidden="true">⌕</span>
              <input
                value={search}
                onChange={(event) => setSearch(event.target.value)}
                placeholder={t("assets.search")}
              />
            </label>
            <button
              type="button"
              className="button-secondary"
              onClick={() => {
                setLoading(true);
                void loadAssets();
              }}
              disabled={loading}
            >
              {t("assets.refresh")}
            </button>
            {canManage && (
              <button
                type="button"
                className="button-primary"
                onClick={openCreate}
                disabled={tokenRequired}
              >
                + {t("assets.add")}
              </button>
            )}
          </div>
        </div>

        {keyFailed && (
          <p className="asset-error" role="alert">
            {t("assets.keyOperationFailed")}
          </p>
        )}
        {tokenRequired && (
          <form className="asset-token-panel" onSubmit={applyToken}>
            <div>
              <strong>{t("assets.tokenRequired")}</strong>
              {tokenRejected && <p role="alert">{t("assets.tokenRejected")}</p>}
            </div>
            <label>
              <span>{t("assets.tokenLabel")}</span>
              <input
                type="password"
                value={tokenDraft}
                onChange={(event) => setTokenDraft(event.target.value)}
                autoComplete="off"
              />
            </label>
            <button type="submit" className="button-primary">
              {t("assets.tokenApply")}
            </button>
          </form>
        )}

        {loadFailed && (
          <p className="asset-error" role="alert">
            {t("assets.loadError")}
          </p>
        )}
        {rotationFailed && (
          <p className="asset-error" role="alert">
            {t(
              rotationConflict ? "assets.sharedCredentialConflict" : "assets.rotationRequestFailed",
            )}
          </p>
        )}
        <div className="asset-table-wrap">
          <table className="asset-table">
            <thead>
              <tr>
                <th>{t("assets.system")}</th>
                <th>{t("assets.latency")}</th>
                <th>{t("assets.name")}</th>
                <th>{t("assets.address")}</th>
                <th>{t("assets.info")}</th>
                <th>{t("assets.remark")}</th>
                <th>{t("assets.actions")}</th>
              </tr>
            </thead>
            <tbody>
              {visibleAssets.map((asset) => {
                const metrics = asset.monitor.metrics;
                const stateLabel = t(`assets.${asset.monitor.state}`);
                const nodePath = asset.node_id
                  ? nodeAncestors(nodes, asset.node_id)
                      .map((node) => node.name)
                      .join(" / ")
                  : "";
                return (
                  <tr key={asset.id}>
                    <td>
                      <span className="system-badge">Linux</span>
                    </td>
                    <td>
                      <span className={`asset-state ${asset.monitor.state}`} title={stateLabel} />
                      {metrics
                        ? `${metrics.latency_ms} ms`
                        : asset.monitor.latency_ms != null
                          ? `${Math.round(asset.monitor.latency_ms)} ms`
                          : "—"}
                    </td>
                    <td>
                      <div className="asset-name">{asset.name}</div>
                      <div className="asset-subline">
                        {asset.username} · {stateLabel}
                        {nodePath ? ` · ${nodePath}` : ""}
                        {canManage && asset.login_review_required
                          ? ` · ${t("assets.loginReviewRequiredShort")}`
                          : ""}
                      </div>
                      {isDatabaseProtocol(asset.protocol) && (
                        <small>
                          {databaseEngine(asset.protocol)} ·{" "}
                          {
                            (
                              asset.postgresql ??
                              asset.mysql ??
                              asset.sqlserver ??
                              asset.clickhouse ??
                              asset.redis ??
                              asset.mongodb
                            )?.database
                          }
                        </small>
                      )}
                      {asset.credential_type === "ssh_key" && (
                        <div className="rotation-status" title={asset.key_fingerprint}>
                          {t("assets.credentialKey")}
                          {asset.ssh_key_rotation?.shared && <> · {t("assets.sharedKey")}</>}
                        </div>
                      )}
                      {asset.ssh_key_rotation && asset.ssh_key_rotation.state !== "disabled" && (
                        <div
                          className={`rotation-status ${asset.ssh_key_rotation.pending ? "recovery_required" : ""}`}
                        >
                          {t(`assets.keyStates.${asset.ssh_key_rotation.state}`)}
                          {asset.ssh_key_rotation.next_rotation_at && (
                            <>
                              {" "}
                              ·{" "}
                              {t("assets.rotationNext", {
                                date: formatRotationDate(asset.ssh_key_rotation.next_rotation_at),
                              })}
                            </>
                          )}
                          {asset.ssh_key_rotation.error_code && (
                            <small>
                              {t(`assets.keyErrors.${asset.ssh_key_rotation.error_code}`, {
                                defaultValue: t("assets.keyOperationFailed"),
                              })}
                            </small>
                          )}
                        </div>
                      )}
                      {asset.password_rotation && (
                        <div className={`rotation-status ${asset.password_rotation.state}`}>
                          {t(`assets.rotation.${asset.password_rotation.state}`)}
                          {asset.password_rotation.shared && <> · {t("assets.sharedPassword")}</>}
                          {asset.password_rotation.state === "scheduled" && (
                            <>
                              {" "}
                              ·{" "}
                              {t("assets.rotationNext", {
                                date: formatRotationDate(asset.password_rotation.next_rotation_at),
                              })}
                            </>
                          )}
                          {asset.password_rotation.state === "due" && (
                            <>
                              {" "}
                              ·{" "}
                              {t("assets.rotationDueAt", {
                                date: formatRotationDate(asset.password_rotation.next_rotation_at),
                              })}
                            </>
                          )}
                          {asset.password_rotation.state === "recovery_required" && (
                            <> · {t("assets.rotationRecoveryHint")}</>
                          )}
                        </div>
                      )}
                    </td>
                    <td className="asset-address">
                      {asset.host}:{asset.port}
                      {asset.gateway_id && (
                        <small>
                          {t("assets.gatewayVia", {
                            name:
                              assets.find((gateway) => gateway.id === asset.gateway_id)?.name ??
                              t("assets.gatewayManaged"),
                          })}
                        </small>
                      )}
                    </td>
                    <td>
                      {asset.protocol === "rdp" ? (
                        <span className="asset-monitor-status">
                          {t(asset.monitor.state === "online" ? "rdp.healthy" : "assets.unknown")}
                        </span>
                      ) : asset.protocol === "kubernetes" ? (
                        <span>
                          {t(
                            asset.monitor.state === "online"
                              ? "kubernetes.healthy"
                              : "assets.unknown",
                          )}
                        </span>
                      ) : asset.protocol === "telnet" ? (
                        <span>
                          {t(
                            asset.monitor.state === "online" ? "telnet.healthy" : "assets.unknown",
                          )}
                        </span>
                      ) : isDatabaseProtocol(asset.protocol) ? (
                        <span>
                          {t(
                            asset.monitor.state === "online"
                              ? "database.healthy"
                              : "assets.unknown",
                          )}
                        </span>
                      ) : metrics ? (
                        <div className="asset-metrics">
                          <div className="metric-column">
                            <MetricBar
                              label={`${t("assets.cpu")} (${metrics.cpu_cores} ${t("assets.cores")})`}
                              percent={metrics.cpu_percent}
                              detail={`${metrics.cpu_percent.toFixed(1)}%`}
                            />
                            <MetricBar
                              label={t("assets.memory")}
                              percent={metrics.memory_percent}
                              detail={`${formatBytes(metrics.memory_used_bytes)} / ${formatBytes(metrics.memory_total_bytes)}`}
                            />
                          </div>
                          <div className="metric-column">
                            <div className="network-metric">
                              <span>{t("assets.network")}</span>
                              <span>
                                ↑ {formatBytes(asset.monitor.network_sent_bytes_per_second, true)}
                              </span>
                              <span>
                                ↓{" "}
                                {formatBytes(asset.monitor.network_received_bytes_per_second, true)}
                              </span>
                            </div>
                            <MetricBar
                              label={t("assets.disk")}
                              percent={metrics.disk_percent}
                              detail={`${formatBytes(metrics.disk_used_bytes)} / ${formatBytes(metrics.disk_total_bytes)}`}
                            />
                          </div>
                        </div>
                      ) : (
                        <span className="metrics-empty">
                          {asset.monitor.error_code === "gateway_failed"
                            ? t("assets.gatewayFailed")
                            : asset.monitor.error_code
                              ? t("assets.probeFailed")
                              : t("assets.unknown")}
                        </span>
                      )}
                    </td>
                    <td className="asset-remark">{asset.remark || "—"}</td>
                    <td>
                      <div className="asset-actions">
                        <button
                          type="button"
                          className="button-primary button-small"
                          disabled={tokenRequired || !asset.permissions?.includes("connect")}
                          title={
                            !asset.permissions?.includes("connect")
                              ? t("assets.connectDenied")
                              : undefined
                          }
                          onClick={() =>
                            isDatabaseProtocol(asset.protocol)
                              ? setDatabaseAsset(asset)
                              : asset.protocol === "rdp"
                                ? setRDPAsset(asset)
                                : asset.protocol === "kubernetes"
                                  ? setKubernetesAsset(asset)
                                  : setTerminalAsset(asset)
                          }
                        >
                          {t("assets.connect")}
                        </button>
                        {isSSHProtocol(asset.protocol) && asset.permissions?.includes("sftp") && (
                          <button
                            type="button"
                            className="button-text"
                            disabled={tokenRequired}
                            onClick={() => setFileAsset(asset)}
                          >
                            {t("files.open")}
                          </button>
                        )}
                        {isSSHProtocol(asset.protocol) &&
                          asset.permissions?.includes("connect") &&
                          (allows("plugins.inspect") ||
                            allows("plugins.manage") ||
                            allows("plugins.protect")) && (
                            <button
                              type="button"
                              className="button-text"
                              disabled={tokenRequired}
                              onClick={() => setPluginAsset(asset)}
                            >
                              {t("hostPlugins.open")}
                            </button>
                          )}
                        {canManage && (
                          <button
                            type="button"
                            className="button-text"
                            disabled={
                              Boolean(asset.ssh_key_rotation?.pending) || keyBusyId === asset.id
                            }
                            onClick={() => openEdit(asset)}
                          >
                            {t("assets.edit")}
                          </button>
                        )}
                        {(canManage ||
                          allows("assets.probe") ||
                          allows("assets.rotate") ||
                          allows("assets.backups")) && (
                          <>
                            <details className="asset-more">
                              <summary className="button-text asset-more-trigger">
                                {t("assets.more")}
                              </summary>
                              <div className="asset-more-menu">
                                {allows("assets.probe") && (
                                  <button
                                    type="button"
                                    className="button-text"
                                    disabled={probingId === asset.id}
                                    onClick={(event) => {
                                      closeDetails(event.currentTarget);
                                      void probeAsset(asset);
                                    }}
                                  >
                                    {probingId === asset.id ? "…" : t("assets.probe")}
                                  </button>
                                )}
                                {allows("assets.rotate") && asset.password_rotation && (
                                  <button
                                    type="button"
                                    className="button-text"
                                    disabled={
                                      rotationBusyId === asset.id ||
                                      keyBusyId === asset.id ||
                                      Boolean(asset.ssh_key_rotation?.pending) ||
                                      asset.password_rotation?.state === "rotating" ||
                                      asset.password_rotation?.state === "recovery_required"
                                    }
                                    onClick={(event) => {
                                      closeDetails(event.currentTarget);
                                      void rotateAssetPassword(asset);
                                    }}
                                  >
                                    {rotationBusyId === asset.id
                                      ? t("assets.rotating")
                                      : t("assets.rotatePassword")}
                                  </button>
                                )}
                                {isSSHProtocol(asset.protocol) && allows("assets.rotate") && (
                                  <>
                                    <button
                                      type="button"
                                      className="button-text"
                                      disabled={
                                        keyBusyId === asset.id ||
                                        rotationBusyId === asset.id ||
                                        asset.password_rotation?.state === "rotating" ||
                                        asset.password_rotation?.state === "recovery_required"
                                      }
                                      onClick={(event) => {
                                        closeDetails(event.currentTarget);
                                        void changeSSHKey(asset);
                                      }}
                                    >
                                      {keyBusyId === asset.id
                                        ? t("assets.keyBusy")
                                        : t(
                                            asset.ssh_key_rotation?.pending
                                              ? "assets.keyResume"
                                              : asset.credential_type === "ssh_key"
                                                ? "assets.keyRotate"
                                                : "assets.keyInstall",
                                          )}
                                    </button>
                                    {asset.ssh_key_rotation?.pending &&
                                      asset.ssh_key_rotation.can_cancel && (
                                        <button
                                          type="button"
                                          className="button-text"
                                          disabled={keyBusyId === asset.id}
                                          onClick={(event) => {
                                            closeDetails(event.currentTarget);
                                            void changeSSHKey(asset, true);
                                          }}
                                        >
                                          {t("assets.keyCancel")}
                                        </button>
                                      )}
                                  </>
                                )}
                                {isSSHProtocol(asset.protocol) && allows("assets.backups") && (
                                  <button
                                    type="button"
                                    className="button-text"
                                    onClick={(event) => {
                                      closeDetails(event.currentTarget);
                                      setCredentialBackupsAsset(asset);
                                    }}
                                  >
                                    {t("assets.manageBackups")}
                                  </button>
                                )}
                                {canManage && (
                                  <button
                                    type="button"
                                    className="button-text danger"
                                    onClick={(event) => {
                                      closeDetails(event.currentTarget);
                                      void deleteAsset(asset);
                                    }}
                                  >
                                    {t("assets.delete")}
                                  </button>
                                )}
                              </div>
                            </details>
                          </>
                        )}
                      </div>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
          {!loading && !loadFailed && !tokenRequired && visibleAssets.length === 0 && (
            <div className="asset-empty">
              <h3>{t("assets.empty")}</h3>
              <p>{t("assets.emptyHint")}</p>
              {canManage && !tokenRequired && (
                <button type="button" className="button-primary" onClick={openCreate}>
                  + {t("assets.add")}
                </button>
              )}
            </div>
          )}
        </div>
      </div>

      {dialogOpen && (
        <div
          className="asset-modal-backdrop"
          role="presentation"
          onMouseDown={(event) => {
            if (event.target === event.currentTarget && !saving) closeAssetDialog();
          }}
        >
          <form
            className="asset-modal"
            role="dialog"
            aria-modal="true"
            aria-labelledby="asset-editor-title"
            onSubmit={(event) => void saveAsset(event)}
          >
            <h3 id="asset-editor-title">
              {editingAsset ? t("assets.dialogEdit") : t("assets.dialogCreate")}
            </h3>
            <div className="asset-form-grid">
              <label>
                <span>{t("database.protocol")}</span>
                <select
                  aria-label={t("database.protocol")}
                  value={form.protocol}
                  disabled={Boolean(editingAsset)}
                  onChange={(e) =>
                    setForm({
                      ...form,
                      protocol: e.target.value,
                      username:
                        e.target.value === "redis" && !form.username ? "default" : form.username,
                      port:
                        e.target.value === "rdp"
                          ? "3389"
                          : e.target.value === "kubernetes"
                            ? "6443"
                            : e.target.value === "postgresql"
                              ? "5432"
                              : e.target.value === "sqlserver"
                                ? "1433"
                                : e.target.value === "clickhouse"
                                  ? "8443"
                                  : e.target.value === "redis"
                                    ? "6379"
                                    : e.target.value === "mongodb"
                                      ? "27017"
                                      : isDatabaseProtocol(e.target.value)
                                        ? "3306"
                                        : e.target.value === "telnet"
                                          ? "992"
                                          : "22",
                      database_settings: {
                        ...defaultPostgreSQL,
                        database:
                          e.target.value === "postgresql"
                            ? "postgres"
                            : e.target.value === "redis"
                              ? "0"
                              : e.target.value === "mongodb"
                                ? "test"
                                : "",
                      },
                      credential_type: "password",
                      private_key: "",
                      private_key_passphrase: "",
                      key_rotation_enabled: false,
                      host_key_fingerprint: "",
                    })
                  }
                >
                  <option value="ssh">SSH</option>
                  <option value="rdp">{t("rdp.name")}</option>
                  <option value="telnet">{t("telnet.name")}</option>
                  <option value="kubernetes">Kubernetes</option>
                  <option value="postgresql">PostgreSQL</option>
                  <option value="mysql">MySQL</option>
                  <option value="mariadb">MariaDB</option>
                  <option value="sqlserver">SQL Server</option>
                  <option value="clickhouse">ClickHouse</option>
                  <option value="redis">Redis</option>
                  <option value="mongodb">MongoDB</option>
                </select>
              </label>
              {form.protocol === "rdp" && (
                <RDPSettingsFields
                  value={form.rdp_settings}
                  onChange={(rdp_settings) => setForm({ ...form, rdp_settings })}
                />
              )}
              {form.protocol === "telnet" && (
                <>
                  <label>
                    <span>{t("telnet.transport")}</span>
                    <select
                      value={form.telnet_settings.tls_mode}
                      aria-label={t("telnet.transport")}
                      aria-describedby="telnet-transport-hint"
                      onChange={(e) =>
                        setForm({
                          ...form,
                          port:
                            form.port === "23" || form.port === "992"
                              ? e.target.value === "disable"
                                ? "23"
                                : "992"
                              : form.port,
                          telnet_settings: {
                            ...form.telnet_settings,
                            tls_mode: e.target.value,
                            server_name:
                              e.target.value === "disable" ? "" : form.telnet_settings.server_name,
                            root_ca_pem:
                              e.target.value === "disable" ? "" : form.telnet_settings.root_ca_pem,
                          },
                        })
                      }
                    >
                      <option value="verify-full">{t("telnet.verifiedTLS")}</option>
                      <option value="disable">{t("telnet.plaintext")}</option>
                    </select>
                    <small id="telnet-transport-hint">
                      {t(
                        form.telnet_settings.tls_mode === "disable"
                          ? "telnet.plaintextHint"
                          : "telnet.tlsHint",
                      )}
                    </small>
                  </label>
                  {form.telnet_settings.tls_mode !== "disable" && (
                    <>
                      <label>
                        <span>{t("database.serverName")}</span>
                        <input
                          maxLength={253}
                          value={form.telnet_settings.server_name}
                          onChange={(e) =>
                            setForm({
                              ...form,
                              telnet_settings: {
                                ...form.telnet_settings,
                                server_name: e.target.value,
                              },
                            })
                          }
                        />
                      </label>
                      <label className="asset-form-wide">
                        <span>{t("database.ca")}</span>
                        <textarea
                          rows={3}
                          maxLength={65536}
                          value={form.telnet_settings.root_ca_pem}
                          onChange={(e) =>
                            setForm({
                              ...form,
                              telnet_settings: {
                                ...form.telnet_settings,
                                root_ca_pem: e.target.value,
                              },
                            })
                          }
                        />
                      </label>
                    </>
                  )}
                  <details className="asset-form-wide">
                    <summary>{t("telnet.prompts")}</summary>
                    <p>{t("telnet.promptHint")}</p>
                    {(["login_prompt", "password_prompt", "success_prompt"] as const).map((key) => (
                      <label key={key}>
                        <span>{t(`telnet.${key}`)}</span>
                        <input
                          required
                          maxLength={512}
                          value={form.telnet_settings[key]}
                          onChange={(e) =>
                            setForm({
                              ...form,
                              telnet_settings: { ...form.telnet_settings, [key]: e.target.value },
                            })
                          }
                        />
                      </label>
                    ))}
                  </details>
                </>
              )}
              {form.protocol === "kubernetes" && (
                <>
                  <label className="asset-form-wide">
                    <span>{t("kubernetes.namespaces")}</span>
                    <input
                      required
                      value={form.kubernetes_settings.namespaces.join(",")}
                      aria-label={t("kubernetes.namespaces")}
                      onChange={(e) =>
                        setForm({
                          ...form,
                          kubernetes_settings: {
                            ...form.kubernetes_settings,
                            namespaces: e.target.value.split(","),
                          },
                        })
                      }
                    />
                    <small>{t("kubernetes.scopeHint")}</small>
                  </label>
                  <label>
                    <span>{t("kubernetes.shell")}</span>
                    <input
                      required
                      value={form.kubernetes_settings.shell[0] ?? "/bin/sh"}
                      onChange={(e) =>
                        setForm({
                          ...form,
                          kubernetes_settings: {
                            ...form.kubernetes_settings,
                            shell: [e.target.value, ...form.kubernetes_settings.shell.slice(1)],
                          },
                        })
                      }
                    />
                  </label>
                  <label>
                    <span>{t("database.serverName")}</span>
                    <input
                      maxLength={253}
                      value={form.kubernetes_settings.server_name}
                      onChange={(e) =>
                        setForm({
                          ...form,
                          kubernetes_settings: {
                            ...form.kubernetes_settings,
                            server_name: e.target.value,
                          },
                        })
                      }
                    />
                  </label>
                  <label className="asset-form-wide">
                    <span>{t("database.ca")}</span>
                    <textarea
                      rows={3}
                      maxLength={65536}
                      value={form.kubernetes_settings.root_ca_pem}
                      aria-label={t("database.ca")}
                      onChange={(e) =>
                        setForm({
                          ...form,
                          kubernetes_settings: {
                            ...form.kubernetes_settings,
                            root_ca_pem: e.target.value,
                          },
                        })
                      }
                    />
                    <small>{t("kubernetes.tlsHint")}</small>
                  </label>
                </>
              )}
              {isDatabaseProtocol(form.protocol) && (
                <>
                  <label>
                    <span>
                      {t(form.protocol === "redis" ? "database.redisIndex" : "database.name")}
                    </span>
                    <input
                      required
                      maxLength={128}
                      value={form.database_settings.database}
                      onChange={(e) =>
                        setForm({
                          ...form,
                          database_settings: {
                            ...form.database_settings,
                            database: e.target.value,
                          },
                        })
                      }
                    />
                  </label>
                  {form.protocol === "mongodb" && (
                    <label>
                      <span>{t("database.authDatabase")}</span>
                      <input
                        maxLength={63}
                        value={form.database_settings.auth_database ?? ""}
                        onChange={(e) =>
                          setForm({
                            ...form,
                            database_settings: {
                              ...form.database_settings,
                              auth_database: e.target.value,
                            },
                          })
                        }
                      />
                    </label>
                  )}
                  <label>
                    <span>{t("database.tls")}</span>
                    <select
                      value={form.database_settings.tls_mode}
                      onChange={(e) =>
                        setForm({
                          ...form,
                          database_settings: {
                            ...form.database_settings,
                            tls_mode: e.target.value,
                          },
                        })
                      }
                    >
                      <option value="verify-full">{t("database.verifyTLS")}</option>
                      <option value="disable">{t("database.noTLS")}</option>
                    </select>
                  </label>
                  <label>
                    <span>{t("database.serverName")}</span>
                    <input
                      maxLength={253}
                      value={form.database_settings.server_name}
                      onChange={(e) =>
                        setForm({
                          ...form,
                          database_settings: {
                            ...form.database_settings,
                            server_name: e.target.value,
                          },
                        })
                      }
                    />
                  </label>
                  <label className="asset-form-wide">
                    <span>{t("database.ca")}</span>
                    <textarea
                      rows={3}
                      maxLength={65536}
                      value={form.database_settings.root_ca_pem}
                      onChange={(e) =>
                        setForm({
                          ...form,
                          database_settings: {
                            ...form.database_settings,
                            root_ca_pem: e.target.value,
                          },
                        })
                      }
                    />
                  </label>
                  <label className="asset-review-toggle asset-form-wide">
                    <input
                      type="checkbox"
                      checked={form.database_settings.read_only}
                      onChange={(e) =>
                        setForm({
                          ...form,
                          database_settings: {
                            ...form.database_settings,
                            read_only: e.target.checked,
                          },
                        })
                      }
                    />
                    <span>{t("database.readOnlyPolicy")}</span>
                  </label>
                </>
              )}
              <label>
                <span>{t("assets.name")}</span>
                <input
                  required
                  maxLength={120}
                  value={form.name}
                  onChange={(event) => setForm({ ...form, name: event.target.value })}
                />
              </label>
              <label>
                <span>{t("assets.group")}</span>
                <input
                  maxLength={120}
                  value={form.group}
                  onChange={(event) => setForm({ ...form, group: event.target.value })}
                />
              </label>
              <label>
                <span>{t("assets.nodes")}</span>
                <select
                  value={form.node_id}
                  onChange={(event) => setForm({ ...form, node_id: event.target.value })}
                >
                  <option value="">{t("assets.unassignedNode")}</option>
                  {treeNodes.map(({ node }) => (
                    <option key={node.id} value={node.id}>
                      {nodeAncestors(nodes, node.id)
                        .map((ancestor) => ancestor.name)
                        .join(" / ")}
                    </option>
                  ))}
                </select>
              </label>
              <label>
                <span>{t("assets.host")}</span>
                <input
                  required
                  maxLength={253}
                  value={form.host}
                  onChange={(event) => setForm({ ...form, host: event.target.value })}
                />
              </label>
              <label>
                <span>
                  {t(
                    form.protocol === "rdp"
                      ? "rdp.port"
                      : form.protocol === "kubernetes"
                        ? "kubernetes.port"
                        : form.protocol === "telnet"
                          ? "telnet.port"
                          : isDatabaseProtocol(form.protocol)
                            ? "database.port"
                            : "assets.port",
                  )}
                </span>
                <input
                  required
                  type="number"
                  min={1}
                  max={65535}
                  value={form.port}
                  onChange={(event) => setForm({ ...form, port: event.target.value })}
                />
              </label>
              <label>
                <span>
                  {t(
                    form.protocol === "rdp"
                      ? "rdp.account"
                      : form.protocol === "kubernetes"
                        ? "kubernetes.account"
                        : isDatabaseProtocol(form.protocol)
                          ? "database.account"
                          : form.protocol === "telnet"
                            ? "telnet.account"
                            : "assets.username",
                  )}
                </span>
                <input
                  required
                  maxLength={128}
                  autoComplete="off"
                  value={form.username}
                  onChange={(event) => setForm({ ...form, username: event.target.value })}
                />
              </label>
              {isSSHProtocol(form.protocol) && (
                <label className="asset-form-wide">
                  <span>{t("assets.credentialType")}</span>
                  <select
                    aria-label={t("assets.credentialType")}
                    value={form.credential_type}
                    onChange={(event) =>
                      setForm({
                        ...form,
                        credential_type: event.target.value as "password" | "ssh_key",
                        password: "",
                        private_key: "",
                        private_key_passphrase: "",
                        key_rotation_enabled:
                          event.target.value === "ssh_key" ? form.key_rotation_enabled : false,
                      })
                    }
                  >
                    <option value="password">{t("assets.credentialPassword")}</option>
                    <option value="ssh_key">{t("assets.credentialKey")}</option>
                  </select>
                </label>
              )}
              {form.credential_type === "ssh_key" ? (
                <>
                  <label className="asset-form-wide">
                    <span>{t("assets.privateKey")}</span>
                    <textarea
                      aria-label={t("assets.privateKey")}
                      required={!editingAsset || editingAsset.credential_type !== "ssh_key"}
                      rows={6}
                      maxLength={65536}
                      autoComplete="off"
                      spellCheck={false}
                      value={form.private_key}
                      onChange={(event) => setForm({ ...form, private_key: event.target.value })}
                    />
                    <small>{t("assets.privateKeyHint")}</small>

                    {editingAsset?.key_fingerprint && (
                      <small>
                        {t("assets.currentKeyFingerprint", {
                          fingerprint: editingAsset.key_fingerprint,
                        })}
                      </small>
                    )}
                  </label>
                  <label className="asset-form-wide">
                    <span>{t("assets.privateKeyPassphrase")}</span>
                    <input
                      type="password"
                      maxLength={1024}
                      autoComplete="new-password"
                      value={form.private_key_passphrase}
                      onChange={(event) =>
                        setForm({ ...form, private_key_passphrase: event.target.value })
                      }
                    />
                  </label>
                  <label className="asset-review-toggle asset-form-wide">
                    <input
                      type="checkbox"
                      checked={form.key_rotation_enabled}
                      disabled={!allows("assets.rotate")}
                      onChange={(event) =>
                        setForm({ ...form, key_rotation_enabled: event.target.checked })
                      }
                    />
                    <span>
                      <strong>{t("assets.keyAutoRotate")}</strong>
                      <small>{t("assets.keyAutoHint")}</small>
                    </span>
                  </label>
                </>
              ) : (
                <label>
                  <span>
                    {t(
                      form.protocol === "rdp"
                        ? "rdp.password"
                        : form.protocol === "kubernetes"
                          ? "kubernetes.token"
                          : isDatabaseProtocol(form.protocol)
                            ? "database.password"
                            : form.protocol === "telnet"
                              ? "telnet.password"
                              : "assets.password",
                    )}
                  </span>
                  <input
                    required={!editingAsset || editingAsset.credential_type === "ssh_key"}
                    type="password"
                    maxLength={4096}
                    autoComplete="new-password"
                    value={form.password}
                    onChange={(event) => setForm({ ...form, password: event.target.value })}
                  />
                  {editingAsset && <small>{t("assets.passwordOptional")}</small>}
                </label>
              )}
              <label className="asset-form-wide">
                <span>{t("assets.gateway")}</span>
                <select
                  value={form.gateway_id}
                  onChange={(event) => setForm({ ...form, gateway_id: event.target.value })}
                >
                  <option value="">{t("assets.gatewayDirect")}</option>
                  {assets
                    .filter(
                      (asset) => isSSHProtocol(asset.protocol) && asset.id !== editingAsset?.id,
                    )
                    .map((asset) => (
                      <option key={asset.id} value={asset.id}>
                        {asset.name} ({asset.username}@{asset.host})
                      </option>
                    ))}
                </select>
                <small>{t("assets.gatewayHint")}</small>
              </label>
              {isSSHProtocol(form.protocol) && (
                <label className="asset-form-wide">
                  <span>{t("assets.hostKey")}</span>
                  <input
                    required
                    maxLength={64}
                    autoComplete="off"
                    value={form.host_key_fingerprint}
                    onChange={(event) =>
                      setForm({ ...form, host_key_fingerprint: event.target.value })
                    }
                  />
                  <small>{t("assets.hostKeyHint")}</small>
                </label>
              )}
              <label className="asset-form-wide">
                <span>{t("assets.remark")}</span>
                <input
                  maxLength={500}
                  value={form.remark}
                  placeholder={t("assets.remarkPlaceholder")}
                  onChange={(event) => setForm({ ...form, remark: event.target.value })}
                />
              </label>
              <label className="asset-review-toggle asset-form-wide">
                <input
                  type="checkbox"
                  checked={form.login_review_required}
                  onChange={(event) =>
                    setForm({ ...form, login_review_required: event.target.checked })
                  }
                />
                <span>
                  <strong>
                    {t(
                      form.protocol === "rdp"
                        ? "rdp.loginReviewRequired"
                        : isDatabaseProtocol(form.protocol)
                          ? "database.loginReviewRequired"
                          : form.protocol === "telnet"
                            ? "telnet.loginReviewRequired"
                            : "assets.loginReviewRequired",
                    )}
                  </strong>
                  <small>
                    {t(
                      form.protocol === "rdp"
                        ? "rdp.loginReviewHint"
                        : isDatabaseProtocol(form.protocol)
                          ? "database.loginReviewHint"
                          : form.protocol === "telnet"
                            ? "telnet.loginReviewHint"
                            : "assets.loginReviewHint",
                    )}
                  </small>
                </span>
              </label>
            </div>
            {saveFailed && (
              <p className="asset-error" role="alert">
                {t(saveConflict ? "assets.sharedCredentialConflict" : "assets.saveFailed")}
              </p>
            )}
            <div className="asset-modal-actions">
              <button
                type="button"
                className="button-secondary"
                disabled={saving}
                onClick={closeAssetDialog}
              >
                {t("assets.cancel")}
              </button>
              <button type="submit" className="button-primary" disabled={saving}>
                {saving ? "…" : t("assets.save")}
              </button>
            </div>
          </form>
        </div>
      )}
      {pluginAsset && (
        <Suspense fallback={null}>
          <HostPluginsDialog
            assetId={pluginAsset.id}
            assetName={pluginAsset.name}
            accessToken={accessToken}
            onClose={() => setPluginAsset(null)}
          />
        </Suspense>
      )}
      {rdpAsset && (
        <Suspense fallback={null}>
          <RDPDesktopDialog
            assetId={rdpAsset.id}
            assetName={rdpAsset.name}
            accessToken={accessToken}
            onClose={() => setRDPAsset(null)}
          />
        </Suspense>
      )}
      {databaseAsset && (
        <Suspense fallback={null}>
          <DatabaseConsoleDialog
            protocol={databaseAsset.protocol}
            assetId={databaseAsset.id}
            assetName={databaseAsset.name}
            accessToken={accessToken}
            onClose={() => setDatabaseAsset(null)}
          />
        </Suspense>
      )}
      {kubernetesAsset && (
        <Suspense fallback={null}>
          <KubernetesTerminalDialog
            assetId={kubernetesAsset.id}
            assetName={kubernetesAsset.name}
            accessToken={accessToken}
            onClose={() => setKubernetesAsset(null)}
          />
        </Suspense>
      )}
      {terminalAsset && (
        <Suspense fallback={null}>
          <SSHTerminalDialog
            protocol={terminalAsset.protocol === "telnet" ? "telnet" : undefined}
            assetId={terminalAsset.id}
            assetName={terminalAsset.name}
            accessToken={accessToken}
            onClose={closeTerminal}
          />
        </Suspense>
      )}
      {fileAsset && (
        <Suspense fallback={null}>
          <SFTPFileManagerDialog
            assetId={fileAsset.id}
            assetName={fileAsset.name}
            accessToken={accessToken}
            onClose={closeFileManager}
          />
        </Suspense>
      )}
      {credentialBackupsAsset && (
        <Suspense fallback={null}>
          <CredentialBackupsDialog
            asset={credentialBackupsAsset}
            request={request}
            onClose={() => setCredentialBackupsAsset(null)}
            onChanged={loadAssets}
          />
        </Suspense>
      )}
    </section>
  );
}
