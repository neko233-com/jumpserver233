import { requestID as newRequestID } from "../utils/requestID";
import {
  lazy,
  Suspense,
  useCallback,
  useEffect,
  useMemo,
  useRef,
  useState,
  type FormEvent,
} from "react";
import { useTranslation } from "react-i18next";
import "../i18n/locales/features/workspaces/register";
import { Link, useSearchParams } from "react-router-dom";
import { usePermissions } from "../auth/usePermissions";
import { useAuth } from "../auth/AuthContext";
import Icon from "../components/ui/Icon";
import ActionMenu from "../components/ui/ActionMenu";
import type {
  AccountChoice,
  PasswordRotation,
  SSHKeyRotation,
} from "../components/managedAccounts";

import RDPSettingsFields, { defaultRDP, type RDPSettings } from "../components/RDPSettingsFields";
const HostPluginsDialog = lazy(() => import("../components/HostPluginsDialog"));
const AccountDiscoveryDialog = lazy(() => import("../components/AccountDiscoveryDialog"));
const ManagedAccountsDialog = lazy(() => import("../components/ManagedAccountsDialog"));
const AccountImportDialog = lazy(() => import("../components/AccountImportDialog"));
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
const MonitorHistoryDialog = lazy(() => import("../components/MonitorHistoryDialog"));

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

type AssetNode = { id: string; name: string; parent_id?: string };
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
  labels?: { id: string; name: string; value: string; color: string; inherited: boolean }[];
  parent_asset_id?: string;
  account_disabled?: boolean;
  accounts?: AccountChoice[];
  selected_account_id?: string;
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
  ssh_workspace?: string;
  monitor: Monitor;
  permissions: string[];
  password_rotation?: PasswordRotation;
};

function operationalAsset(asset: Asset, chosen?: string): Asset {
  if (!isSSHProtocol(asset.protocol) || !asset.accounts?.length) return asset;
  const selected =
    asset.accounts.find((a) => a.id === chosen) ||
    asset.accounts.find((a) => a.id === asset.selected_account_id) ||
    asset.accounts[0];
  return {
    ...asset,
    id: selected.id,
    parent_asset_id: selected.default ? undefined : asset.id,
    username: selected.username,
    credential_type: selected.credential_type,
    key_fingerprint: selected.key_fingerprint,
    credential_revision: selected.credential_revision,
    account_disabled: !selected.active,
    permissions: selected.permissions,
    password_rotation: selected.password_rotation,
    ssh_key_rotation: selected.ssh_key_rotation,
  };
}

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
  ssh_workspace: string;
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
  ssh_workspace: "",
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
  const [params] = useSearchParams();
  const { t, i18n } = useTranslation();
  const { accessToken, setAccessToken } = useAuth();
  const [assets, setAssets] = useState<Asset[]>([]);
  const [nodes, setNodes] = useState<AssetNode[]>([]);
  const [selectedGroup, setSelectedGroup] = useState("");
  const [selectedNode, setSelectedNode] = useState("");
  const [search, setSearch] = useState(() => params.get("asset_id") || "");
  const [selectedLabel, setSelectedLabel] = useState(() => params.get("label") || "");
  const [loading, setLoading] = useState(true);
  const [statusFilter, setStatusFilter] = useState("");
  const [sortBy, setSortBy] = useState("name");
  const [groupsOpen, setGroupsOpen] = useState(
    () => window.matchMedia("(min-width: 1500px)").matches,
  );
  const [updatedAt, setUpdatedAt] = useState<Date | null>(null);
  const [filtersOpen, setFiltersOpen] = useState(false);
  const [loadFailed, setLoadFailed] = useState(false);
  const [tokenRequired, setTokenRequired] = useState(false);
  const [tokenRejected, setTokenRejected] = useState(false);
  const [tokenDraft, setTokenDraft] = useState("");
  const [dialogOpen, setDialogOpen] = useState(false);
  const [editingAsset, setEditingAsset] = useState<Asset | null>(null);
  const [form, setForm] = useState<AssetForm>(emptyForm);
  const initialForm = useRef("");
  const inventoryRequest = useRef<AbortController | null>(null);
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
  const [historyAsset, setHistoryAsset] = useState<Asset | null>(null);
  const [pluginAsset, setPluginAsset] = useState<Asset | null>(null);
  const [discoveryAsset, setDiscoveryAsset] = useState<Asset | null>(null);
  const [managedAccountsAsset, setManagedAccountsAsset] = useState<Asset | null>(null);
  const [importOpen, setImportOpen] = useState(false);
  const [managedFinding, setManagedFinding] = useState<
    { id: string; username: string } | undefined
  >();
  const [selectedAccounts, setSelectedAccounts] = useState<Record<string, string>>(() => {
    const asset = params.get("asset_id"),
      account = params.get("account_id");
    return asset && account ? { [asset]: account } : {};
  });
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
    inventoryRequest.current?.abort();
    const controller = new AbortController();
    inventoryRequest.current = controller;
    try {
      const [response, nodeResponse] = await Promise.all([
        request("/api/v1/assets", { signal: controller.signal }),
        request("/api/v1/assets/nodes", { signal: controller.signal }),
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
      if (controller.signal.aborted) return;
      setAssets(result);
      setNodes(nextNodes);
      setUpdatedAt(new Date());
      setTokenRequired(false);
      setTokenRejected(false);
      setLoadFailed(false);
    } catch {
      if (!controller.signal.aborted) setLoadFailed(true);
    } finally {
      if (!controller.signal.aborted) setLoading(false);
    }
  }, [accessToken, request]);

  useEffect(() => {
    // The initial fetch synchronizes the page with server-owned inventory state.
    // eslint-disable-next-line react/set-state-in-effect
    void loadAssets();
    const timer = window.setInterval(() => {
      if (document.visibilityState !== "hidden") void loadAssets();
    }, 15_000);
    return () => {
      window.clearInterval(timer);
      inventoryRequest.current?.abort();
    };
  }, [loadAssets]);

  const linkedAsset = params.get("asset_id") || "";
  useEffect(() => {
    // Synchronize a new command-search destination without reloading the page.
    // eslint-disable-next-line react/set-state-in-effect
    setSearch(linkedAsset);
  }, [linkedAsset]);

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

  const labelChoices = useMemo(
    () =>
      Array.from(
        new Map(assets.flatMap((a) => a.labels || []).map((l) => [l.id, l])).values(),
      ).sort((a, b) => `${a.name}:${a.value}`.localeCompare(`${b.name}:${b.value}`)),
    [assets],
  );
  const visibleAssets = useMemo(() => {
    const query = search.trim().toLocaleLowerCase();
    return assets
      .filter((asset) => {
        if (statusFilter && asset.monitor.state !== statusFilter) return false;
        if (selectedGroup && asset.group !== selectedGroup) return false;
        if (selectedLabel && !asset.labels?.some((l) => l.id === selectedLabel)) return false;
        if (selectedNode === unassignedNode && asset.node_id) return false;
        if (
          selectedNode &&
          selectedNode !== unassignedNode &&
          (!asset.node_id || !descendantIDs(nodes, selectedNode).has(asset.node_id))
        )
          return false;
        if (!query) return true;
        return `${asset.id} ${asset.name} ${asset.host} ${asset.remark} ${(asset.labels || []).map((l) => `${l.name}:${l.value}`).join(" ")}`
          .toLocaleLowerCase()
          .includes(query);
      })
      .sort((a, b) =>
        sortBy === "latency"
          ? (a.monitor.metrics?.latency_ms ?? a.monitor.latency_ms ?? Infinity) -
            (b.monitor.metrics?.latency_ms ?? b.monitor.latency_ms ?? Infinity)
          : sortBy === "cpu"
            ? (b.monitor.metrics?.cpu_percent ?? -1) - (a.monitor.metrics?.cpu_percent ?? -1)
            : a.name.localeCompare(b.name, i18n.language, { numeric: true }),
      );
  }, [
    assets,
    nodes,
    search,
    selectedGroup,
    selectedNode,
    selectedLabel,
    statusFilter,
    sortBy,
    i18n.language,
  ]);

  const resetFilters = () => {
    setSearch("");
    setSelectedGroup("");
    setSelectedNode("");
    setSelectedLabel("");
    setStatusFilter("");
  };
  const hasFilters = !!(search || selectedGroup || selectedNode || selectedLabel || statusFilter);

  function openCreate() {
    setEditingAsset(null);
    setForm(emptyForm);
    initialForm.current = JSON.stringify(emptyForm);
    setSaveFailed(false);
    setDialogOpen(true);
  }

  function openEdit(asset: Asset) {
    setEditingAsset(asset);
    const nextForm: AssetForm = {
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
      ssh_workspace: asset.ssh_workspace ?? "",
    };
    setForm(nextForm);
    initialForm.current = JSON.stringify(nextForm);
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
      ssh_workspace: isSSHProtocol(form.protocol) ? identity.ssh_workspace : undefined,
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
  function requestCloseAssetDialog() {
    if (saving) return;
    if (initialForm.current !== JSON.stringify(form) && !window.confirm(t("ui.unsaved"))) return;
    closeAssetDialog();
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
                  request_id: pending?.pending ? pending.request_id : newRequestID(),
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
    <section className="asset-inventory" data-groups-open={groupsOpen} aria-busy={loading}>
      <aside className="asset-groups" hidden={!groupsOpen} id="asset-collections">
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
          <div className="asset-toolbar" data-filters-open={filtersOpen}>
            <button
              type="button"
              className="asset-filter-toggle icon-button"
              aria-label={t("ui.assets.filters")}
              title={t("ui.assets.filters")}
              aria-expanded={filtersOpen}
              onClick={() => setFiltersOpen((value) => !value)}
            >
              <Icon name="filter" />
            </button>
            <button
              type="button"
              className="button-secondary"
              aria-controls="asset-collections"
              aria-expanded={groupsOpen}
              onClick={() => setGroupsOpen((value) => !value)}
            >
              <Icon name="folder" size={16} />
              {t("ui.assets.collections")}
            </button>
            <select
              aria-label={t("assets.labels")}
              value={selectedLabel}
              onChange={(e) => setSelectedLabel(e.target.value)}
            >
              <option value="">{t("assets.allLabels")}</option>
              {selectedLabel && !labelChoices.some((l) => l.id === selectedLabel) && (
                <option value={selectedLabel}>{selectedLabel}</option>
              )}
              {labelChoices.map((l) => (
                <option value={l.id} key={l.id}>
                  {l.name}
                  {l.value ? `: ${l.value}` : ""}
                </option>
              ))}
            </select>
            <label className="asset-search">
              <Icon name="search" size={17} />
              <input
                type="search"
                aria-label={t("assets.search")}
                value={search}
                onChange={(event) => setSearch(event.target.value)}
                placeholder={t("assets.search")}
              />
            </label>
            <select
              aria-label={t("ui.assets.sort")}
              value={sortBy}
              onChange={(event) => setSortBy(event.target.value)}
            >
              <option value="name">{t("ui.assets.sortName")}</option>
              <option value="latency">{t("ui.assets.sortLatency")}</option>
              <option value="cpu">{t("ui.assets.sortCPU")}</option>
            </select>
            <button
              type="button"
              className="button-secondary"
              onClick={() => {
                setLoading(true);
                void loadAssets();
              }}
              disabled={loading}
            >
              <Icon name="refresh" size={16} className={loading ? "ui-spinning" : undefined} />
              {t("assets.refresh")}
            </button>
            {canManage && (
              <button
                type="button"
                className="button-primary"
                onClick={openCreate}
                disabled={tokenRequired}
              >
                <Icon name="plus" size={16} />
                {t("assets.add")}
              </button>
            )}
            {allows("accounts.manage") && allows("accounts.import") && (
              <button
                type="button"
                className="button-secondary"
                disabled={tokenRequired}
                onClick={() => setImportOpen(true)}
              >
                {t("accountImport.title")}
              </button>
            )}
          </div>
        </div>

        <div className="asset-status-strip" aria-label={t("ui.assets.statusFilters")}>
          {["", "online", "offline", "unknown"].map((status) => (
            <button
              type="button"
              key={status}
              aria-pressed={statusFilter === status}
              className={statusFilter === status ? "active" : ""}
              onClick={() => setStatusFilter(status)}
            >
              <span className={`status-dot ${status || "all"}`} />
              <span>{status ? t(`assets.${status}`) : t("ui.assets.total")}</span>
              <strong>
                {status
                  ? assets.filter((asset) => asset.monitor.state === status).length
                  : assets.length}
              </strong>
            </button>
          ))}
          {hasFilters && (
            <button type="button" className="clear-filters" onClick={resetFilters}>
              <Icon name="close" size={14} />
              {t("ui.clearFilters")}
            </button>
          )}
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
              {visibleAssets.map((physicalAsset) => {
                const asset = operationalAsset(physicalAsset, selectedAccounts[physicalAsset.id]);
                const metrics = asset.monitor.metrics;
                const stateLabel = t(`assets.${asset.monitor.state}`);
                const nodePath = asset.node_id
                  ? nodeAncestors(nodes, asset.node_id)
                      .map((node) => node.name)
                      .join(" / ")
                  : "";
                return (
                  <tr key={physicalAsset.id}>
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
                      {asset.remark && (
                        <div className="asset-description" title={asset.remark}>
                          {asset.remark}
                        </div>
                      )}
                      <div className="asset-labels">
                        {(physicalAsset.labels || []).map((l) => (
                          <Link
                            className="asset-label-badge"
                            style={{ borderColor: l.color }}
                            to={`/console?label=${encodeURIComponent(l.id)}`}
                            onClick={() => setSelectedLabel(l.id)}
                            key={l.id}
                          >
                            {l.name}
                            {l.value ? `: ${l.value}` : ""}
                          </Link>
                        ))}
                        <Link
                          to={`/console/labels?type=asset&id=${encodeURIComponent(physicalAsset.id)}`}
                        >
                          {t("assets.labels")}
                        </Link>
                      </div>
                      <div className="asset-subline">
                        {asset.username} · {stateLabel}
                        {(physicalAsset.accounts?.length || 0) > 1 && (
                          <>
                            {" "}
                            ·{" "}
                            {t("managedAccounts.count", { count: physicalAsset.accounts!.length })}
                          </>
                        )}
                        {asset.account_disabled && <> · {t("managedAccounts.disabled")}</>}
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
                        {isSSHProtocol(asset.protocol) && asset.permissions?.includes("view") && (
                          <button
                            type="button"
                            className="button-text button-small"
                            onClick={() => setHistoryAsset(asset)}
                          >
                            {t("assets.monitorHistory")}
                          </button>
                        )}
                        <button
                          type="button"
                          className="button-primary button-small asset-connect-action"
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
                            data-file-action="true"
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
                            onClick={() => openEdit(physicalAsset)}
                          >
                            {t("assets.edit")}
                          </button>
                        )}
                        {(canManage ||
                          asset.permissions?.includes("view") ||
                          allows("assets.probe") ||
                          allows("assets.rotate") ||
                          allows("assets.backups") ||
                          (isSSHProtocol(asset.protocol) &&
                            (allows("accounts.view") ||
                              Boolean(physicalAsset.accounts?.length)))) && (
                          <>
                            <ActionMenu label={t("assets.more")}>
                              {isSSHProtocol(asset.protocol) &&
                                asset.permissions?.includes("view") && (
                                  <button
                                    type="button"
                                    className="button-text mobile-only-action"
                                    onClick={(event) => {
                                      closeDetails(event.currentTarget);
                                      setHistoryAsset(asset);
                                    }}
                                  >
                                    {t("assets.monitorHistory")}
                                  </button>
                                )}
                              {isSSHProtocol(asset.protocol) &&
                                asset.permissions?.includes("connect") &&
                                (allows("plugins.inspect") ||
                                  allows("plugins.manage") ||
                                  allows("plugins.protect")) && (
                                  <button
                                    type="button"
                                    className="button-text mobile-only-action"
                                    onClick={(event) => {
                                      closeDetails(event.currentTarget);
                                      setPluginAsset(asset);
                                    }}
                                  >
                                    {t("hostPlugins.open")}
                                  </button>
                                )}
                              {canManage && (
                                <button
                                  type="button"
                                  className="button-text mobile-only-action"
                                  disabled={
                                    Boolean(asset.ssh_key_rotation?.pending) ||
                                    keyBusyId === asset.id
                                  }
                                  onClick={(event) => {
                                    closeDetails(event.currentTarget);
                                    openEdit(physicalAsset);
                                  }}
                                >
                                  {t("assets.edit")}
                                </button>
                              )}
                              {isSSHProtocol(asset.protocol) &&
                                Boolean(physicalAsset.accounts?.length) && (
                                  <button
                                    type="button"
                                    className="button-text"
                                    onClick={(event) => {
                                      closeDetails(event.currentTarget);
                                      setManagedAccountsAsset(physicalAsset);
                                    }}
                                  >
                                    {t("managedAccounts.open")}
                                  </button>
                                )}
                              {isSSHProtocol(asset.protocol) && allows("accounts.view") && (
                                <button
                                  type="button"
                                  className="button-text"
                                  onClick={(event) => {
                                    closeDetails(event.currentTarget);
                                    setDiscoveryAsset(asset);
                                  }}
                                >
                                  {t("accountDiscovery.open")}
                                </button>
                              )}
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
                                    void deleteAsset(physicalAsset);
                                  }}
                                >
                                  {t("assets.delete")}
                                </button>
                              )}
                            </ActionMenu>
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
              <Icon name={hasFilters ? "search" : "server"} size={32} />
              <h3>{t(hasFilters ? "ui.assets.noMatches" : "assets.empty")}</h3>
              <p>{t(hasFilters ? "ui.assets.noMatchesHint" : "assets.emptyHint")}</p>
              {hasFilters && (
                <button type="button" className="button-secondary" onClick={resetFilters}>
                  {t("ui.clearFilters")}
                </button>
              )}
              {canManage && !tokenRequired && !hasFilters && (
                <button type="button" className="button-primary" onClick={openCreate}>
                  + {t("assets.add")}
                </button>
              )}
            </div>
          )}
        </div>
        <footer className="asset-list-footer">
          <span role="status">
            {t("ui.assets.showing", { count: visibleAssets.length, total: assets.length })}
          </span>
          <span>
            {updatedAt &&
              t("ui.assets.updated", {
                time: updatedAt.toLocaleTimeString(i18n.language, {
                  hour: "2-digit",
                  minute: "2-digit",
                }),
              })}
          </span>
        </footer>
      </div>

      {dialogOpen && (
        <div
          className="asset-modal-backdrop"
          role="presentation"
          onMouseDown={(event) => {
            if (event.target === event.currentTarget && !saving) requestCloseAssetDialog();
          }}
        >
          <form
            className="asset-modal"
            role="dialog"
            aria-modal="true"
            aria-labelledby="asset-editor-title"
            onSubmit={(event) => void saveAsset(event)}
            onKeyDown={(event) => {
              if (event.key === "Escape" && !event.nativeEvent.isComposing) {
                event.preventDefault();
                event.stopPropagation();
                requestCloseAssetDialog();
              }
            }}
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
                      (asset) =>
                        isSSHProtocol(asset.protocol) &&
                        !asset.ssh_workspace &&
                        asset.id !== editingAsset?.id,
                    )
                    .flatMap((asset) =>
                      (asset.accounts?.length
                        ? asset.accounts
                        : [{ id: asset.id, username: asset.username, active: true }]
                      ).map((account) => (
                        <option key={account.id} value={account.id} disabled={!account.active}>
                          {asset.name} ({account.username}@{asset.host})
                        </option>
                      )),
                    )}
                </select>
                <small>{t("assets.gatewayHint")}</small>
              </label>
              {isSSHProtocol(form.protocol) && (
                <label className="asset-form-wide">
                  <span id="ssh-workspace-label">{t("assets.workspace")}</span>
                  <input
                    aria-labelledby="ssh-workspace-label"
                    aria-describedby="ssh-workspace-hint"
                    value={form.ssh_workspace}
                    onChange={(event) => setForm({ ...form, ssh_workspace: event.target.value })}
                    placeholder="/srv/workspace"
                    maxLength={1024}
                  />
                  <small id="ssh-workspace-hint">{t("assets.workspaceHint")}</small>
                </label>
              )}
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
      {managedAccountsAsset && (
        <Suspense fallback={null}>
          <ManagedAccountsDialog
            assetId={managedAccountsAsset.id}
            assetName={managedAccountsAsset.name}
            selectedId={
              selectedAccounts[managedAccountsAsset.id] ||
              managedAccountsAsset.selected_account_id ||
              managedAccountsAsset.id
            }
            accessToken={accessToken}
            discovered={managedFinding}
            onChanged={() => void loadAssets()}
            onSelect={async (account) => {
              await loadAssets();
              setSelectedAccounts((v) => ({ ...v, [managedAccountsAsset.id]: account.id }));
            }}
            onClose={() => {
              setManagedAccountsAsset(null);
              setManagedFinding(undefined);
            }}
          />
        </Suspense>
      )}
      {importOpen && (
        <Suspense fallback={null}>
          <AccountImportDialog
            accessToken={accessToken}
            hosts={assets}
            onChanged={() => void loadAssets()}
            onClose={() => setImportOpen(false)}
          />
        </Suspense>
      )}
      {discoveryAsset && (
        <Suspense fallback={null}>
          <AccountDiscoveryDialog
            assetId={discoveryAsset.id}
            assetName={discoveryAsset.name}
            accessToken={accessToken}
            canConnect={Boolean(discoveryAsset.permissions?.includes("connect"))}
            onManage={(finding) => {
              const parent = assets.find(
                (a) => a.id === (discoveryAsset.parent_asset_id || discoveryAsset.id),
              );
              if (!parent) return;
              setManagedFinding(finding);
              setManagedAccountsAsset(parent);
              setDiscoveryAsset(null);
            }}
            onClose={() => setDiscoveryAsset(null)}
          />
        </Suspense>
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
            workspace={fileAsset.ssh_workspace}
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
      {historyAsset && (
        <Suspense fallback={null}>
          <MonitorHistoryDialog
            asset={historyAsset}
            request={request}
            onClose={() => setHistoryAsset(null)}
          />
        </Suspense>
      )}
    </section>
  );
}
