import PasswordRules from "../components/PasswordRules";
import { lazy, Suspense, useCallback, useEffect, useMemo, useState, type FormEvent } from "react";
import { useTranslation } from "react-i18next";
import { useAuth } from "../auth/AuthContext";
const PasswordSecuritySettings = lazy(() => import("../components/PasswordSecuritySettings"));
const SessionSecuritySettings = lazy(() => import("../components/SessionSecuritySettings"));

type User = { id: string; username: string; role: "admin" | "operator"; created_at: string };
type MFAEnforcementMode = "disabled" | "admins" | "all";
type MFAEnforcementSettings = { mode: MFAEnforcementMode };
type UserGroup = {
  id: string;
  name: string;
  description?: string;
  user_ids: string[];
  created_at: string;
};
type Asset = {
  id: string;
  name: string;
  username: string;
  node_id?: string;
  accounts?: { username: string; active: boolean }[];
};
const assetAccounts = (asset: Asset | undefined) =>
  asset?.accounts?.map((a) => a.username) || (asset ? [asset.username] : []);
type AssetNode = { id: string; name: string; parent_id?: string };
type GrantAction = "view" | "connect" | "sftp";
type Grant = {
  id: string;
  user_id?: string;
  group_id?: string;
  asset_id?: string;
  node_id?: string;
  account: string;
  actions: GrantAction[];
  starts_at?: string;
  ends_at?: string;
  created_at: string;
  created_by: string;
};
type CommandFilter = {
  id: string;
  name: string;
  user_id?: string;
  group_id?: string;
  asset_id?: string;
  node_id?: string;
  account: string;
  match: "exact" | "contains" | "regex";
  pattern: string;
  action: "allow" | "deny" | "review";
  priority: number;
  starts_at?: string;
  ends_at?: string;
  created_at: string;
  created_by: string;
};
type CommandReview = {
  actor?: string;
  id: string;
  session_id: string;
  asset_id: string;
  asset_name: string;
  operator: string;
  account: string;
  command: string;
  rule_name: string;
  requested_at: string;
  expires_at: string;
};
type CommandReviewPage = { results: CommandReview[]; total: number };
type LoginAccessReview = {
  id: string;
  action:
    | "ssh"
    | "sftp"
    | "database"
    | "kubernetes"
    | "telnet"
    | "account_discovery"
    | "remote_account";
  operator: string;
  asset_id: string;
  asset_name: string;
  account: string;
  requested_at: string;
  expires_at: string;
};
type LoginAccessReviewPage = { results: LoginAccessReview[]; total: number };
type CommandFilterDraft = {
  name: string;
  target: "all" | "user" | "group";
  userID: string;
  groupID: string;
  scope: "all" | "asset" | "node";
  assetID: string;
  nodeID: string;
  account: string;
  match: CommandFilter["match"];
  pattern: string;
  action: CommandFilter["action"];
  priority: string;
  startsAt: string;
  endsAt: string;
};

const actions: GrantAction[] = ["view", "connect", "sftp"];
const settingPermissions = {
  users: "users.manage",
  groups: "groups.manage",
  grants: "grants.manage",
  nodes: "nodes.manage",
  filters: "command_filters.manage",
  reviews: "reviews.command.manage",
  loginReviews: "reviews.login.manage",
  security: "security.manage",
} as const;

function formatDate(value: string, locale: string) {
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? "—" : date.toLocaleString(locale);
}

function asISO(value: string) {
  return value ? new Date(value).toISOString() : undefined;
}

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

function nodeDescendants(nodes: AssetNode[], nodeID: string) {
  const result = new Set([nodeID]);
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

export default function SettingsPage() {
  const { t, i18n } = useTranslation();
  const { accessToken, setAccessToken } = useAuth();
  const [tokenDraft, setTokenDraft] = useState("");
  const [tokenRequired, setTokenRequired] = useState(false);
  const [tokenRejected, setTokenRejected] = useState(false);
  const [role, setRole] = useState("");
  const [systemPermissions, setSystemPermissions] = useState<string[]>([]);
  const allows = (permission: string) => systemPermissions.includes(permission);
  const canSettings = Object.values(settingPermissions).some(allows);
  const [users, setUsers] = useState<User[]>([]);
  const [groups, setGroups] = useState<UserGroup[]>([]);
  const [assets, setAssets] = useState<Asset[]>([]);
  const [nodes, setNodes] = useState<AssetNode[]>([]);
  const [grants, setGrants] = useState<Grant[]>([]);
  const [commandFilters, setCommandFilters] = useState<CommandFilter[]>([]);
  const [pendingReviews, setPendingReviews] = useState<CommandReview[]>([]);
  const [pendingLoginReviews, setPendingLoginReviews] = useState<LoginAccessReview[]>([]);
  const [mfaEnforcement, setMfaEnforcement] = useState<MFAEnforcementMode>("disabled");
  const [mfaPolicySaved, setMfaPolicySaved] = useState(false);
  const [mfaPolicyError, setMfaPolicyError] = useState(false);
  const [tab, setTab] = useState<
    "users" | "groups" | "grants" | "nodes" | "filters" | "reviews" | "loginReviews" | "security"
  >("grants");
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState(false);
  const [failed, setFailed] = useState(false);
  const [reviewLoadFailed, setReviewLoadFailed] = useState(false);
  const [loginReviewLoadFailed, setLoginReviewLoadFailed] = useState(false);
  const [reviewNotice, setReviewNotice] = useState("");
  const [userName, setUserName] = useState("");
  const [userPassword, setUserPassword] = useState("");
  const [userRole, setUserRole] = useState<User["role"]>("operator");
  const [groupName, setGroupName] = useState("");
  const [groupDescription, setGroupDescription] = useState("");
  const [nodeName, setNodeName] = useState("");
  const [nodeParentID, setNodeParentID] = useState("");
  const [nodeNameDrafts, setNodeNameDrafts] = useState<Record<string, string>>({});
  const [nodeParentDrafts, setNodeParentDrafts] = useState<Record<string, string>>({});
  const [memberDrafts, setMemberDrafts] = useState<Record<string, string>>({});
  const [grantTarget, setGrantTarget] = useState<"user" | "group">("user");
  const [grantScope, setGrantScope] = useState<"asset" | "node">("asset");
  const [grantUserID, setGrantUserID] = useState("");
  const [grantGroupID, setGrantGroupID] = useState("");
  const [grantAssetID, setGrantAssetID] = useState("");
  const [grantNodeID, setGrantNodeID] = useState("");
  const [grantAccount, setGrantAccount] = useState("");
  const [grantActions, setGrantActions] = useState<GrantAction[]>([]);
  const [startsAt, setStartsAt] = useState("");
  const [endsAt, setEndsAt] = useState("");
  const [filterDraft, setFilterDraft] = useState<CommandFilterDraft>({
    name: "",
    target: "all",
    userID: "",
    groupID: "",
    scope: "all",
    assetID: "",
    nodeID: "",
    account: "*",
    match: "contains",
    pattern: "",
    action: "deny",
    priority: "100",
    startsAt: "",
    endsAt: "",
  });

  const request = useCallback(
    (url: string, init?: RequestInit) => {
      const headers = new Headers(init?.headers);
      if (accessToken) headers.set("Authorization", `Bearer ${accessToken}`);
      return fetch(url, { ...init, headers });
    },
    [accessToken],
  );

  const refreshCommandReviews = useCallback(async () => {
    try {
      const response = await request("/api/v1/command-reviews");
      if (!response.ok) throw new Error("command review request failed");
      const result = (await response.json()) as CommandReviewPage;
      setPendingReviews(result.results);
      setReviewLoadFailed(false);
    } catch {
      setReviewLoadFailed(true);
    }
  }, [request]);

  const refreshLoginReviews = useCallback(async () => {
    try {
      const response = await request("/api/v1/access-reviews");
      if (!response.ok) throw new Error("login review request failed");
      const result = (await response.json()) as LoginAccessReviewPage;
      setPendingLoginReviews(result.results);
      setLoginReviewLoadFailed(false);
    } catch {
      setLoginReviewLoadFailed(true);
    }
  }, [request]);

  const loadData = useCallback(async () => {
    setLoading(true);
    setFailed(false);
    try {
      const identityResponse = await request("/api/v1/users/me");
      if (identityResponse.status === 401) {
        setTokenRequired(true);
        setTokenRejected(Boolean(accessToken));
        setRole("");
        return;
      }
      if (!identityResponse.ok) throw new Error("identity request failed");
      const identity = (await identityResponse.json()) as { role?: string };
      setRole(identity.role ?? "");
      setTokenRequired(false);
      setTokenRejected(false);
      const permissionResponse = await request("/api/v1/rbac/me");
      if (!permissionResponse.ok) throw new Error("permissions unavailable");
      const snapshot = (await permissionResponse.json()) as { permissions: string[] };
      setSystemPermissions(snapshot.permissions);
      const can = (permission: string) => snapshot.permissions.includes(permission);
      const available = (
        Object.keys(settingPermissions) as Array<keyof typeof settingPermissions>
      ).filter((key) => can(settingPermissions[key]));
      if (!available.length) return;
      setTab((current) => (available.includes(current) ? current : available[0]));
      async function read<T>(path: string, permitted: boolean, fallback: T): Promise<T> {
        if (!permitted) return fallback;
        const response = await request(path);
        if (!response.ok) throw new Error("settings request failed");
        return response.json() as Promise<T>;
      }
      const [
        nextUsers,
        assetResults,
        nextGrants,
        nextGroups,
        nextNodes,
        nextFilters,
        reviewPage,
        loginReviewPage,
        mfaPolicy,
      ] = await Promise.all([
        read<User[]>(
          can("users.manage") ? "/api/v1/system/users" : "/api/v1/users",
          ["users.manage", "groups.manage", "grants.manage", "command_filters.manage"].some(can),
          [],
        ),
        read<Asset[]>("/api/v1/assets", true, []),
        read<Grant[]>("/api/v1/grants", can("grants.manage"), []),
        read<UserGroup[]>(
          "/api/v1/user-groups",
          ["groups.manage", "grants.manage", "command_filters.manage"].some(can),
          [],
        ),
        read<AssetNode[]>("/api/v1/assets/nodes", true, []),
        read<CommandFilter[]>("/api/v1/command-filters", can("command_filters.manage"), []),
        read<CommandReviewPage>("/api/v1/command-reviews", can("reviews.command.manage"), {
          results: [],
          total: 0,
        }),
        read<LoginAccessReviewPage>("/api/v1/access-reviews", can("reviews.login.manage"), {
          results: [],
          total: 0,
        }),
        read<MFAEnforcementSettings>("/api/v1/settings/security/mfa", can("security.manage"), {
          mode: "disabled",
        }),
      ]);
      setUsers(nextUsers);
      setGroups(nextGroups);
      setAssets(assetResults);
      setNodes(nextNodes);
      setGrants(nextGrants);
      setCommandFilters(nextFilters);
      setPendingReviews(reviewPage.results);
      setPendingLoginReviews(loginReviewPage.results);
      setMfaEnforcement(mfaPolicy.mode);
      setReviewLoadFailed(false);
      setLoginReviewLoadFailed(false);
      setGrantUserID(
        (current) => current || nextUsers.find((user) => user.role === "operator")?.id || "",
      );
      setGrantGroupID((current) => current || nextGroups[0]?.id || "");
      setGrantAssetID((current) => current || assetResults[0]?.id || "");
      setGrantNodeID((current) => current || nextNodes[0]?.id || "");
      setGrantAccount((current) => current || assetResults[0]?.username || "");
      setNodeNameDrafts(Object.fromEntries(nextNodes.map((node) => [node.id, node.name])));
      setNodeParentDrafts(
        Object.fromEntries(nextNodes.map((node) => [node.id, node.parent_id ?? ""])),
      );
      setMemberDrafts((current) => {
        const next = { ...current };
        for (const group of nextGroups) {
          const available = nextUsers.find(
            (user) =>
              user.role === "operator" &&
              !group.user_ids.includes(user.id) &&
              user.id === next[group.id],
          );
          if (!available)
            next[group.id] =
              nextUsers.find(
                (user) => user.role === "operator" && !group.user_ids.includes(user.id),
              )?.id ?? "";
        }
        return next;
      });
    } catch {
      setFailed(true);
    } finally {
      setLoading(false);
    }
  }, [accessToken, request]);

  useEffect(() => {
    if (!systemPermissions.includes("reviews.command.manage") || tab !== "reviews") return;
    const timer = window.setInterval(() => void refreshCommandReviews(), 5_000);
    return () => window.clearInterval(timer);
  }, [refreshCommandReviews, systemPermissions, tab]);

  useEffect(() => {
    if (!systemPermissions.includes("reviews.login.manage") || tab !== "loginReviews") return;
    const timer = window.setInterval(() => void refreshLoginReviews(), 5_000);
    return () => window.clearInterval(timer);
  }, [refreshLoginReviews, systemPermissions, tab]);

  useEffect(() => {
    // The initial request resolves permissions from the server before exposing admin data.
    // eslint-disable-next-line react/set-state-in-effect
    void loadData();
  }, [loadData]);

  const usersByID = useMemo(() => new Map(users.map((user) => [user.id, user])), [users]);
  const groupsByID = useMemo(() => new Map(groups.map((group) => [group.id, group])), [groups]);
  const assetsByID = useMemo(() => new Map(assets.map((asset) => [asset.id, asset])), [assets]);
  const grantAssetAccounts = assetAccounts(assetsByID.get(grantAssetID));
  const selectedGrantAccount =
    grantScope === "asset"
      ? grantAssetAccounts.includes(grantAccount)
        ? grantAccount
        : grantAssetAccounts[0] || ""
      : grantAccount.trim();
  const nodesByID = useMemo(() => new Map(nodes.map((node) => [node.id, node])), [nodes]);
  const grantNodeAssets = useMemo(() => {
    const inScope = nodeDescendants(nodes, grantNodeID);
    return assets.filter((asset) => asset.node_id && inScope.has(asset.node_id));
  }, [assets, grantNodeID, nodes]);
  const grantNodeAccounts = useMemo(
    () => [...new Set(grantNodeAssets.flatMap(assetAccounts))].sort(),
    [grantNodeAssets],
  );

  function applyToken(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setAccessToken(tokenDraft.trim());
    setTokenRejected(false);
  }

  async function createUser(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setBusy(true);
    setFailed(false);
    try {
      const response = await request("/api/v1/users", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username: userName.trim(), password: userPassword, role: userRole }),
      });
      if (!response.ok) throw new Error("user create failed");
      setUserName("");
      setUserPassword("");
      await loadData();
    } catch {
      setFailed(true);
    } finally {
      setBusy(false);
    }
  }

  async function saveMFAEnforcement(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setBusy(true);
    setMfaPolicySaved(false);
    setMfaPolicyError(false);
    try {
      const response = await request("/api/v1/settings/security/mfa", {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ mode: mfaEnforcement }),
      });
      if (!response.ok) throw new Error("MFA policy update failed");
      const result = (await response.json()) as MFAEnforcementSettings;
      setMfaEnforcement(result.mode);
      setMfaPolicySaved(true);
    } catch {
      setMfaPolicyError(true);
    } finally {
      setBusy(false);
    }
  }

  async function createGroup(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setBusy(true);
    setFailed(false);
    try {
      const response = await request("/api/v1/user-groups", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ name: groupName.trim(), description: groupDescription.trim() }),
      });
      if (!response.ok) throw new Error("group create failed");
      setGroupName("");
      setGroupDescription("");
      await loadData();
    } catch {
      setFailed(true);
    } finally {
      setBusy(false);
    }
  }

  async function createNode(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setBusy(true);
    setFailed(false);
    try {
      const response = await request("/api/v1/assets/nodes", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ name: nodeName.trim(), parent_id: nodeParentID }),
      });
      if (!response.ok) throw new Error("asset node create failed");
      setNodeName("");
      setNodeParentID("");
      await loadData();
    } catch {
      setFailed(true);
    } finally {
      setBusy(false);
    }
  }

  async function updateNode(node: AssetNode) {
    setBusy(true);
    setFailed(false);
    try {
      const response = await request(`/api/v1/assets/nodes/${encodeURIComponent(node.id)}`, {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          name: (nodeNameDrafts[node.id] ?? node.name).trim(),
          parent_id: nodeParentDrafts[node.id] ?? node.parent_id ?? "",
        }),
      });
      if (!response.ok) throw new Error("asset node update failed");
      await loadData();
    } catch {
      setFailed(true);
    } finally {
      setBusy(false);
    }
  }

  async function deleteNode(node: AssetNode) {
    if (!window.confirm(t("settings.deleteNodeConfirm", { node: node.name }))) return;
    setBusy(true);
    setFailed(false);
    try {
      const response = await request(`/api/v1/assets/nodes/${encodeURIComponent(node.id)}`, {
        method: "DELETE",
      });
      if (!response.ok) throw new Error("asset node delete failed");
      await loadData();
    } catch {
      setFailed(true);
    } finally {
      setBusy(false);
    }
  }

  async function updateGroupMember(group: UserGroup, userID: string, add: boolean) {
    if (!userID) return;
    setBusy(true);
    setFailed(false);
    try {
      const response = await request(
        `/api/v1/user-groups/${encodeURIComponent(group.id)}/members/${encodeURIComponent(userID)}`,
        { method: add ? "PUT" : "DELETE" },
      );
      if (!response.ok) throw new Error("group membership update failed");
      await loadData();
    } catch {
      setFailed(true);
    } finally {
      setBusy(false);
    }
  }

  async function deleteGroup(group: UserGroup) {
    if (!window.confirm(t("settings.deleteGroupConfirm", { group: group.name }))) return;
    setBusy(true);
    setFailed(false);
    try {
      const response = await request(`/api/v1/user-groups/${encodeURIComponent(group.id)}`, {
        method: "DELETE",
      });
      if (!response.ok) throw new Error("group delete failed");
      await loadData();
    } catch {
      setFailed(true);
    } finally {
      setBusy(false);
    }
  }

  async function createGrant(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const subjectID = grantTarget === "group" ? grantGroupID : grantUserID;
    const scopeID = grantScope === "node" ? grantNodeID : grantAssetID;
    const account = selectedGrantAccount;
    if (grantScope === "asset" && !assetAccounts(assetsByID.get(grantAssetID)).includes(account))
      return;
    if (!subjectID || !scopeID || !account || grantActions.length === 0) return;
    setBusy(true);
    setFailed(false);
    try {
      const response = await request("/api/v1/grants", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          ...(grantTarget === "group" ? { group_id: grantGroupID } : { user_id: grantUserID }),
          ...(grantScope === "node" ? { node_id: grantNodeID } : { asset_id: grantAssetID }),
          account,
          actions: grantActions,
          starts_at: asISO(startsAt),
          ends_at: asISO(endsAt),
        }),
      });
      if (!response.ok) throw new Error("grant create failed");
      setStartsAt("");
      setEndsAt("");
      await loadData();
    } catch {
      setFailed(true);
    } finally {
      setBusy(false);
    }
  }

  async function deleteGrant(grant: Grant) {
    const subject = grant.group_id
      ? (groupsByID.get(grant.group_id)?.name ?? grant.group_id)
      : (usersByID.get(grant.user_id ?? "")?.username ?? grant.user_id);
    const scope = grant.node_id
      ? (nodesByID.get(grant.node_id)?.name ?? grant.node_id)
      : (assetsByID.get(grant.asset_id ?? "")?.name ?? grant.asset_id);
    if (
      !window.confirm(
        t("settings.deleteGrantConfirm", { user: subject ?? "—", target: scope ?? "—" }),
      )
    )
      return;
    setBusy(true);
    setFailed(false);
    try {
      const response = await request(`/api/v1/grants/${encodeURIComponent(grant.id)}`, {
        method: "DELETE",
      });
      if (!response.ok) throw new Error("grant delete failed");
      await loadData();
    } catch {
      setFailed(true);
    } finally {
      setBusy(false);
    }
  }

  async function createCommandFilter(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setBusy(true);
    setFailed(false);
    try {
      const response = await request("/api/v1/command-filters", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          name: filterDraft.name.trim(),
          ...(filterDraft.target === "user" ? { user_id: filterDraft.userID } : {}),
          ...(filterDraft.target === "group" ? { group_id: filterDraft.groupID } : {}),
          ...(filterDraft.scope === "asset" ? { asset_id: filterDraft.assetID } : {}),
          ...(filterDraft.scope === "node" ? { node_id: filterDraft.nodeID } : {}),
          account: filterDraft.account.trim() || "*",
          match: filterDraft.match,
          pattern: filterDraft.pattern.trim(),
          action: filterDraft.action,
          priority: Number(filterDraft.priority),
          starts_at: asISO(filterDraft.startsAt),
          ends_at: asISO(filterDraft.endsAt),
        }),
      });
      if (!response.ok) throw new Error("command filter create failed");
      setFilterDraft((current) => ({
        ...current,
        name: "",
        pattern: "",
        startsAt: "",
        endsAt: "",
      }));
      await loadData();
    } catch {
      setFailed(true);
    } finally {
      setBusy(false);
    }
  }

  async function deleteCommandFilter(filter: CommandFilter) {
    if (!window.confirm(t("settings.deleteFilterConfirm", { name: filter.name }))) return;
    setBusy(true);
    setFailed(false);
    try {
      const response = await request(`/api/v1/command-filters/${encodeURIComponent(filter.id)}`, {
        method: "DELETE",
      });
      if (!response.ok) throw new Error("command filter delete failed");
      await loadData();
    } catch {
      setFailed(true);
    } finally {
      setBusy(false);
    }
  }

  async function resolveCommandReview(review: CommandReview, decision: "approve" | "deny") {
    if (
      decision === "approve" &&
      !window.confirm(t("settings.approveReviewConfirm", { command: review.command }))
    )
      return;
    setBusy(true);
    setFailed(false);
    setReviewNotice("");
    try {
      const response = await request(
        `/api/v1/command-reviews/${encodeURIComponent(review.id)}/${decision}`,
        { method: "POST" },
      );
      if (response.status === 409) {
        setReviewNotice("stale");
        await refreshCommandReviews();
        return;
      }
      if (!response.ok) throw new Error("command review resolution failed");
      await refreshCommandReviews();
    } catch {
      setFailed(true);
    } finally {
      setBusy(false);
    }
  }

  async function resolveLoginReview(review: LoginAccessReview, decision: "approve" | "deny") {
    if (
      decision === "approve" &&
      !window.confirm(
        t("settings.approveLoginReviewConfirm", {
          operator: review.operator,
          asset: review.asset_name,
          action: t(
            review.action === "telnet"
              ? "telnet.reviewAction"
              : review.action === "kubernetes"
                ? "kubernetes.reviewAction"
                : review.action === "database"
                  ? "database.reviewAction"
                  : review.action === "sftp"
                    ? "settings.sftpReviewAction"
                    : review.action === "account_discovery"
                      ? "accountSchedule.approval"
                      : review.action === "remote_account"
                        ? "remoteAccounts.approval"
                        : "settings.sshReviewAction",
          ),
        }),
      )
    )
      return;
    setBusy(true);
    setFailed(false);
    setReviewNotice("");
    try {
      const response = await request(
        `/api/v1/access-reviews/${encodeURIComponent(review.id)}/${decision}`,
        { method: "POST" },
      );
      if (response.status === 409) {
        setReviewNotice("stale");
        await refreshLoginReviews();
        return;
      }
      if (!response.ok) throw new Error("login review resolution failed");
      await refreshLoginReviews();
    } catch {
      setFailed(true);
    } finally {
      setBusy(false);
    }
  }

  return (
    <section className="admin-settings">
      <header className="admin-settings-heading">
        <div>
          <h2>{t("settings.title")}</h2>
          <p>{t("settings.subtitle")}</p>
        </div>
        {canSettings && (
          <button
            type="button"
            className="button-secondary"
            onClick={() => void loadData()}
            disabled={loading}
          >
            {loading ? "…" : t("settings.refresh")}
          </button>
        )}
      </header>

      {tokenRequired && (
        <form className="asset-token-panel" onSubmit={applyToken}>
          <div>
            <strong>{t("settings.tokenRequired")}</strong>
            {tokenRejected && <p role="alert">{t("settings.tokenRejected")}</p>}
          </div>
          <label>
            <span>{t("settings.tokenLabel")}</span>
            <input
              type="password"
              value={tokenDraft}
              onChange={(event) => setTokenDraft(event.target.value)}
              autoComplete="current-password"
            />
          </label>
          <button type="submit" className="button-primary">
            {t("settings.tokenApply")}
          </button>
        </form>
      )}
      {role && !canSettings && <div className="settings-notice">{t("rbac.settingsDenied")}</div>}
      {failed && (
        <p className="asset-error" role="alert">
          {t("settings.loadError")}
        </p>
      )}

      {canSettings && (
        <>
          <div className="audit-tabs settings-tabs" role="tablist" aria-label={t("settings.title")}>
            {(Object.keys(settingPermissions) as Array<keyof typeof settingPermissions>)
              .filter((key) => allows(settingPermissions[key]))
              .map((key) => (
                <button
                  key={key}
                  type="button"
                  role="tab"
                  aria-selected={tab === key}
                  className={tab === key ? "active" : ""}
                  onClick={() => {
                    setTab(key);
                    if (key === "reviews") void refreshCommandReviews();
                    if (key === "loginReviews") void refreshLoginReviews();
                  }}
                >
                  {t(
                    `settings.${{ users: "usersTab", groups: "groupsTab", grants: "grantsTab", nodes: "nodesTab", filters: "commandFiltersTab", reviews: "commandReviewsTab", loginReviews: "loginReviewsTab", security: "securityTab" }[key]}`,
                  )}
                  {key === "reviews" && (
                    <span className="settings-review-count">{pendingReviews.length}</span>
                  )}
                  {key === "loginReviews" && (
                    <span className="settings-review-count">{pendingLoginReviews.length}</span>
                  )}
                </button>
              ))}
          </div>

          {tab === "security" && (
            <div className="settings-columns">
              <Suspense fallback={null}>
                <SessionSecuritySettings />
                <PasswordSecuritySettings />
              </Suspense>
              <form
                className="settings-card settings-form"
                onSubmit={(event) => void saveMFAEnforcement(event)}
              >
                <h3>{t("settings.mfaPolicyTitle")}</h3>
                <p>{t("settings.mfaPolicyDescription")}</p>
                <label>
                  <span>{t("settings.mfaPolicyMode")}</span>
                  <select
                    value={mfaEnforcement}
                    onChange={(event) => {
                      setMfaEnforcement(event.target.value as MFAEnforcementMode);
                      setMfaPolicySaved(false);
                      setMfaPolicyError(false);
                    }}
                  >
                    <option value="disabled">{t("settings.mfaPolicyDisabled")}</option>
                    <option value="admins">{t("settings.mfaPolicyAdmins")}</option>
                    <option value="all">{t("settings.mfaPolicyAll")}</option>
                  </select>
                </label>
                <p className="settings-help">{t("settings.mfaPolicyKeyRequired")}</p>
                {mfaPolicyError && (
                  <p className="asset-error" role="alert">
                    {t("settings.mfaPolicyError")}
                  </p>
                )}
                {mfaPolicySaved && (
                  <p className="settings-notice" role="status">
                    {t("settings.mfaPolicySaved")}
                  </p>
                )}
                <button type="submit" className="button-primary" disabled={busy}>
                  {busy ? "…" : t("settings.mfaPolicySave")}
                </button>
              </form>
            </div>
          )}

          {tab === "users" && (
            <div className="settings-columns">
              <form
                className="settings-card settings-form"
                onSubmit={(event) => void createUser(event)}
              >
                <h3>{t("settings.createUser")}</h3>
                <label>
                  <span>{t("settings.username")}</span>
                  <input
                    required
                    minLength={3}
                    maxLength={64}
                    value={userName}
                    onChange={(event) => setUserName(event.target.value)}
                    autoComplete="off"
                  />
                </label>
                <label>
                  <span>{t("settings.password")}</span>
                  <input
                    required
                    minLength={12}
                    maxLength={256}
                    type="password"
                    value={userPassword}
                    onChange={(event) => setUserPassword(event.target.value)}
                    autoComplete="new-password"
                  />
                </label>
                <PasswordRules admin={userRole === "admin"} />
                <label>
                  <span>{t("settings.role")}</span>
                  <select
                    value={userRole}
                    onChange={(event) => setUserRole(event.target.value as User["role"])}
                  >
                    <option value="operator">{t("settings.operator")}</option>
                    {allows("roles.manage") && (
                      <option value="admin">{t("settings.administrator")}</option>
                    )}
                  </select>
                </label>
                <button type="submit" className="button-primary" disabled={busy}>
                  {busy ? "…" : t("settings.create")}
                </button>
              </form>
              <div className="settings-card settings-table-card">
                <h3>
                  {t("settings.usersTab")} <span>{users.length}</span>
                </h3>
                <div className="settings-table-wrap">
                  <table className="settings-table">
                    <thead>
                      <tr>
                        <th>{t("settings.username")}</th>
                        <th>{t("settings.role")}</th>
                        <th>{t("settings.created")}</th>
                      </tr>
                    </thead>
                    <tbody>
                      {users.map((user) => (
                        <tr key={user.id}>
                          <td>
                            <strong>{user.username}</strong>
                            <small>{user.id}</small>
                          </td>
                          <td>{t(`settings.roles.${user.role}`)}</td>
                          <td>{formatDate(user.created_at, i18n.language)}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
                {!loading && users.length === 0 && (
                  <div className="settings-empty">{t("settings.noUsers")}</div>
                )}
              </div>
            </div>
          )}

          {tab === "groups" && (
            <div className="settings-columns">
              <form
                className="settings-card settings-form"
                onSubmit={(event) => void createGroup(event)}
              >
                <h3>{t("settings.createGroup")}</h3>
                <label>
                  <span>{t("settings.groupName")}</span>
                  <input
                    required
                    minLength={1}
                    maxLength={64}
                    value={groupName}
                    onChange={(event) => setGroupName(event.target.value)}
                  />
                </label>
                <label>
                  <span>{t("settings.groupDescription")}</span>
                  <input
                    maxLength={256}
                    value={groupDescription}
                    onChange={(event) => setGroupDescription(event.target.value)}
                  />
                </label>
                <button type="submit" className="button-primary" disabled={busy}>
                  {busy ? "…" : t("settings.create")}
                </button>
              </form>
              <div className="settings-group-list">
                {groups.map((group) => {
                  const availableUsers = users.filter(
                    (user) => user.role === "operator" && !group.user_ids.includes(user.id),
                  );
                  const groupHasGrants = grants.some((grant) => grant.group_id === group.id);
                  return (
                    <article className="settings-card settings-group-card" key={group.id}>
                      <header className="settings-group-header">
                        <div>
                          <h3>{group.name}</h3>
                          {group.description && <p>{group.description}</p>}
                        </div>
                        <button
                          type="button"
                          className="button-text danger"
                          disabled={busy || groupHasGrants}
                          onClick={() => void deleteGroup(group)}
                        >
                          {t("settings.deleteGroup")}
                        </button>
                      </header>
                      {groupHasGrants && (
                        <p className="settings-help">{t("settings.groupHasGrants")}</p>
                      )}
                      <div className="settings-group-controls">
                        <label>
                          <span>{t("settings.addMember")}</span>
                          <select
                            value={memberDrafts[group.id] ?? ""}
                            onChange={(event) =>
                              setMemberDrafts((current) => ({
                                ...current,
                                [group.id]: event.target.value,
                              }))
                            }
                          >
                            <option value="">{t("settings.selectMember")}</option>
                            {availableUsers.map((user) => (
                              <option value={user.id} key={user.id}>
                                {user.username}
                              </option>
                            ))}
                          </select>
                        </label>
                        <button
                          type="button"
                          className="button-secondary"
                          disabled={busy || !memberDrafts[group.id] || availableUsers.length === 0}
                          onClick={() =>
                            void updateGroupMember(group, memberDrafts[group.id], true)
                          }
                        >
                          {t("settings.add")}
                        </button>
                      </div>
                      <div className="settings-group-members">
                        <strong>
                          {t("settings.members")} <span>{group.user_ids.length}</span>
                        </strong>
                        {group.user_ids.length > 0 ? (
                          group.user_ids.map((userID) => (
                            <span className="settings-group-member" key={userID}>
                              {usersByID.get(userID)?.username ?? userID}
                              <button
                                type="button"
                                className="button-text danger"
                                disabled={busy}
                                aria-label={t("settings.removeMemberLabel", {
                                  user: usersByID.get(userID)?.username ?? userID,
                                })}
                                onClick={() => void updateGroupMember(group, userID, false)}
                              >
                                {t("settings.removeMember")}
                              </button>
                            </span>
                          ))
                        ) : (
                          <p>{t("settings.noMembers")}</p>
                        )}
                      </div>
                    </article>
                  );
                })}
                {!loading && groups.length === 0 && (
                  <div className="settings-card settings-empty">{t("settings.noGroups")}</div>
                )}
              </div>
            </div>
          )}

          {tab === "nodes" && (
            <div className="settings-columns">
              <form
                className="settings-card settings-form"
                onSubmit={(event) => void createNode(event)}
              >
                <h3>{t("settings.createNode")}</h3>
                <label>
                  <span>{t("settings.nodeName")}</span>
                  <input
                    required
                    minLength={1}
                    maxLength={64}
                    value={nodeName}
                    onChange={(event) => setNodeName(event.target.value)}
                  />
                </label>
                <label>
                  <span>{t("settings.parentNode")}</span>
                  <select
                    value={nodeParentID}
                    onChange={(event) => setNodeParentID(event.target.value)}
                  >
                    <option value="">{t("settings.rootNode")}</option>
                    {nodes.map((node) => (
                      <option key={node.id} value={node.id}>
                        {nodeAncestors(nodes, node.id)
                          .map((ancestor) => ancestor.name)
                          .join(" / ")}
                      </option>
                    ))}
                  </select>
                </label>
                <button type="submit" className="button-primary" disabled={busy}>
                  {busy ? "…" : t("settings.create")}
                </button>
              </form>
              <div className="settings-group-list">
                {nodes.map((node) => {
                  const descendants = nodeDescendants(nodes, node.id);
                  const childCount = nodes.filter(
                    (candidate) => candidate.parent_id === node.id,
                  ).length;
                  const assignedAssetCount = assets.filter(
                    (asset) => asset.node_id === node.id,
                  ).length;
                  const nodeGrantCount = grants.filter((grant) => grant.node_id === node.id).length;
                  const cannotDelete =
                    childCount > 0 || assignedAssetCount > 0 || nodeGrantCount > 0;
                  const parentChoices = nodes.filter(
                    (candidate) => candidate.id !== node.id && !descendants.has(candidate.id),
                  );
                  const nodePath = nodeAncestors(nodes, node.id)
                    .map((ancestor) => ancestor.name)
                    .join(" / ");
                  return (
                    <article className="settings-card settings-node-card" key={node.id}>
                      <header className="settings-group-header">
                        <div>
                          <h3>{nodePath}</h3>
                          <small>{node.id}</small>
                        </div>
                      </header>
                      <div className="settings-node-fields">
                        <label>
                          <span>{t("settings.nodeName")}</span>
                          <input
                            required
                            maxLength={64}
                            value={nodeNameDrafts[node.id] ?? node.name}
                            onChange={(event) =>
                              setNodeNameDrafts((current) => ({
                                ...current,
                                [node.id]: event.target.value,
                              }))
                            }
                          />
                        </label>
                        <label>
                          <span>{t("settings.parentNode")}</span>
                          <select
                            value={nodeParentDrafts[node.id] ?? node.parent_id ?? ""}
                            onChange={(event) =>
                              setNodeParentDrafts((current) => ({
                                ...current,
                                [node.id]: event.target.value,
                              }))
                            }
                          >
                            <option value="">{t("settings.rootNode")}</option>
                            {parentChoices.map((candidate) => (
                              <option key={candidate.id} value={candidate.id}>
                                {nodeAncestors(nodes, candidate.id)
                                  .map((ancestor) => ancestor.name)
                                  .join(" / ")}
                              </option>
                            ))}
                          </select>
                        </label>
                      </div>
                      {cannotDelete && (
                        <p className="settings-help">
                          {t("settings.nodeDeleteBlocked", {
                            children: childCount,
                            assets: assignedAssetCount,
                            grants: nodeGrantCount,
                          })}
                        </p>
                      )}
                      <div className="settings-node-actions">
                        <button
                          type="button"
                          className="button-secondary"
                          disabled={busy}
                          onClick={() => void updateNode(node)}
                        >
                          {t("settings.saveNode")}
                        </button>
                        <button
                          type="button"
                          className="button-text danger"
                          disabled={busy || cannotDelete}
                          onClick={() => void deleteNode(node)}
                        >
                          {t("settings.deleteNode")}
                        </button>
                      </div>
                    </article>
                  );
                })}
                {!loading && nodes.length === 0 && (
                  <div className="settings-card settings-empty">{t("settings.noNodes")}</div>
                )}
              </div>
            </div>
          )}

          {tab === "grants" && (
            <>
              <form
                className="settings-card settings-grant-form"
                onSubmit={(event) => void createGrant(event)}
              >
                <h3>{t("settings.createGrant")}</h3>
                <div className="settings-grant-fields">
                  <label>
                    <span>{t("settings.grantTarget")}</span>
                    <select
                      value={grantTarget}
                      onChange={(event) => setGrantTarget(event.target.value as "user" | "group")}
                    >
                      <option value="user">{t("settings.targetUser")}</option>
                      <option value="group">{t("settings.targetGroup")}</option>
                    </select>
                  </label>
                  {grantTarget === "user" ? (
                    <label>
                      <span>{t("settings.user")}</span>
                      <select
                        required
                        value={grantUserID}
                        onChange={(event) => setGrantUserID(event.target.value)}
                      >
                        <option value="">{t("settings.selectUser")}</option>
                        {users
                          .filter((user) => user.role === "operator")
                          .map((user) => (
                            <option key={user.id} value={user.id}>
                              {user.username}
                            </option>
                          ))}
                      </select>
                    </label>
                  ) : (
                    <label>
                      <span>{t("settings.group")}</span>
                      <select
                        required
                        value={grantGroupID}
                        onChange={(event) => setGrantGroupID(event.target.value)}
                      >
                        <option value="">{t("settings.selectGroup")}</option>
                        {groups.map((group) => (
                          <option key={group.id} value={group.id}>
                            {group.name}
                          </option>
                        ))}
                      </select>
                    </label>
                  )}
                  <label>
                    <span>{t("settings.scopeType")}</span>
                    <select
                      value={grantScope}
                      onChange={(event) => setGrantScope(event.target.value as "asset" | "node")}
                    >
                      <option value="asset">{t("settings.assetScope")}</option>
                      <option value="node">{t("settings.nodeScope")}</option>
                    </select>
                  </label>
                  {grantScope === "asset" ? (
                    <>
                      <label>
                        <span>{t("settings.asset")}</span>
                        <select
                          required
                          value={grantAssetID}
                          onChange={(event) => {
                            setGrantAssetID(event.target.value);
                            setGrantAccount(
                              assetAccounts(assetsByID.get(event.target.value))[0] || "",
                            );
                          }}
                        >
                          <option value="">{t("settings.selectAsset")}</option>
                          {assets.map((asset) => (
                            <option key={asset.id} value={asset.id}>
                              {asset.name} · {asset.username}
                            </option>
                          ))}
                        </select>
                      </label>
                      <label>
                        <span>{t("settings.sshAccount")}</span>
                        <select
                          required
                          value={selectedGrantAccount}
                          onChange={(event) => setGrantAccount(event.target.value)}
                        >
                          {assetAccounts(assetsByID.get(grantAssetID)).map((account) => (
                            <option key={account} value={account}>
                              {account}
                            </option>
                          ))}
                        </select>
                      </label>
                    </>
                  ) : (
                    <>
                      <label>
                        <span>{t("settings.node")}</span>
                        <select
                          required
                          value={grantNodeID}
                          onChange={(event) => {
                            setGrantNodeID(event.target.value);
                            const inScope = nodeDescendants(nodes, event.target.value);
                            const firstAccount = assets.find(
                              (asset) => asset.node_id && inScope.has(asset.node_id),
                            )?.username;
                            if (firstAccount) setGrantAccount(firstAccount);
                          }}
                        >
                          <option value="">{t("settings.selectNode")}</option>
                          {nodes.map((node) => (
                            <option key={node.id} value={node.id}>
                              {nodeAncestors(nodes, node.id)
                                .map((ancestor) => ancestor.name)
                                .join(" / ")}
                            </option>
                          ))}
                        </select>
                      </label>
                      <label>
                        <span>{t("settings.sshAccount")}</span>
                        <input
                          required
                          maxLength={128}
                          list="node-grant-accounts"
                          value={grantAccount}
                          onChange={(event) => setGrantAccount(event.target.value)}
                        />
                        <datalist id="node-grant-accounts">
                          {grantNodeAccounts.map((account) => (
                            <option key={account} value={account} />
                          ))}
                        </datalist>
                      </label>
                    </>
                  )}
                  <label>
                    <span>{t("settings.startsAt")}</span>
                    <input
                      type="datetime-local"
                      value={startsAt}
                      onChange={(event) => setStartsAt(event.target.value)}
                    />
                  </label>
                  <label>
                    <span>{t("settings.endsAt")}</span>
                    <input
                      type="datetime-local"
                      value={endsAt}
                      onChange={(event) => setEndsAt(event.target.value)}
                    />
                  </label>
                </div>
                <fieldset className="settings-actions">
                  <legend>{t("settings.actions")}</legend>
                  {actions.map((action) => (
                    <label key={action}>
                      <input
                        type="checkbox"
                        checked={grantActions.includes(action)}
                        onChange={(event) =>
                          setGrantActions((current) =>
                            event.target.checked
                              ? [...current, action]
                              : current.filter((value) => value !== action),
                          )
                        }
                      />
                      <span>{t(`settings.grantActions.${action}`)}</span>
                    </label>
                  ))}
                </fieldset>
                <button
                  type="submit"
                  className="button-primary"
                  disabled={
                    busy ||
                    (grantTarget === "user"
                      ? users.every((user) => user.role !== "operator")
                      : groups.length === 0) ||
                    (grantScope === "asset"
                      ? !grantAssetID || !selectedGrantAccount
                      : !grantNodeID || !grantAccount.trim()) ||
                    grantActions.length === 0
                  }
                >
                  {busy ? "…" : t("settings.create")}
                </button>
                {grantScope === "asset" && assets.length === 0 && (
                  <p className="settings-help">{t("settings.noAssets")}</p>
                )}
                {grantScope === "node" && nodes.length === 0 && (
                  <p className="settings-help">{t("settings.createNodeFirst")}</p>
                )}
              </form>
              <div className="settings-card settings-table-card">
                <h3>
                  {t("settings.grantsTab")} <span>{grants.length}</span>
                </h3>
                <div className="settings-table-wrap">
                  <table className="settings-table">
                    <thead>
                      <tr>
                        <th>{t("settings.user")}</th>
                        <th>{t("settings.scope")}</th>
                        <th>{t("settings.actions")}</th>
                        <th>{t("settings.validity")}</th>
                        <th>{t("settings.createdBy")}</th>
                        <th>{t("settings.operation")}</th>
                      </tr>
                    </thead>
                    <tbody>
                      {grants.map((grant) => (
                        <tr key={grant.id}>
                          <td>
                            {grant.group_id
                              ? (groupsByID.get(grant.group_id)?.name ?? grant.group_id)
                              : (usersByID.get(grant.user_id ?? "")?.username ??
                                grant.user_id ??
                                "—")}
                          </td>
                          <td>
                            <strong>
                              {grant.node_id
                                ? (nodesByID.get(grant.node_id)?.name ?? grant.node_id)
                                : (assetsByID.get(grant.asset_id ?? "")?.name ?? grant.asset_id)}
                            </strong>
                            <small>
                              {grant.node_id ? `${t("settings.nodeScope")} · ` : ""}
                              {grant.account}
                            </small>
                          </td>
                          <td>
                            {grant.actions
                              .map((action) => t(`settings.grantActions.${action}`))
                              .join(" · ")}
                          </td>
                          <td>
                            {grant.starts_at
                              ? formatDate(grant.starts_at, i18n.language)
                              : t("settings.immediate")}
                            <small>
                              {grant.ends_at
                                ? `${t("settings.until")} ${formatDate(grant.ends_at, i18n.language)}`
                                : t("settings.noExpiry")}
                            </small>
                          </td>
                          <td>{grant.created_by || "—"}</td>
                          <td>
                            <button
                              type="button"
                              className="button-text danger"
                              disabled={busy}
                              onClick={() => void deleteGrant(grant)}
                            >
                              {t("settings.delete")}
                            </button>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
                {!loading && grants.length === 0 && (
                  <div className="settings-empty">{t("settings.noGrants")}</div>
                )}
              </div>
            </>
          )}

          {tab === "filters" && (
            <>
              <form
                className="settings-card settings-grant-form"
                onSubmit={(event) => void createCommandFilter(event)}
              >
                <h3>{t("settings.createCommandFilter")}</h3>
                <div className="settings-grant-fields">
                  <label>
                    <span>{t("settings.filterName")}</span>
                    <input
                      required
                      maxLength={80}
                      value={filterDraft.name}
                      onChange={(event) =>
                        setFilterDraft((current) => ({ ...current, name: event.target.value }))
                      }
                    />
                  </label>
                  <label>
                    <span>{t("settings.filterTarget")}</span>
                    <select
                      value={filterDraft.target}
                      onChange={(event) =>
                        setFilterDraft((current) => ({
                          ...current,
                          target: event.target.value as CommandFilterDraft["target"],
                        }))
                      }
                    >
                      <option value="all">{t("settings.allUsers")}</option>
                      <option value="user">{t("settings.user")}</option>
                      <option value="group">{t("settings.group")}</option>
                    </select>
                  </label>
                  {filterDraft.target === "user" && (
                    <label>
                      <span>{t("settings.user")}</span>
                      <select
                        required
                        value={filterDraft.userID}
                        onChange={(event) =>
                          setFilterDraft((current) => ({ ...current, userID: event.target.value }))
                        }
                      >
                        <option value="">{t("settings.selectUser")}</option>
                        {users
                          .filter((user) => user.role === "operator")
                          .map((user) => (
                            <option key={user.id} value={user.id}>
                              {user.username}
                            </option>
                          ))}
                      </select>
                    </label>
                  )}
                  {filterDraft.target === "group" && (
                    <label>
                      <span>{t("settings.group")}</span>
                      <select
                        required
                        value={filterDraft.groupID}
                        onChange={(event) =>
                          setFilterDraft((current) => ({ ...current, groupID: event.target.value }))
                        }
                      >
                        <option value="">{t("settings.selectGroup")}</option>
                        {groups.map((group) => (
                          <option key={group.id} value={group.id}>
                            {group.name}
                          </option>
                        ))}
                      </select>
                    </label>
                  )}
                  <label>
                    <span>{t("settings.filterScope")}</span>
                    <select
                      value={filterDraft.scope}
                      onChange={(event) =>
                        setFilterDraft((current) => ({
                          ...current,
                          scope: event.target.value as CommandFilterDraft["scope"],
                        }))
                      }
                    >
                      <option value="all">{t("settings.allAssets")}</option>
                      <option value="asset">{t("settings.asset")}</option>
                      <option value="node">{t("settings.node")}</option>
                    </select>
                  </label>
                  {filterDraft.scope === "asset" && (
                    <label>
                      <span>{t("settings.asset")}</span>
                      <select
                        required
                        value={filterDraft.assetID}
                        onChange={(event) =>
                          setFilterDraft((current) => ({ ...current, assetID: event.target.value }))
                        }
                      >
                        <option value="">{t("settings.selectAsset")}</option>
                        {assets.map((asset) => (
                          <option key={asset.id} value={asset.id}>
                            {asset.name} · {asset.username}
                          </option>
                        ))}
                      </select>
                    </label>
                  )}
                  {filterDraft.scope === "node" && (
                    <label>
                      <span>{t("settings.node")}</span>
                      <select
                        required
                        value={filterDraft.nodeID}
                        onChange={(event) =>
                          setFilterDraft((current) => ({ ...current, nodeID: event.target.value }))
                        }
                      >
                        <option value="">{t("settings.selectNode")}</option>
                        {nodes.map((node) => (
                          <option key={node.id} value={node.id}>
                            {nodeAncestors(nodes, node.id)
                              .map((ancestor) => ancestor.name)
                              .join(" / ")}
                          </option>
                        ))}
                      </select>
                    </label>
                  )}
                  <label>
                    <span>{t("settings.sshAccount")}</span>
                    <input
                      required
                      maxLength={128}
                      value={filterDraft.account}
                      list="command-filter-accounts"
                      onChange={(event) =>
                        setFilterDraft((current) => ({ ...current, account: event.target.value }))
                      }
                    />
                    <datalist id="command-filter-accounts">
                      {[
                        ...new Set(
                          assets
                            .filter(
                              (a) => filterDraft.scope !== "asset" || a.id === filterDraft.assetID,
                            )
                            .flatMap(assetAccounts),
                        ),
                      ].map((account) => (
                        <option key={account} value={account} />
                      ))}
                    </datalist>
                  </label>
                  <label>
                    <span>{t("settings.filterMatch")}</span>
                    <select
                      value={filterDraft.match}
                      onChange={(event) =>
                        setFilterDraft((current) => ({
                          ...current,
                          match: event.target.value as CommandFilter["match"],
                        }))
                      }
                    >
                      <option value="contains">{t("settings.matchContains")}</option>
                      <option value="exact">{t("settings.matchExact")}</option>
                      <option value="regex">{t("settings.matchRegex")}</option>
                    </select>
                  </label>
                  <label>
                    <span>{t("settings.filterPattern")}</span>
                    <input
                      required
                      maxLength={256}
                      value={filterDraft.pattern}
                      onChange={(event) =>
                        setFilterDraft((current) => ({ ...current, pattern: event.target.value }))
                      }
                    />
                  </label>
                  <label>
                    <span>{t("settings.filterAction")}</span>
                    <select
                      value={filterDraft.action}
                      onChange={(event) =>
                        setFilterDraft((current) => ({
                          ...current,
                          action: event.target.value as CommandFilter["action"],
                        }))
                      }
                    >
                      <option value="deny">{t("settings.filterDeny")}</option>
                      <option value="allow">{t("settings.filterAllow")}</option>
                      <option value="review">{t("settings.filterReview")}</option>
                    </select>
                  </label>
                  <label>
                    <span>{t("settings.filterPriority")}</span>
                    <input
                      required
                      type="number"
                      min={0}
                      max={9999}
                      value={filterDraft.priority}
                      onChange={(event) =>
                        setFilterDraft((current) => ({ ...current, priority: event.target.value }))
                      }
                    />
                  </label>
                  <label>
                    <span>{t("settings.startsAt")}</span>
                    <input
                      type="datetime-local"
                      value={filterDraft.startsAt}
                      onChange={(event) =>
                        setFilterDraft((current) => ({ ...current, startsAt: event.target.value }))
                      }
                    />
                  </label>
                  <label>
                    <span>{t("settings.endsAt")}</span>
                    <input
                      type="datetime-local"
                      value={filterDraft.endsAt}
                      onChange={(event) =>
                        setFilterDraft((current) => ({ ...current, endsAt: event.target.value }))
                      }
                    />
                  </label>
                </div>
                <p className="settings-help">{t("settings.filterPriorityHint")}</p>
                <button
                  type="submit"
                  className="button-primary"
                  disabled={
                    busy ||
                    (filterDraft.target === "user" &&
                      users.every((user) => user.role !== "operator")) ||
                    (filterDraft.target === "group" && groups.length === 0) ||
                    (filterDraft.scope === "asset" && assets.length === 0) ||
                    (filterDraft.scope === "node" && nodes.length === 0)
                  }
                >
                  {busy ? "…" : t("settings.create")}
                </button>
              </form>
              <div className="settings-card settings-table-card">
                <h3>
                  {t("settings.commandFiltersTab")} <span>{commandFilters.length}</span>
                </h3>
                <div className="settings-table-wrap">
                  <table className="settings-table">
                    <thead>
                      <tr>
                        <th>{t("settings.filterPriority")}</th>
                        <th>{t("settings.filterName")}</th>
                        <th>{t("settings.filterScope")}</th>
                        <th>{t("settings.filterRule")}</th>
                        <th>{t("settings.validity")}</th>
                        <th>{t("settings.operation")}</th>
                      </tr>
                    </thead>
                    <tbody>
                      {commandFilters.map((filter) => {
                        const target = filter.group_id
                          ? (groupsByID.get(filter.group_id)?.name ?? filter.group_id)
                          : filter.user_id
                            ? (usersByID.get(filter.user_id)?.username ?? filter.user_id)
                            : t("settings.allUsers");
                        const scope = filter.node_id
                          ? (nodesByID.get(filter.node_id)?.name ?? filter.node_id)
                          : filter.asset_id
                            ? (assetsByID.get(filter.asset_id)?.name ?? filter.asset_id)
                            : t("settings.allAssets");
                        return (
                          <tr key={filter.id}>
                            <td>{filter.priority}</td>
                            <td>
                              <strong>{filter.name}</strong>
                              <small>
                                {target} · {filter.account}
                              </small>
                            </td>
                            <td>{scope}</td>
                            <td>
                              <strong>{t(`settings.filterActions.${filter.action}`)}</strong>
                              <small>
                                {t(`settings.filterMatches.${filter.match}`)} · {filter.pattern}
                              </small>
                            </td>
                            <td>
                              {filter.starts_at
                                ? formatDate(filter.starts_at, i18n.language)
                                : t("settings.immediate")}
                              <small>
                                {filter.ends_at
                                  ? `${t("settings.until")} ${formatDate(filter.ends_at, i18n.language)}`
                                  : t("settings.noExpiry")}
                              </small>
                            </td>
                            <td>
                              <button
                                type="button"
                                className="button-text danger"
                                disabled={busy}
                                onClick={() => void deleteCommandFilter(filter)}
                              >
                                {t("settings.delete")}
                              </button>
                            </td>
                          </tr>
                        );
                      })}
                    </tbody>
                  </table>
                </div>
                {!loading && commandFilters.length === 0 && (
                  <div className="settings-empty">{t("settings.noCommandFilters")}</div>
                )}
              </div>
            </>
          )}

          {tab === "reviews" && (
            <section className="settings-review-list" aria-label={t("settings.commandReviewsTab")}>
              <header className="settings-card settings-review-heading">
                <div>
                  <h3>
                    {t("settings.commandReviewsTab")} <span>{pendingReviews.length}</span>
                  </h3>
                  <p>{t("settings.commandReviewHint")}</p>
                </div>
                <button
                  type="button"
                  className="button-secondary"
                  disabled={busy}
                  onClick={() => void refreshCommandReviews()}
                >
                  {t("settings.refresh")}
                </button>
              </header>
              {reviewNotice === "stale" && (
                <p className="settings-notice" role="status">
                  {t("settings.commandReviewStale")}
                </p>
              )}
              {reviewLoadFailed && (
                <p className="asset-error" role="alert">
                  {t("settings.commandReviewLoadError")}
                </p>
              )}
              {loading && pendingReviews.length === 0 && (
                <div className="settings-card settings-empty">
                  {t("settings.commandReviewLoading")}
                </div>
              )}
              {!loading && pendingReviews.length === 0 && !reviewLoadFailed && (
                <div className="settings-card settings-empty">{t("settings.noCommandReviews")}</div>
              )}
              {pendingReviews.map((review) => (
                <article className="settings-card settings-review-card" key={review.id}>
                  <div className="settings-review-main">
                    <header>
                      <strong>{review.asset_name}</strong>
                      <span>
                        {t("settings.reviewExpires", {
                          time: formatDate(review.expires_at, i18n.language),
                        })}
                      </span>
                    </header>
                    <pre>{review.command}</pre>
                    {review.actor && <p>{t("sharing.actor", { name: review.actor })}</p>}
                    <p>
                      {t("settings.reviewContext", {
                        operator: review.operator,
                        account: review.account,
                        rule: review.rule_name,
                      })}
                    </p>
                    <small>
                      {t("settings.reviewRequested", {
                        time: formatDate(review.requested_at, i18n.language),
                      })}
                    </small>
                  </div>
                  <div className="settings-review-actions">
                    <button
                      type="button"
                      className="button-primary"
                      disabled={busy}
                      onClick={() => void resolveCommandReview(review, "approve")}
                    >
                      {t("settings.approveReview")}
                    </button>
                    <button
                      type="button"
                      className="button-secondary"
                      disabled={busy}
                      onClick={() => void resolveCommandReview(review, "deny")}
                    >
                      {t("settings.denyReview")}
                    </button>
                  </div>
                </article>
              ))}
            </section>
          )}

          {tab === "loginReviews" && (
            <section className="settings-review-list" aria-label={t("settings.loginReviewsTab")}>
              <header className="settings-card settings-review-heading">
                <div>
                  <h3>
                    {t("settings.loginReviewsTab")} <span>{pendingLoginReviews.length}</span>
                  </h3>
                  <p>{t("settings.loginReviewHint")}</p>
                </div>
                <button
                  type="button"
                  className="button-secondary"
                  disabled={busy}
                  onClick={() => void refreshLoginReviews()}
                >
                  {t("settings.refresh")}
                </button>
              </header>
              {reviewNotice === "stale" && (
                <p className="settings-notice" role="status">
                  {t("settings.commandReviewStale")}
                </p>
              )}
              {loginReviewLoadFailed && (
                <p className="asset-error" role="alert">
                  {t("settings.loginReviewLoadError")}
                </p>
              )}
              {loading && pendingLoginReviews.length === 0 && (
                <div className="settings-card settings-empty">
                  {t("settings.loginReviewLoading")}
                </div>
              )}
              {!loading && pendingLoginReviews.length === 0 && !loginReviewLoadFailed && (
                <div className="settings-card settings-empty">{t("settings.noLoginReviews")}</div>
              )}
              {pendingLoginReviews.map((review) => (
                <article className="settings-card settings-review-card" key={review.id}>
                  <div className="settings-review-main">
                    <header>
                      <strong>{review.asset_name}</strong>
                      <span>
                        {t("settings.reviewExpires", {
                          time: formatDate(review.expires_at, i18n.language),
                        })}
                      </span>
                    </header>
                    <p>
                      {t("settings.loginReviewContext", {
                        operator: review.operator,
                        account: review.account,
                        action: t(
                          review.action === "telnet"
                            ? "telnet.reviewAction"
                            : review.action === "kubernetes"
                              ? "kubernetes.reviewAction"
                              : review.action === "database"
                                ? "database.reviewAction"
                                : review.action === "sftp"
                                  ? "settings.sftpReviewAction"
                                  : review.action === "account_discovery"
                                    ? "accountSchedule.approval"
                                    : review.action === "remote_account"
                                      ? "remoteAccounts.approval"
                                      : "settings.sshReviewAction",
                        ),
                      })}
                    </p>
                    <small>
                      {t("settings.reviewRequested", {
                        time: formatDate(review.requested_at, i18n.language),
                      })}
                    </small>
                  </div>
                  <div className="settings-review-actions">
                    <button
                      type="button"
                      className="button-primary"
                      disabled={busy}
                      onClick={() => void resolveLoginReview(review, "approve")}
                    >
                      {t("settings.approveReview")}
                    </button>
                    <button
                      type="button"
                      className="button-secondary"
                      disabled={busy}
                      onClick={() => void resolveLoginReview(review, "deny")}
                    >
                      {t("settings.denyReview")}
                    </button>
                  </div>
                </article>
              ))}
            </section>
          )}
        </>
      )}
    </section>
  );
}
