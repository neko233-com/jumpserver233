import { useCallback, useEffect, useState } from "react";
import { useAuth } from "./AuthContext";

export function usePermissions() {
  const { accessToken } = useAuth();
  const [permissions, setPermissions] = useState<string[]>([]);
  const [systemPermissions, setSystemPermissions] = useState<string[]>([]);
  const [ready, setReady] = useState(false);
  const [userID, setUserID] = useState("");
  const refresh = useCallback(
    async (signal?: AbortSignal) => {
      try {
        const response = await fetch("/api/v1/rbac/me", {
          signal,
          headers: accessToken ? { Authorization: `Bearer ${accessToken}` } : {},
        });
        if (!response.ok) throw new Error("permissions unavailable");
        const data = (await response.json()) as {
          permissions: string[];
          user_id: string;
          system_permissions?: string[];
        };
        if (!signal?.aborted) {
          setPermissions(data.permissions);
          setSystemPermissions(data.system_permissions || data.permissions);
          setUserID(data.user_id);
        }
      } catch {
        if (!signal?.aborted) {
          setPermissions([]);
          setSystemPermissions([]);
          setUserID("");
        }
      } finally {
        if (!signal?.aborted) setReady(true);
      }
    },
    [accessToken],
  );
  useEffect(() => {
    const controller = new AbortController();
    const reload = () => {
      void refresh(controller.signal);
    };
    queueMicrotask(reload);
    const timer = window.setInterval(reload, 15_000);
    window.addEventListener("focus", reload);
    return () => {
      controller.abort();
      window.clearInterval(timer);
      window.removeEventListener("focus", reload);
    };
  }, [refresh]);
  return {
    permissions,
    userID,
    ready,
    refresh,
    allows: (permission: string) =>
      permissions.includes(permission) || systemPermissions.includes(permission),
    systemAllows: (permission: string) => systemPermissions.includes(permission),
  };
}
