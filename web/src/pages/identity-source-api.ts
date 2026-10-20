import { useCallback, useRef } from "react";
import { useAuth } from "../auth/AuthContext";

export function useIdentitySourceAPI() {
  const { accessToken } = useAuth();
  const receipts = useRef(new Map<string, { body: string; id: string }>());
  const request = useCallback(
    async <T>(path: string, init?: RequestInit): Promise<T> => {
      const headers = new Headers(init?.headers);
      if (accessToken) headers.set("Authorization", `Bearer ${accessToken}`);
      if (init?.body) headers.set("Content-Type", "application/json");
      const r = await fetch(path, { ...init, headers });
      const result = (await r.json()) as T & { error_code?: string };
      if (!r.ok) throw new Error(result.error_code ?? "identity_sources_unavailable");
      return result;
    },
    [accessToken],
  );
  const operation = useCallback((key: string, body: object) => {
    const raw = JSON.stringify(body);
    let value = receipts.current.get(key);
    if (!value || value.body !== raw) {
      value = {
        body: raw,
        id:
          "request-" +
          Array.from(crypto.getRandomValues(new Uint8Array(16)), (n) =>
            n.toString(16).padStart(2, "0"),
          ).join(""),
      };
      receipts.current.set(key, value);
    }
    return { ...body, request_id: value.id };
  }, []);
  const completed = useCallback((key: string) => {
    receipts.current.delete(key);
  }, []);
  return { request, operation, completed };
}
