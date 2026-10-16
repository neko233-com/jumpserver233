import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useRef,
  useState,
  type ReactNode,
} from "react";

type AuthContextValue = {
  accessToken: string;
  setAccessToken: (token: string) => void;
  setCookieSession: () => void;
  authenticated: boolean;
  sessionReady: boolean;
};

const AuthContext = createContext<AuthContextValue | null>(null);

export function AuthProvider({ children }: { children: ReactNode }) {
  const [accessToken, setToken] = useState("");
  const [authenticated, setAuthenticated] = useState(false);
  const [sessionReady, setSessionReady] = useState(false);
  const sessionProbe = useRef<AbortController | null>(null);
  const setAccessToken = useCallback((token: string) => {
    sessionProbe.current?.abort();
    setToken(token);
    setAuthenticated(Boolean(token));
    setSessionReady(true);
  }, []);
  const setCookieSession = useCallback(() => {
    sessionProbe.current?.abort();
    setToken("");
    setAuthenticated(true);
    setSessionReady(true);
  }, []);

  useEffect(() => {
    let active = true;
    const controller = new AbortController();
    sessionProbe.current = controller;
    fetch("/api/v1/authentication/session/", {
      credentials: "same-origin",
      signal: controller.signal,
    })
      .then((response) => {
        if (!active || controller.signal.aborted) return;
        setAuthenticated(response.ok);
      })
      .catch(() => {
        if (active && !controller.signal.aborted) setAuthenticated(false);
      })
      .finally(() => {
        if (active && !controller.signal.aborted) setSessionReady(true);
      });
    return () => {
      active = false;
      controller.abort();
    };
  }, []);

  const value = useMemo(
    () => ({ accessToken, setAccessToken, setCookieSession, authenticated, sessionReady }),
    [accessToken, setAccessToken, setCookieSession, authenticated, sessionReady],
  );
  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth() {
  const value = useContext(AuthContext);
  if (!value) throw new Error("useAuth must be used within AuthProvider");
  return value;
}
