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
import { useTranslation } from "react-i18next";
import "./branding.css";

export type Colors = {
  bg: string;
  panel: string;
  text: string;
  muted: string;
  border: string;
  accent: string;
  accent_text: string;
};
export type Branding = {
  revision: number;
  name_en: string;
  name_zh: string;
  theme: string;
  accent: string;
  logo_digest: string;
  icon_digest: string;
  mark_digest: string;
  login_digest: string;
  login_title_en: string;
  login_title_zh: string;
  footer_en: string;
  footer_zh: string;
  registration_label: string;
  registration_url: string;
  colors: Colors;
};
export const defaults: Branding = {
  revision: 1,
  name_en: "JumpServer233",
  name_zh: "JumpServer233",
  theme: "graphite",
  accent: "#2f81f7",
  logo_digest: "",
  icon_digest: "",
  mark_digest: "",
  login_digest: "",
  login_title_en: "",
  login_title_zh: "",
  footer_en: "",
  footer_zh: "",
  registration_label: "",
  registration_url: "",
  colors: {
    bg: "#0d1117",
    panel: "#161b22",
    text: "#e6edf3",
    muted: "#8b949e",
    border: "#30363d",
    accent: "#2f81f7",
    accent_text: "#000000",
  },
};
type Value = {
  settings: Branding;
  name: string;
  reload: () => Promise<void>;
  notify: () => Promise<void>;
};
const BrandingContext = createContext<Value | null>(null);
const keys = ["bg", "panel", "text", "muted", "border", "accent", "accent_text"] as const;
const imageURL = (hash: string) => (hash ? `/api/v1/branding/images/${hash}` : "");
export function validBranding(value: Branding): boolean {
  return (
    Number.isSafeInteger(value?.revision) &&
    value.revision > 0 &&
    typeof value.name_en === "string" &&
    typeof value.name_zh === "string" &&
    value.name_en.length > 0 &&
    value.name_zh.length > 0 &&
    value.name_en.length <= 256 &&
    value.name_zh.length <= 256 &&
    ["graphite", "midnight", "forest", "plum", "crimson"].includes(value.theme) &&
    [value.logo_digest, value.icon_digest, value.mark_digest, value.login_digest].every(
      (hash) => hash === "" || /^[a-f0-9]{64}$/.test(hash),
    ) &&
    keys.every((key) => /^#[a-f0-9]{6}$/.test(value.colors?.[key]))
  );
}
export function BrandingProvider({ children }: { children: ReactNode }) {
  const { i18n } = useTranslation();
  const [settings, setSettings] = useState(defaults);
  const etag = useRef("");
  const channel = useRef<BroadcastChannel | null>(null);
  const pending = useRef<Promise<void> | null>(null);
  const reload = useCallback(() => {
    if (pending.current) return pending.current;
    const request = fetch("/api/v1/branding", {
      cache: "no-cache",
      headers: etag.current ? { "If-None-Match": etag.current } : {},
      signal: AbortSignal.timeout(10000),
    })
      .then(async (response) => {
        if (response.status === 304) return;
        if (!response.ok) throw Error("Branding unavailable");
        const next = (await response.json()) as Branding;
        if (!validBranding(next)) throw Error("Invalid branding");
        etag.current = response.headers.get("ETag") || "";
        setSettings((previous) =>
          JSON.stringify(previous) === JSON.stringify(next) ? previous : next,
        );
      })
      .catch(() => undefined)
      .finally(() => {
        pending.current = null;
      });
    pending.current = request;
    return request;
  }, []);
  const invalidate = useCallback(async () => {
    await pending.current;
    etag.current = "";
    await reload();
  }, [reload]);
  const notify = useCallback(async () => {
    await invalidate();
    channel.current?.postMessage("refresh");
  }, [invalidate]);
  useEffect(() => {
    const refresh = () => {
      if (document.visibilityState === "visible") void reload();
    };
    if (typeof BroadcastChannel !== "undefined") {
      channel.current = new BroadcastChannel("jms233-branding");
      channel.current.onmessage = () => {
        void invalidate();
      };
    }
    void reload();
    const timer = window.setInterval(refresh, 60000);
    document.addEventListener("visibilitychange", refresh);
    window.addEventListener("focus", refresh);
    return () => {
      window.clearInterval(timer);
      document.removeEventListener("visibilitychange", refresh);
      window.removeEventListener("focus", refresh);
      channel.current?.close();
      channel.current = null;
    };
  }, [reload, invalidate]);
  const name = i18n.language.startsWith("zh") ? settings.name_zh : settings.name_en;
  useEffect(() => {
    const root = document.documentElement;
    for (const key of keys)
      root.style.setProperty(`--${key.replaceAll("_", "-")}`, settings.colors[key]);
    root.style.setProperty("--surface", settings.colors.panel);
    root.dataset.brandCustom = String(
      settings.theme !== "graphite" || settings.accent !== defaults.accent,
    );
    root.dataset.brandTheme = settings.theme;
  }, [settings]);
  useEffect(() => {
    document.title = name;
  }, [name]);
  useEffect(() => {
    const existing = document.querySelector<HTMLLinkElement>("link[data-branding-icon]");
    if (!settings.icon_digest) {
      existing?.remove();
      return;
    }
    const link = existing || document.createElement("link");
    link.rel = "icon";
    link.type = "image/png";
    link.dataset.brandingIcon = "true";
    link.href = imageURL(settings.icon_digest);
    if (!existing) document.head.appendChild(link);
  }, [settings.icon_digest]);
  const value = useMemo(
    () => ({ settings, name, reload, notify }),
    [settings, name, reload, notify],
  );
  return <BrandingContext.Provider value={value}>{children}</BrandingContext.Provider>;
}
export function useBranding() {
  const context = useContext(BrandingContext);
  if (!context) throw Error("BrandingProvider missing");
  return context;
}
export function BrandMark({
  children,
  compact = false,
}: {
  children?: ReactNode;
  compact?: boolean;
}) {
  const { settings, name } = useBranding();
  const [failed, setFailed] = useState("");
  const digest = compact ? settings.mark_digest : settings.logo_digest;
  return digest && failed !== digest ? (
    <img
      className={compact ? "brand-logo brand-mark" : "brand-logo"}
      src={imageURL(digest)}
      alt={compact ? "" : name}
      aria-hidden={compact || undefined}
      onError={() => setFailed(digest)}
    />
  ) : (
    <>{compact ? null : children || name}</>
  );
}
export function BrandFooter() {
  const { settings } = useBranding();
  const { i18n } = useTranslation();
  const text = i18n.language.startsWith("zh") ? settings.footer_zh : settings.footer_en;
  if (!text && !settings.registration_label) return null;
  return (
    <footer className="brand-footer">
      {text && <span>{text}</span>}
      {settings.registration_label &&
        (settings.registration_url ? (
          <a href={settings.registration_url} target="_blank" rel="noopener noreferrer">
            {settings.registration_label}
          </a>
        ) : (
          <span>{settings.registration_label}</span>
        ))}
    </footer>
  );
}
