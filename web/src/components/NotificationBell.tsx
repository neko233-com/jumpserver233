import { useEffect, useState } from "react";
import { NavLink } from "react-router-dom";
import { useTranslation } from "react-i18next";
import { useAuth } from "../auth/AuthContext";

export default function NotificationBell() {
  const { accessToken } = useAuth(),
    { t, i18n } = useTranslation();
  const [count, setCount] = useState<number | null>(null);
  useEffect(() => {
    const controller = new AbortController();
    let running = false;
    const headers = accessToken ? { Authorization: `Bearer ${accessToken}` } : undefined;
    const reload = async () => {
      if (running || document.visibilityState === "hidden") return;
      running = true;
      try {
        const response = await fetch("/api/v1/notifications/inbox?unread=true&limit=1", {
          headers,
          signal: AbortSignal.any([controller.signal, AbortSignal.timeout(15_000)]),
        });
        if (!response.ok) throw new Error();
        const value = await response.json();
        if (!controller.signal.aborted)
          setCount(Number.isSafeInteger(value.unread) ? value.unread : 0);
      } catch {
        if (!controller.signal.aborted) setCount(null);
      } finally {
        running = false;
      }
    };
    const update = () => {
      void reload();
    };
    void reload();
    const timer = setInterval(update, 30_000);
    window.addEventListener("jms233-notifications", update);
    window.addEventListener("focus", update);
    document.addEventListener("visibilitychange", update);
    return () => {
      controller.abort();
      clearInterval(timer);
      window.removeEventListener("jms233-notifications", update);
      window.removeEventListener("focus", update);
      document.removeEventListener("visibilitychange", update);
    };
  }, [accessToken]);
  useEffect(() => {
    const controller = new AbortController();
    void fetch("/api/v1/notifications/locale", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        ...(accessToken ? { Authorization: `Bearer ${accessToken}` } : {}),
      },
      body: JSON.stringify({ language: i18n.language.startsWith("zh") ? "zh-CN" : "en" }),
      signal: AbortSignal.any([controller.signal, AbortSignal.timeout(15_000)]),
    }).catch(() => undefined);
    return () => controller.abort();
  }, [accessToken, i18n.language]);
  return (
    <NavLink to="/console/notifications" className="profile-link">
      {t("nav.notifications")}
      {count !== null && count > 0 && (
        <span aria-label={t("nav.notificationUnread", { count })}>
          {" "}
          ({count > 99 ? "99+" : count})
        </span>
      )}
    </NavLink>
  );
}
