import { useEffect, useState } from "react";
import { useTranslation } from "react-i18next";
import { useAuth } from "../auth/AuthContext";
import {
  ORGANIZATIONS_CHANGED,
  selectedOrganization,
  switchOrganization,
} from "../auth/organization";
type Choice = {
  id: string;
  name: string;
  builtin: boolean;
  enabled: boolean;
  archived_at?: string;
};
export default function OrganizationSwitcher() {
  const { t } = useTranslation();
  const { accessToken } = useAuth();
  const [choices, setChoices] = useState<Choice[]>([]);
  const [error, setError] = useState(false);
  useEffect(() => {
    const controller = new AbortController();
    let revision = 0;
    async function load() {
      const requestRevision = ++revision;
      try {
        const response = await fetch("/api/v1/organizations", {
          signal: controller.signal,
          headers: accessToken ? { Authorization: `Bearer ${accessToken}` } : {},
        });
        if (!response.ok) throw new Error("organizations unavailable");
        const data = (await response.json()) as { results: Choice[] };
        if (!controller.signal.aborted && requestRevision === revision) {
          setChoices(data.results.filter((o) => o.enabled && !o.archived_at));
          setError(false);
        }
      } catch {
        if (!controller.signal.aborted && requestRevision === revision) setError(true);
      }
    }
    void load();
    const refresh = () => {
      void load();
    };
    window.addEventListener(ORGANIZATIONS_CHANGED, refresh);
    window.addEventListener("focus", refresh);
    const timer = window.setInterval(() => {
      void load();
    }, 15000);
    return () => {
      controller.abort();
      window.clearInterval(timer);
      window.removeEventListener(ORGANIZATIONS_CHANGED, refresh);
      window.removeEventListener("focus", refresh);
    };
  }, [accessToken]);
  const current = selectedOrganization();
  return (
    <label className="organization-switcher">
      <span>{t("organization.current")}</span>
      <select
        value={current}
        aria-label={t("organization.current")}
        onChange={(event) => switchOrganization(event.target.value)}
      >
        {!choices.some((o) => o.id === current) && (
          <option value={current}>
            {t(error ? "organization.unavailable" : "organization.choose")}
          </option>
        )}
        {choices.map((o) => (
          <option key={o.id} value={o.id}>
            {o.builtin ? t("organization.default") : o.name}
          </option>
        ))}
      </select>
    </label>
  );
}
