import { useEffect, useState } from "react";
import { useTranslation } from "react-i18next";
import "../i18n/locales/features/password-security/register";
export type PasswordPolicy = {
  revision: number;
  min_length: number;
  admin_min_length: number;
  require_upper: boolean;
  require_lower: boolean;
  require_digit: boolean;
  require_special: boolean;
  history_count: number;
  max_age_days: number;
  admin_max_age_days: number;
};
export default function PasswordRules({
  policy,
  admin = false,
}: {
  policy?: PasswordPolicy;
  admin?: boolean;
}) {
  const { t } = useTranslation();
  const [loaded, setLoaded] = useState<PasswordPolicy | undefined>(policy);
  useEffect(() => {
    if (policy) return;
    const c = new AbortController();
    void fetch("/api/v1/authentication/password-policy", { signal: c.signal })
      .then(async (r) => {
        if (r.ok) {
          const value = (await r.json()) as PasswordPolicy;
          if (!c.signal.aborted) setLoaded(value);
        }
      })
      .catch(() => {});
    return () => c.abort();
  }, [policy]);
  const p = policy || loaded;
  return p ? (
    <p className="settings-help">
      {t("passwordSecurity.rules", {
        min: admin ? p.admin_min_length : p.min_length,
        history: p.history_count,
      })}{" "}
      {["upper", "lower", "digit", "special"]
        .filter((v) => p[("require_" + v) as keyof PasswordPolicy])
        .map((v) => t("passwordSecurity." + v))
        .join(", ")}
    </p>
  ) : null;
}
