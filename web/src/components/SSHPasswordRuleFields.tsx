import { useId } from "react";
import { useTranslation } from "react-i18next";
import "../i18n/locales/features/ssh-password-policy/register";

export type SSHPasswordRules = {
  min_length: number;
  max_length: number;
  min_upper: number;
  min_lower: number;
  min_digits: number;
  min_symbols: number;
  exclude: string;
};
export const inheritedPasswordRules: SSHPasswordRules = {
  min_length: 16,
  max_length: 128,
  min_upper: 0,
  min_lower: 0,
  min_digits: 0,
  min_symbols: 0,
  exclude: "",
};
const fields = [
  "min_length",
  "max_length",
  "min_upper",
  "min_lower",
  "min_digits",
  "min_symbols",
] as const;

export default function SSHPasswordRuleFields({
  rules,
  disabled = false,
  onChange,
}: {
  rules: SSHPasswordRules;
  disabled?: boolean;
  onChange: (value: SSHPasswordRules) => void;
}) {
  const { t } = useTranslation(),
    id = useId();
  return (
    <>
      <div className="ssh-password-policy-grid">
        {fields.map((field) => (
          <label key={field} htmlFor={id + field}>
            {t(`sshPasswordPolicy.${field}`)}
            <input
              id={id + field}
              type="number"
              min={field === "min_length" || field === "max_length" ? 16 : 0}
              max="128"
              required
              disabled={disabled}
              value={rules[field]}
              onChange={(e) => onChange({ ...rules, [field]: Number(e.target.value) })}
            />
          </label>
        ))}
      </div>
      <label htmlFor={id + "exclude"}>
        {t("sshPasswordPolicy.exclude")}
        <input
          id={id + "exclude"}
          value={rules.exclude}
          maxLength={62}
          disabled={disabled}
          autoComplete="off"
          onChange={(e) => onChange({ ...rules, exclude: e.target.value })}
        />
      </label>
      <p className="settings-help">{t("sshPasswordPolicy.allowed")}</p>
    </>
  );
}
