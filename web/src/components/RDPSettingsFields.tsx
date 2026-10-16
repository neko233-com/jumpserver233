import { useTranslation } from "react-i18next";
export type RDPSettings = {
  security: string;
  domain: string;
  server_name: string;
  root_ca_pem: string;
  width: number;
  height: number;
  read_only: boolean;
  clipboard: boolean;
};
export const defaultRDP: RDPSettings = {
  security: "nla",
  domain: "",
  server_name: "",
  root_ca_pem: "",
  width: 1280,
  height: 720,
  read_only: false,
  clipboard: false,
};
export default function RDPSettingsFields({
  value,
  onChange,
}: {
  value: RDPSettings;
  onChange: (value: RDPSettings) => void;
}) {
  const { t } = useTranslation();
  return (
    <>
      <label className="asset-field">
        <span>{t("rdp.security")}</span>
        <select
          value={value.security}
          onChange={(e) => onChange({ ...value, security: e.target.value })}
        >
          <option value="nla">{t("rdp.nla")}</option>
          <option value="tls">{t("rdp.tls")}</option>
        </select>
        <small>{t("rdp.tlsHint")}</small>
      </label>
      {(["domain", "server_name", "root_ca_pem"] as const).map((field) => (
        <label className="asset-field" key={field}>
          <span>{t(`rdp.${field}`)}</span>
          {field === "root_ca_pem" ? (
            <textarea
              maxLength={65536}
              value={value[field]}
              onChange={(e) => onChange({ ...value, [field]: e.target.value })}
            />
          ) : (
            <input
              maxLength={field === "domain" ? 128 : 253}
              value={value[field]}
              onChange={(e) => onChange({ ...value, [field]: e.target.value })}
            />
          )}
        </label>
      ))}
      {(["width", "height"] as const).map((field) => (
        <label className="asset-field" key={field}>
          <span>{t(`rdp.${field}`)}</span>
          <input
            type="number"
            min={field === "width" ? 320 : 200}
            max={field === "width" ? 3840 : 2160}
            value={value[field]}
            onChange={(e) => onChange({ ...value, [field]: Number(e.target.value) })}
          />
        </label>
      ))}
      {(["read_only", "clipboard"] as const).map((field) => (
        <label className="asset-field" key={field}>
          <span>
            <input
              type="checkbox"
              checked={value[field]}
              onChange={(e) => onChange({ ...value, [field]: e.target.checked })}
            />{" "}
            {t(`rdp.${field}`)}
          </span>
        </label>
      ))}
      <p className="asset-field">{t("rdp.auditHint")}</p>
    </>
  );
}
