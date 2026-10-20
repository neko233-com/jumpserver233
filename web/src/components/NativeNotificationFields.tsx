import { useTranslation } from "react-i18next";

export type NativeSMSConfig = {
  access_key_id: string;
  region: string;
  app_id: string;
  endpoint: string;
  sender: string;
  service_id: string;
  sign_name: string;
  verification: { id: string; parameters: string[] | null };
  notification: { id: string; parameters: string[] | null };
};
export type NativeChannel = {
  enabled: boolean;
  provider?: string;
  native_sms: NativeSMSConfig;
  url: string;
  ca: string;
  bearer_configured: boolean;
  secret_configured: boolean;
};
const smsKinds = ["custom", "aliyun", "tencent", "huawei", "cmpp"];
const chatKinds = ["custom", "wecom", "dingtalk", "feishu", "lark"];
export function nativeChannel(value: NativeChannel) {
  return Boolean(value.provider && value.provider !== "custom");
}
export default function NativeNotificationFields({
  channel,
  value,
  change,
  providerChange,
}: {
  channel: "webhook" | "sms";
  value: NativeChannel;
  change: (value: NativeChannel) => void;
  providerChange: () => void;
}) {
  const { t } = useTranslation();
  const provider = value.provider || "custom";
  const cfg = value.native_sms;
  const fields: Array<keyof Omit<NativeSMSConfig, "verification" | "notification">> =
    provider === "cmpp"
      ? ["access_key_id", "endpoint", "sender", "service_id", "sign_name"]
      : provider === "huawei"
        ? ["access_key_id", "endpoint", "sender", "sign_name"]
        : provider === "tencent"
          ? ["access_key_id", "region", "app_id", "sign_name"]
          : ["access_key_id", "sign_name"];
  return (
    <>
      <label>
        {t("notifications.native.provider")}
        <select
          value={provider}
          onChange={(e) => {
            const selected = e.target.value;
            providerChange();
            change({
              ...value,
              provider: selected,
              url: "",
              native_sms:
                channel === "sms"
                  ? {
                      ...cfg,
                      verification: { id: cfg.verification.id, parameters: ["code"] },
                      notification: {
                        id: cfg.notification.id,
                        parameters: cfg.notification.parameters ?? ["title", "state"],
                      },
                    }
                  : cfg,
              bearer_configured: false,
              secret_configured: false,
            });
          }}
        >
          {(channel === "sms" ? smsKinds : chatKinds).map((kind) => (
            <option value={kind} key={kind}>
              {t("notifications.native.providers." + kind)}
            </option>
          ))}
        </select>
      </label>
      {provider !== "custom" && (
        <p>
          {t(channel === "sms" ? "notifications.native.smsHint" : "notifications.native.chatHint")}
        </p>
      )}
      {channel === "sms" && provider !== "custom" && (
        <>
          <div className="rotation-fields">
            {fields.map((key) => (
              <label key={key}>
                {t("notifications.native.fields." + key)}
                <input
                  required={key !== "service_id"}
                  value={cfg[key]}
                  maxLength={key === "endpoint" ? 2048 : 128}
                  onChange={(e) =>
                    change({ ...value, native_sms: { ...cfg, [key]: e.target.value } })
                  }
                />
              </label>
            ))}
          </div>
          {(["verification", "notification"] as const).map((kind) => (
            <fieldset key={kind}>
              <legend>{t("notifications.native." + kind)}</legend>
              <label>
                {t(
                  provider === "cmpp"
                    ? "notifications.native.templateText"
                    : "notifications.native.templateID",
                )}
                <input
                  required
                  value={cfg[kind].id}
                  maxLength={512}
                  onChange={(e) =>
                    change({
                      ...value,
                      native_sms: { ...cfg, [kind]: { ...cfg[kind], id: e.target.value } },
                    })
                  }
                />
              </label>
              <label>
                {t("notifications.native.parameters")}
                <input
                  value={(cfg[kind].parameters ?? []).join(" ")}
                  maxLength={128}
                  readOnly={kind === "verification"}
                  onChange={(e) =>
                    change({
                      ...value,
                      native_sms: {
                        ...cfg,
                        [kind]: {
                          ...cfg[kind],
                          parameters: e.target.value.trim().split(/\s+/).filter(Boolean),
                        },
                      },
                    })
                  }
                />
              </label>
            </fieldset>
          ))}
          {provider === "cmpp" && <p>{t("notifications.native.cmppHint")}</p>}
        </>
      )}
    </>
  );
}
