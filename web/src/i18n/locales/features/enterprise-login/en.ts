export default {
  enterpriseLogin: {
    title: "{{provider}} sign-in",
    hint: "Use the provider's official QR/authorization page. The server checks the configured organization and an active internal member before platform MFA and login review.",
    sources: "Identity sources",
    providers: { wecom: "WeCom", dingtalk: "DingTalk", feishu: "Feishu / Lark" },
    application: "Internal application",
    advanced: "Advanced",
    enabled: "Enable provider sign-in",
    provision: "Provision new operators on first sign-in",
    save: "Save provider settings",
    reload: "Reload",
    check: "Check application credentials",
    saved: "Provider settings saved. Start a fresh sign-in after changing them.",
    checkOK:
      "Application credentials are available. This does not establish actual QR sign-in or member permissions.",
    secretSaved: "A secret is saved. Leave the field blank to keep it.",
    secretMissing: "No application secret is saved.",
    clearSecret: "Clear the saved secret",
    callbackHint:
      "Register this exact callback URL and trusted domain in the provider's application. Production callbacks require the installation's public HTTPS origin.",
    loopback: "Allow literal loopback HTTP callbacks for local development",
    permissions:
      "Use an internal application with member identity and directory-status read permissions. External contacts, departed, frozen, inactive or mismatched-tenant users are rejected. New identities remain operators without asset grants.",
    prepare: "Prepare external operator",
    prepared: "External account ready: {{username}}",
    subjectHint:
      "Use the provider's stable user ID: WeCom userid, DingTalk unionId, or Feishu/Lark open_id. Display names, email and mobile numbers do not link identities.",
    denied: "Choose a valid enterprise identity source and use system security permission.",
    audit: "Provider settings audit",
    at: "Time",
    actor: "Actor",
    revision: "Revision",
    regions: { cn: "Feishu China", global: "Lark international" },
    versions: { v3: "OAuth v3", v2: "OAuth v2 compatibility" },
    fields: {
      client_id: "Corp ID / App Key / App ID",
      tenant_id: "Corp ID / tenant_key",
      agent_id: "WeCom Agent ID",
      client_secret: "Application secret (write only)",
      callback_url: "Callback URL",
      region: "Provider region",
      oauth_version: "OAuth endpoint version",
      scopes: "Additional Feishu/Lark scopes (space separated)",
      ca_pem: "Additional CA certificates (PEM, optional)",
      subject: "Stable provider subject",
      alias: "External username (optional)",
    },
    finishTitle: "Complete enterprise sign-in",
    finishHint:
      "The enterprise identity is verified. Complete required platform MFA and login review before a session is issued.",
    finish: "Complete sign-in",
    loginError: "Enterprise sign-in failed or expired. Start a fresh sign-in.",
    passwordManaged:
      "This account uses enterprise identity sign-in. Its primary credential is managed by the provider.",
    reauthRequired:
      "Sign in again with this enterprise source before changing MFA or recovery credentials.",
    reauthHint:
      "A recent enterprise sign-in is required; the provider's application secret and target SSH password are never requested here.",
    mfaStartHint: "Use a recent enterprise session to enroll a platform authenticator.",
    errors: {
      enterprise_login_invalid:
        "Check the application, tenant, callback, scopes, secret and request ID.",
      enterprise_login_conflict: "Settings or the request changed. Reload before editing.",
      enterprise_login_rejected:
        "The identity, tenant, member status or second factor was rejected.",
      enterprise_login_capacity:
        "Sign-in capacity or attempt budget is full. Retry after the indicated delay.",
      enterprise_login_unavailable:
        "The enterprise provider is unavailable. Check application permissions and network access without logging provider responses.",
    },
  },
};
