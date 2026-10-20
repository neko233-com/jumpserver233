export default {
  sshCertificates: {
    title: "SSH certificates",
    description:
      "Use short-lived user certificates for Web SSH, CLI, SFTP, monitoring and gateways. Ephemeral private keys remain in server memory; failed issuance denies the connection.",
    trustHint:
      "Before enabling an account policy, install the issuer trust bundle as TrustedUserCAKeys on its target SSH server and validate/reload sshd. Host-key fingerprint checks remain required.",
    new: "New issuer",
    edit: "Edit issuer",
    delete: "Delete issuer",
    provider: "Signing provider",
    builtin: "Built-in Ed25519 CA",
    openbao: "OpenBao SSH signer",
    fields: {
      name: "Name",
      endpoint: "OpenBao HTTPS origin",
      mount: "SSH mount",
      role: "Signing role",
      namespace: "Namespace (optional)",
      root_ca_pem: "TLS root CA PEM (optional)",
      public_key: "Pinned signing CA public key",
      token: "Write-only OpenBao token",
    },
    ttl: "Certificate lifetime (60–600 seconds)",
    enabled: "Enabled",
    disabled: "Disabled",
    tokenHint:
      "An empty token on edit retains the saved token. No signing private key or saved token is returned.",
    save: "Save issuer",
    cancel: "Cancel",
    saved: "Issuer saved.",
    bound: "Account policy saved.",
    refresh: "Refresh",
    reload: "Reload current revisions",
    denied: "SSH issuer-view permission is required.",
    revision: "Revision {{revision}}",
    trustBundle: "Target trust bundle",
    rotationHint:
      "Prepare a new CA, distribute the full trust bundle to target servers, then activate it. The previous public key remains in this bundle for 11 minutes after activation.",
    rotate: "Prepare CA rotation",
    activate: "Activate prepared CA",
    confirm: {
      rotate: "Generate a new pending CA? Current signing continues until activation.",
      activate:
        "Activate the prepared CA after distributing the trust bundle to every affected SSH server?",
      delete: "Delete this issuer? Referenced issuers cannot be deleted.",
    },
    binding: "Account authentication",
    account: "SSH account",
    chooseAccount: "Choose a visible account",
    issuer: "Issuer policy",
    bootstrap: "Use stored password/private key",
    bindingHint:
      "A selected issuer replaces authentication for this exact account and endpoint. A changed endpoint requires explicit rebinding. Clear the policy explicitly to use stored credentials again. Password/key rotation of a certificate-bound account is blocked.",
    bind: "Save account policy",
    audit: "Certificate audit",
    service: "Server authentication",
    previous: "Previous",
    next: "Next",
    total: "{{count}} events",
    actions: {
      save: "Save issuer",
      rotate: "Prepare CA",
      activate: "Activate CA",
      delete: "Delete issuer",
      bind: "Bind account",
      issue: "Issue user certificate",
    },
    errors: {
      ssh_certificates_invalid: "Check fields, provider, CA public key, lifetime and request ID.",
      ssh_certificates_not_found: "Issuer/account is missing or outside your access.",
      ssh_certificates_conflict:
        "The revision, endpoint, operation or request changed. Reload before editing again.",
      ssh_certificates_in_use:
        "Clear every account policy referencing this issuer before deleting it.",
      ssh_certificates_capacity: "Certificate storage or retained CA capacity is full.",
      ssh_certificates_unavailable:
        "The certificate service is unavailable. Retry unchanged requests safely.",
      permission_denied: "This action requires the corresponding certificate permission.",
    },
  },
};
