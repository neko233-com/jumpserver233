export default {
  identitySources: {
    title: "Identity sources",
    hint: "Manage independent LDAP, OIDC, CAS and SAML sources. Existing default providers keep their endpoints.",
    signIn: "Sign in with {{name}}",
    add: "Add source",
    edit: "Edit source",
    name: "Name",
    kind: "Provider",
    enabled: "Enabled",
    disabled: "Disabled",
    archived: "Archived",
    save: "Save",
    cancel: "Cancel",
    refresh: "Reload",
    configure: "Provider settings",
    callback: "Callback URL",
    empty: "No additional identity sources.",
    saved: "Identity source saved.",
    denied: "Select an identity source and use an account with system security access.",
    disableHint:
      "Disabling or archiving a source revokes its existing credentials. Enabling it again requires fresh sign-in. Configure the provider separately before enabling login.",
    kinds: {
      ldap: "LDAP / Active Directory",
      oidc: "OpenID Connect",
      cas: "CAS",
      saml: "SAML 2.0",
    },
    audit: "Source audit",
    at: "Time",
    actor: "Actor",
    revision: "Revision",
    sync: "Directory synchronization",
    syncHint:
      "Preview complete LDAP snapshots and apply owned memberships. Stable directory IDs identify users; names and email addresses never merge accounts.",
    scanSettings: "Collection settings",
    syncSaved: "Synchronization settings saved. Collect a new preview before applying.",
    mappings: "Group and organization mappings",
    addMapping: "Add mapping",
    remove: "Remove mapping",
    none: "None",
    preview: "Collect preview",
    previewCount: "{{users}} users and {{groups}} groups collected.",
    previewHint:
      "The first 50 users are shown. A preview expires after 10 minutes. Only a complete snapshot can be applied; manual memberships remain authoritative.",
    apply: "Apply complete snapshot",
    applied: "Snapshot applied. Manual assignments were preserved.",
    pendingHint:
      "A synchronization transaction is pending. Authentication for this source remains blocked until retry or abort finishes.",
    retry: "Retry original transaction",
    abort: "Abort and suspend source users",
    abortHint:
      "Aborting removes automatic memberships and suspends all users of this source. A later successful synchronization can restore directory access; manual restrictions remain.",
    aborted:
      "Transaction aborted; directory users are suspended until a successful synchronization.",
    missingHint:
      "Missing users are suspended only after two complete snapshots when suspension is selected. LDAP-disabled users are suspended immediately. An incomplete search never removes members. Interval 0 is manual; scheduled intervals are 15–10080 minutes.",
    fields: {
      user_filter: "User search filter",
      username_attribute: "Directory username attribute",
      group_base_dn: "Group base DN",
      group_filter: "Group search filter",
      directory_group_dn: "Directory group DN",
      group_ids: "Platform groups",
      organization_id: "Organization",
      organization_role: "Organization role",
      interval_minutes: "Synchronization interval (minutes)",
      missing_action: "When a user disappears",
    },
    missing: {
      keep: "Keep owned memberships",
      remove: "Remove automatic memberships",
      disable: "Remove memberships, then suspend after two snapshots",
    },
    roles: { member: "Member", auditor: "Auditor", admin: "Organization administrator" },
    username: "Directory username",
    userID: "Platform user ID",
    groups: "Platform groups",
    status: "Status",
    active: "Active",
    suspended: "Suspended by directory",
    entries: "Managed identities",
    runs: "Synchronization history",
    previous: "Previous",
    next: "Next",
    total: "{{count}} entries",
    states: { applying: "Applying / retry required", completed: "Completed", aborted: "Aborted" },
    errors: {
      identity_sources_invalid: "Check the source name, provider and status.",
      identity_sources_conflict: "The revision, name or request conflicts. Reload before editing.",
      identity_sources_not_found: "Identity source not found.",
      identity_sources_capacity:
        "Identity source storage is full. Existing data has been preserved.",
      identity_sources_unavailable:
        "Identity sources are temporarily unavailable. An unchanged failed request can be retried.",
      directory_sync_invalid:
        "Check the filters, stable attributes, group and organization mappings, and interval.",
      directory_sync_conflict:
        "Settings, provider, preview or request changed. Reload and collect a fresh preview when no transaction is pending.",
      directory_sync_pending:
        "Retry or abort the pending transaction before starting another operation.",
      directory_sync_incomplete:
        "LDAP collection is incomplete, cyclic, truncated or over its limit. No membership changes were applied.",
      directory_sync_capacity:
        "Directory synchronization capacity is full. Existing data has been preserved.",
      directory_sync_unavailable:
        "Directory synchronization is unavailable. Check provider availability and pending transaction history.",
      permission_denied:
        "Writing mappings requires system security, group, role and organization management permissions.",
    },
  },
};
