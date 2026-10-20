export default {
  rbac: {
    permissionsList: {
      accounts_rotation_fixed_password: "Configure and execute fixed-password rotation plans",
      accounts_rotation_check: "Check stored SSH account credentials",
      accounts_password_policy_view: "View SSH password generation policy",
      accounts_password_policy_manage: "Manage SSH password generation policy",
    },
  },
  sshPasswordPolicy: {
    title: "Generated SSH password policy",
    hint: "Applies to new automatic seven-day, manual and planned password rotations in this organization. Shared remote accounts must satisfy every organization's policy. Existing credentials and recovery journals stay intact.",
    configure: "Configure generated passwords",
    revision: "Policy revision {{revision}}",
    min_length: "Minimum length",
    max_length: "Maximum length",
    min_upper: "Minimum uppercase letters",
    min_lower: "Minimum lowercase letters",
    min_digits: "Minimum digits",
    min_symbols: "Minimum symbols",
    exclude: "Excluded characters (optional)",
    allowed:
      "16–128 characters; category minima must fit the maximum. Exclusions must be unique and leave at least 16 allowed characters. Symbols: !#%+,-.=?@[]^_{}~. Incompatible shared policies stop rotation before remote changes.",
    save: "Save SSH password policy",
    refresh: "Refresh password policy",
    history: "Policy change history",
    saved: "SSH password policy saved.",
    invalid: "Invalid character or length requirements. Check the policy limits.",
    conflict: "Policy changed. Current values were reloaded; review and save again.",
    denied: "Permission to manage this policy is required.",
    unavailable: "Password policy unavailable. Retry later.",
    loading: "Loading password policy…",
  },
};
