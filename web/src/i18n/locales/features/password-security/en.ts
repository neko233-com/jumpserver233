export default {
  passwordSecurity: {
    title: "Password security",
    scope:
      "Applies to local platform passwords. External providers manage their passwords. Remote SSH credentials use separate rotation plans.",
    min_length: "Minimum bytes (operator)",
    admin_min_length: "Minimum bytes (administrator)",
    history_count: "Previous passwords disallowed",
    max_age_days: "Operator maximum age (days; 0 disables)",
    admin_max_age_days: "Administrator maximum age (days; 0 disables)",
    upper: "Uppercase",
    lower: "Lowercase",
    digit: "Digits",
    special: "Symbols",
    rules:
      "{{min}}–256 UTF-8 bytes; no control characters. Reject the current and last {{history}} recorded passwords.",
    policyWarning:
      "Saving revokes all local users' sessions and API credentials, including yours. You will sign in again. Length and complexity apply to new passwords; age limits also apply to existing passwords.",
    save: "Save password policy and sign out",
    audit: "Password policy audit",
    revision: "Revision {{revision}} · local identities revoked: {{count}}",
    previous: "Previous",
    next: "Next",
    error: "Operation failed. Refresh, check the policy revision and retry.",
    changeTitle: "Change your password",
    changeHint:
      "Your password expired or an administrator requires a change. This temporary proof only allows a password change. Sign in again afterwards to complete all access checks.",
    password: "New password",
    confirm: "Confirm new password",
    change: "Change password",
    back: "Cancel and return to sign-in",
    mismatch: "Passwords do not match.",
    password_policy: "The password does not meet the configured requirements.",
    password_history: "Choose a password that was not used recently.",
    password_unchanged: "Choose a different password.",
    password_change_invalid: "This change request expired or was invalidated. Sign in again.",
    password_rate_limit: "Too many attempts. Try again later.",
    reset_password: "Reset password",
    reset_mfa: "Reset MFA",
    resetHint:
      "Revoke sessions, API credentials and pending sign-ins. MFA reset removes TOTP, recovery codes and the SMS login phone; Passkeys remain enrolled. The account's enabled state and grants stay as configured.",
    force: "Require a password change at next sign-in",
    apply: "Confirm credential reset",
    cancel: "Cancel",
    resetError:
      "Reset failed. Check the revision, password policy and credential/role management permissions; refresh before retrying.",
  },
};
