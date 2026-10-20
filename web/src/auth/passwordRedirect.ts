export function loginChallengeRedirect(value: {
  password_change_required?: boolean;
  sms_factor_required?: boolean;
}): boolean {
  if (value.sms_factor_required) {
    window.location.assign(passwordReturnPath("/login?factor=sms"));
    return true;
  }
  if (!value.password_change_required) return false;
  window.location.assign(passwordReturnPath("/password-change"));
  return true;
}
export function passwordReturnPath(base: string): string {
  const next = new URLSearchParams(window.location.search).get("next");
  return (
    base +
    (next?.startsWith("/share/")
      ? (base.includes("?") ? "&" : "?") + "next=" + encodeURIComponent(next)
      : "")
  );
}
export { loginChallengeRedirect as passwordRedirect };
