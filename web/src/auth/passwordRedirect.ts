export function passwordRedirect(value: { password_change_required?: boolean }): boolean {
  if (!value.password_change_required) return false;
  window.location.assign(passwordReturnPath("/password-change"));
  return true;
}
export function passwordReturnPath(base: string): string {
  const next = new URLSearchParams(window.location.search).get("next");
  return base + (next?.startsWith("/share/") ? "?next=" + encodeURIComponent(next) : "");
}
