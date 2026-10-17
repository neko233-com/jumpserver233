const key = "jms233.loginReturn";
const allowed =
  /^\/share\/[A-Za-z0-9_-]{16,128}(?:\?org=[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12})?$/;

// Only a local share route can survive the sign-in/MFA/SSO flow. No secret code
// is put in the URL or storage, and arbitrary redirects are rejected.
export function loginReturnPath() {
  const requested = new URLSearchParams(window.location.search).get("next");
  try {
    if (requested && allowed.test(requested)) {
      sessionStorage.setItem(key, requested);
      return requested;
    }
    if (requested) {
      sessionStorage.removeItem(key);
      return "/console";
    }
    const previous = sessionStorage.getItem(key);
    return previous && allowed.test(previous) ? previous : "/console";
  } catch {
    return requested && allowed.test(requested) ? requested : "/console";
  }
}
export function clearLoginReturn() {
  try {
    sessionStorage.removeItem(key);
  } catch {
    /* Storage is optional. */
  }
}
