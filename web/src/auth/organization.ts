export const DEFAULT_ORGANIZATION = "00000000-0000-0000-0000-000000000002";
export const ORGANIZATIONS_CHANGED = "jms233:organizations-changed";
const storageKey = "jms233.org";
export function selectedOrganization() {
  try {
    return localStorage.getItem(storageKey) || DEFAULT_ORGANIZATION;
  } catch {
    return DEFAULT_ORGANIZATION;
  }
}
export function switchOrganization(id: string) {
  if (!/^[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}$/.test(id)) return;
  try {
    localStorage.setItem(storageKey, id);
  } catch {
    return;
  }
  window.location.assign("/console");
}

// Every same-origin API request captures its organization when it starts. A
// switch reloads the application, closing terminals and discarding old UI state.
// External identity-provider requests never receive this header.
export function installOrganizationFetch() {
  window.addEventListener("storage", (event) => {
    if (event.key === storageKey) window.location.assign("/console");
  });
  const original = window.fetch.bind(window);
  window.fetch = (input: RequestInfo | URL, init?: RequestInit) => {
    const url = new URL(input instanceof Request ? input.url : String(input), window.location.href);
    if (url.origin !== window.location.origin || !url.pathname.startsWith("/api/v1/"))
      return original(input, init);
    const headers = new Headers(input instanceof Request ? input.headers : undefined);
    new Headers(init?.headers).forEach((value, key) => headers.set(key, value));
    headers.set("X-JMS-ORG", selectedOrganization());
    return original(input, { ...init, headers });
  };
}
