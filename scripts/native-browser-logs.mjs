// Classify only two browser diagnostics expected in this isolated native QA:
// the anonymous session probe and headless GPU readback performance messages.
// Application warnings, post-login 401s and all other failures remain fatal.
export function classifyNativeBrowserLog(type, text, locationURL, origin, authenticated) {
  if (!authenticated && type === "error" && text === "Failed to load resource: the server responded with a status of 401 (Unauthorized)") {
    try {
      const url = new URL(locationURL);
      if (url.origin === origin && url.pathname === "/api/v1/authentication/session/" && !url.search && !url.hash) return "anonymous_session_probe";
    } catch { /* Missing/invalid diagnostic locations are never exempted. */ }
  }
  if (type === "warning" && /^\[\.WebGL-0x[0-9a-f]+\]GL Driver Message \(OpenGL, Performance, GL_CLOSE_PATH_NV, High\): GPU stall due to ReadPixels(?: \(this message will no longer repeat\))?$/.test(text)) return "headless_gpu_readback";
  return "unexpected";
}
