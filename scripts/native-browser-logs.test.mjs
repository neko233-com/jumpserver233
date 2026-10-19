import test from "node:test";
import assert from "node:assert/strict";
import { classifyNativeBrowserLog } from "./native-browser-logs.mjs";

const origin = "http://127.0.0.10:18080", anonymous = "Failed to load resource: the server responded with a status of 401 (Unauthorized)";
test("only an anonymous session probe at the exact QA origin is expected", () => {
  assert.equal(classifyNativeBrowserLog("error", anonymous, origin + "/api/v1/authentication/session/", origin, false), "anonymous_session_probe");
  for (const [url, authenticated] of [[origin + "/api/v1/assets", false], [origin + "/api/v1/authentication/session/", true], [origin + "/api/v1/authentication/session/?q=x", false], ["http://other.example/api/v1/authentication/session/", false], ["", false]]) {
    assert.equal(classifyNativeBrowserLog("error", anonymous, url, origin, authenticated), "unexpected");
  }
});
test("only exact headless GL readback performance warnings are categorized", () => {
  const message = "[.WebGL-0x123abc]GL Driver Message (OpenGL, Performance, GL_CLOSE_PATH_NV, High): GPU stall due to ReadPixels";
  for (const suffix of ["", " (this message will no longer repeat)"]) assert.equal(classifyNativeBrowserLog("warning", message + suffix, "", origin, true), "headless_gpu_readback");
  for (const text of ["WebGL context lost", message + " error", "Application warning", message.replace("Performance", "Error")]) assert.equal(classifyNativeBrowserLog("warning", text, "", origin, true), "unexpected");
  assert.equal(classifyNativeBrowserLog("error", message, "", origin, true), "unexpected");
});
