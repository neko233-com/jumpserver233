import test from "node:test";
import assert from "node:assert/strict";
import { webcrypto } from "node:crypto";
import { requestID } from "../src/utils/requestID.ts";

test("operation IDs are UUID v4 using secure random bytes without randomUUID", () => {
  const original = Object.getOwnPropertyDescriptor(globalThis, "crypto");
  Object.defineProperty(globalThis, "crypto", { configurable: true, value: {
    getRandomValues: webcrypto.getRandomValues.bind(webcrypto),
    randomUUID() { throw Error("unavailable on private HTTP"); },
  } });
  try {
    const ids = Array.from({ length: 1024 }, () => requestID());
    assert.equal(new Set(ids).size, 1024);
    for (const id of ids) assert.match(id, /^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/);
  } finally {
    if (original) Object.defineProperty(globalThis, "crypto", original);
    else delete globalThis.crypto;
  }
});
