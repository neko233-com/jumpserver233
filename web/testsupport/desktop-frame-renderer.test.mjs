import { test } from "node:test";
import assert from "node:assert/strict";
import { createDesktopFrameRenderer } from "../src/components/desktopFrameRenderer.ts";
const packet = (n) => {
  const b = new ArrayBuffer(32);
  new DataView(b).setBigUint64(0, BigInt(n));
  const header = new DataView(b);
  header.setBigUint64(8, 0x89504e470d0a1a0an);
  header.setUint32(16, 13);
  header.setUint32(20, 0x49484452);
  header.setUint32(24, 320);
  header.setUint32(28, 200);
  return b;
};
const tick = () => new Promise((resolve) => setImmediate(resolve));

test("desktop renderer decodes one frame at a time and retains only the latest pending frame", async () => {
  const original = globalThis.createImageBitmap;
  const requests = [],
    draws = [];
  let closed = 0,
    failed = 0;
  globalThis.createImageBitmap = () => new Promise((resolve) => requests.push(resolve));
  const canvas = { getContext: () => ({ drawImage: (b) => draws.push(b.id) }) };
  const renderer = createDesktopFrameRenderer(
    () => canvas,
    () => {},
    () => failed++,
  );
  try {
    for (let i = 1; i <= 20; i++) renderer.push(packet(i));
    assert.equal(requests.length, 1);
    requests[0]({
      id: 1,
      width: 320,
      height: 200,
      close() {
        closed++;
      },
    });
    await tick();
    assert.equal(requests.length, 2);
    assert.deepEqual(draws, [1]);
    requests[1]({
      id: 20,
      width: 320,
      height: 200,
      close() {
        closed++;
      },
    });
    await tick();
    assert.deepEqual(draws, [1, 20]);
    assert.equal(closed, 2);
    assert.equal(failed, 0);
    renderer.push(packet(19));
    renderer.push(packet(20));
    await tick();
    assert.equal(requests.length, 2);
  } finally {
    renderer.dispose();
    globalThis.createImageBitmap = original;
  }
});
test("desktop renderer disposes an in-flight bitmap without touching the closed canvas", async () => {
  const original = globalThis.createImageBitmap;
  let finish,
    closed = 0,
    draws = 0;
  globalThis.createImageBitmap = () =>
    new Promise((resolve) => {
      finish = resolve;
    });
  const renderer = createDesktopFrameRenderer(
    () => ({
      getContext: () => ({
        drawImage() {
          draws++;
        },
      }),
    }),
    () => {},
    () => assert.fail("disposed renderer failed"),
  );
  try {
    renderer.push(packet(1));
    renderer.dispose();
    finish({
      width: 320,
      height: 200,
      close() {
        closed++;
      },
    });
    await tick();
    assert.equal(closed, 1);
    assert.equal(draws, 0);
  } finally {
    globalThis.createImageBitmap = original;
  }
});
test("desktop renderer rejects invalid payloads, zero sequences and oversized decoded images", async () => {
  const original = globalThis.createImageBitmap;
  try {
    for (const bad of [new ArrayBuffer(1), packet(0), new ArrayBuffer((40 << 20) + 9)]) {
      let errors = 0;
      const r = createDesktopFrameRenderer(
        () => null,
        () => {},
        () => errors++,
      );
      r.push(bad);
      assert.equal(errors, 1);
      r.push(packet(1));
      r.dispose();
    }
    let closed = 0,
      errors = 0;
    globalThis.createImageBitmap = async () => ({
      width: 3841,
      height: 1,
      close() {
        closed++;
      },
    });
    const r = createDesktopFrameRenderer(
      () => null,
      () => {},
      () => errors++,
    );
    r.push(packet(1));
    await tick();
    assert.equal(errors, 1);
    assert.equal(closed, 1);
    r.dispose();
  } finally {
    globalThis.createImageBitmap = original;
  }
});

test("desktop renderer validates PNG dimensions and header before allocating a decoder", () => {
  const original = globalThis.createImageBitmap;
  let decodes = 0;
  globalThis.createImageBitmap = () => {
    decodes++;
    throw Error("Unexpected decode");
  };
  try {
    for (const [offset, value] of [
      [8, 0],
      [16, 12],
      [20, 0],
      [24, 0],
      [24, 3841],
      [28, 2161],
    ]) {
      const data = packet(1);
      new DataView(data).setUint32(offset, value);
      let errors = 0;
      const r = createDesktopFrameRenderer(
        () => null,
        () => {},
        () => errors++,
      );
      r.push(data);
      assert.equal(errors, 1);
      r.dispose();
    }
    assert.equal(decodes, 0);
  } finally {
    globalThis.createImageBitmap = original;
  }
});
