// One in-flight decode and one replaceable latest frame bound browser memory.
// This module deliberately has no React dependency so lifecycle is explicit.
export function createDesktopFrameRenderer(
  target: () => HTMLCanvasElement | null,
  onFrame: () => void,
  onError: () => void,
) {
  let closed = false,
    busy = false,
    latest = 0n;
  let pending: ArrayBuffer | null = null;
  const fail = () => {
    if (closed) return;
    closed = true;
    pending = null;
    onError();
  };
  async function drain() {
    if (busy || closed) return;
    busy = true;
    try {
      while (!closed && pending) {
        const data = pending;
        pending = null;
        const bitmap = await createImageBitmap(new Blob([data.slice(8)], { type: "image/png" }));
        try {
          if (
            bitmap.width < 1 ||
            bitmap.height < 1 ||
            bitmap.width > 3840 ||
            bitmap.height > 2160 ||
            bitmap.width * bitmap.height > 3840 * 2160
          )
            throw Error("Invalid desktop dimensions");
          const canvas = target();
          if (!closed && canvas) {
            canvas.width = bitmap.width;
            canvas.height = bitmap.height;
            canvas.getContext("2d")?.drawImage(bitmap, 0, 0);
            onFrame();
          }
        } finally {
          bitmap.close();
        }
      }
    } catch {
      fail();
    } finally {
      busy = false;
    }
  }
  return {
    push(data: ArrayBuffer) {
      if (closed) return;
      if (
        !(data instanceof ArrayBuffer) ||
        data.byteLength < 32 ||
        data.byteLength > 40 * 1024 * 1024 + 8
      ) {
        fail();
        return;
      }
      const header = new DataView(data);
      const sequence = header.getBigUint64(0);
      const width = header.getUint32(24),
        height = header.getUint32(28);
      if (
        header.getBigUint64(8) !== 0x89504e470d0a1a0an ||
        header.getUint32(16) !== 13 ||
        header.getUint32(20) !== 0x49484452 ||
        width < 1 ||
        height < 1 ||
        width > 3840 ||
        height > 2160
      ) {
        fail();
        return;
      }
      if (sequence === 0n) {
        fail();
        return;
      }
      if (sequence <= latest) return;
      latest = sequence;
      pending = data;
      void drain();
    },
    dispose() {
      closed = true;
      pending = null;
    },
  };
}
