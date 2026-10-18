// Only missing-resource errors are safe to ignore during owned QA cleanup.
export function isMissingDockerResource(error) {
  const detail = String(error?.stderr || error?.message || "").toLowerCase();
  return detail.includes("no such object") || detail.includes("no such container") || detail.includes("no such volume") || detail.includes("no such network");
}

// Building the same QA image is idempotent. Retry only transient registry/network
// failures; container creation and remote commands are never retried here.
export async function buildQAImage(execute, args, options = {}) {
  for (let attempt = 0; ; attempt++) {
    try {
      return await execute("docker", args, { maxBuffer: 8 * 1024 * 1024, ...options });
    } catch (error) {
      const detail = String(error.stderr || error.message);
      if (attempt >= 2 || !/\bEOF\b|ECONNRESET|ETIMEDOUT|timeout|connection reset|502 Bad Gateway|503 Service Unavailable/i.test(detail)) throw error;
      process.stderr.write("Transient QA image registry failure; retrying bounded image preparation.\n");
      await new Promise(resolve => setTimeout(resolve, 250 * (attempt + 1)));
    }
  }
}
