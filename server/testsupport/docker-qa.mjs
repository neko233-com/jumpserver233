// Only missing-resource errors are safe to ignore during owned QA cleanup.
export function isMissingDockerResource(error) {
  const detail = String(error?.stderr || error?.message || "").toLowerCase();
  if (/(?:^|:\s*|\n\s*)(?:permission denied|access denied|unauthorized|forbidden|cannot connect|connection refused)\b/.test(detail) || /^\s*eof\s*$/.test(detail)) return false;
  return detail.includes("no such object") || detail.includes("no such container") || detail.includes("no such volume") || detail.includes("no such network") || /(?:^|\n)(?:error response from daemon:\s*)?network [a-z0-9][a-z0-9_.-]* not found\s*$/.test(detail);
}

// Building the same QA image is idempotent. Retry only transient registry/network
// failures and Windows context metadata sharing violations before dispatch;
// container creation and remote commands are never retried here.
export async function buildQAImage(execute, args, options = {}) {
  for (let attempt = 0; ; attempt++) {
    try {
      return await execute("docker", args, { maxBuffer: 8 * 1024 * 1024, ...options });
    } catch (error) {
      const detail = String(error.stderr || error.message);
      const sharedContext = /unable to resolve docker endpoint: context /i.test(detail) && /[\\/]meta\.json: The process cannot access the file because it is being used by another process/i.test(detail);
      if (attempt >= 2 || !(sharedContext || /\bEOF\b|ECONNRESET|ETIMEDOUT|timeout|connection reset|502 Bad Gateway|503 Service Unavailable/i.test(detail))) throw error;
      process.stderr.write("Transient QA image preparation failure; retrying bounded preparation.\n");
      await new Promise(resolve => setTimeout(resolve, 250 * (attempt + 1)));
    }
  }
}
