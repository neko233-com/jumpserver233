export default {
  runtimeLogs: {
    title: "Runtime logs",
    description:
      "Automatic size and daily rotation keeps operational logs manageable. Session recordings, command and file audits keep their own retention policies.",
    loading: "Loading log status…",
    console: "Logs are managed by the process supervisor. Built-in file rotation is disabled.",
    usage: "Disk usage",
    archives: "Archives",
    megabytes: "{{value}} MB",
    policy:
      "Up to {{size}} MB per file, {{count}} archives and {{days}} days. Expired archives are removed automatically.",
    last: "Last rotated: {{at}}",
    ioError: "Log storage needs attention. Check directory permissions and free disk space.",
    truncated: "{{count}} oversized records were shortened to keep file sizes bounded.",
    conflict: "Log state changed. Status has been refreshed; try again.",
    error: "Could not update log status. Retry or check the service.",
    rotated: "Rotation completed. Retrying the same request does not rotate again.",
    rotate: "Rotate now",
    rotating: "Rotating…",
    refresh: "Refresh status",
  },
};
