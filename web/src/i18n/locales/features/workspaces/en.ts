export default {
  assets: {
    workspace: "SSH execution workspace (optional)",
    workspaceHint:
      "Confine shells, jobs and SFTP to an existing Linux directory outside the helper cache. System tools are read-only. Network, elevation and gateway use are blocked. Unsupported hosts refuse connections. Empty uses ordinary SSH.",
  },
  files: { workspaceRoot: "Workspace {{path}} (shown as /)" },
};
