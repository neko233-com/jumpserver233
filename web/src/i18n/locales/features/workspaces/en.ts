export default {
  directoryPolicy: {
    mode: "Execution directory scope",
    pattern: "Directory path or pattern",
    modes: {
      all: "Any directory",
      exact: "Exact directory",
      tree: "Directory and descendants",
      regex: "Full-path regular expression",
    },
    hint: "Matches the verified starting directory. Matching commands in unverified terminals are blocked. The SSH workspace controls file access.",
    workingDirectory: "Execution directory (optional)",
    workingHint:
      "Choose an existing directory inside the SSH workspace. Empty starts at the workspace root. The command still has access to the configured workspace.",
    verifiedDirectory: "Verified execution directory",
    terminalNotice:
      "The starting directory cannot be verified in this terminal. Use an SSH job or jms exec with --directory inside the configured workspace.",
  },
  assets: {
    workspace: "SSH execution workspace (optional)",
    workspaceHint:
      "Confine shells, jobs and SFTP to an existing Linux directory outside the helper cache. System tools are read-only. Network, elevation and gateway use are blocked. Unsupported hosts refuse connections. Empty uses ordinary SSH.",
  },
  files: { workspaceRoot: "Workspace {{path}} (shown as /)" },
};
