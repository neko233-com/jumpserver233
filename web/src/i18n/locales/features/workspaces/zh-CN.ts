export default {
  assets: {
    workspace: "SSH 执行工作区（可选）",
    workspaceHint:
      "将 shell、作业和 SFTP 限制在 helper 缓存外的 Linux 目录树，系统工具只读；禁止网络、提权和网关转发。不支持时拒绝连接，留空用普通 SSH。",
  },
  files: { workspaceRoot: "工作区 {{path}}（显示为 /）" },
};
