export default {
  directoryPolicy: {
    mode: "执行目录范围",
    pattern: "目录路径或模式",
    modes: {
      all: "任意目录",
      exact: "精确目录",
      tree: "目录及其子目录",
      regex: "完整路径正则表达式",
    },
    hint: "匹配经验证的执行起始目录。无法验证目录的终端会拒绝匹配的命令。文件访问范围由 SSH 工作区限制。",
    workingDirectory: "执行目录（可选）",
    workingHint:
      "选择 SSH 工作区内已存在的目录；留空从工作区根目录执行。命令仍可访问配置的整个工作区。",
    verifiedDirectory: "已验证的执行目录",
    terminalNotice:
      "当前终端无法验证执行起始目录，请使用 SSH 作业，或通过 jms exec --directory 指定已配置工作区内的目录。",
  },
  assets: {
    workspace: "SSH 执行工作区（可选）",
    workspaceHint:
      "将 shell、作业和 SFTP 限制在 helper 缓存外的 Linux 目录树，系统工具只读；禁止网络、提权和网关转发。不支持时拒绝连接，留空用普通 SSH。",
  },
  files: { workspaceRoot: "工作区 {{path}}（显示为 /）" },
};
