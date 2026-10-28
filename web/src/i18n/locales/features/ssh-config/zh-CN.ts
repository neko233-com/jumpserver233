export default { sshConfigImport: {
  title: "导入本机 SSH 配置",
  hint: "将当前组织中允许连接的 SSH 账号同步成本机别名。连接仍经过跳板机授权、审批和审计，不导出目标机密码。",
  host: "跳板机 SSH 地址", port: "SSH 端口",
  chooseFile: "选择本机 ~/.ssh/config，确认文件访问后更新专用区块；其他配置保留。首次连接仍需核对跳板机主机密钥。",
  fallback: "当前浏览器或 HTTP 地址无法直接访问本机配置。请安装 jms 客户端，配置 JMS_SERVER_URL 和平台身份后运行以下命令；可先加 --preview 查看。",
  windows: "Windows PowerShell", unix: "macOS / Linux 终端",
  failed: "导入未完成：请选择正确的 config 文件，检查授权、文件冲突或并发修改后重试。",
  success: "已同步 {{count}} 个账号。请使用生成的 jms 别名连接。", close: "关闭", import: "选择配置并导入",
} };
