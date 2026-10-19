export default {
  rbac: {
    permissionsList: {
      accounts_password_policy_view: "查看 SSH 密码生成策略",
      accounts_password_policy_manage: "管理 SSH 密码生成策略",
    },
  },
  sshPasswordPolicy: {
    title: "SSH 生成密码策略",
    hint: "用于当前组织新发起的每七天自动、手动与计划改密。共享远端账号必须同时满足各组织策略；已有凭据和恢复日志继续保留。",
    configure: "配置生成密码规则",
    revision: "策略修订 {{revision}}",
    min_length: "最短长度",
    max_length: "最长长度",
    min_upper: "最少大写字母",
    min_lower: "最少小写字母",
    min_digits: "最少数字",
    min_symbols: "最少特殊字符",
    exclude: "排除字符（可选）",
    allowed:
      "长度 16–128，各字符类别下限之和不能超过最长长度。排除字符不可重复，且至少保留 16 种可用字符。特殊字符：!#%+,-.=?@[]^_{}~。共享策略不兼容时，在远端改密前拒绝操作。",
    save: "保存 SSH 密码策略",
    refresh: "刷新密码策略",
    history: "策略变更历史",
    saved: "SSH 密码策略已保存。",
    invalid: "字符或长度要求无效，请检查策略限制。",
    conflict: "策略已变化，已重新加载当前值，请核对后再保存。",
    denied: "需要密码策略管理权限。",
    unavailable: "暂时无法读取密码策略，请稍后重试。",
    loading: "正在读取密码策略…",
  },
};
