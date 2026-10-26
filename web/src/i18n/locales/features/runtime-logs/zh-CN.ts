export default {
  runtimeLogs: {
    title: "运行日志",
    description:
      "按大小和日期自动轮转，控制运维日志占用。会话录像、命令与文件审计继续遵循各自的保留策略。",
    loading: "正在读取日志状态…",
    console: "日志由进程管理器接管，内置文件轮转已关闭。",
    usage: "磁盘占用",
    archives: "历史文件",
    megabytes: "{{value}} MB",
    policy: "每个文件最多 {{size}} MB，保留 {{count}} 份历史和 {{days}} 天，自动清理过期文件。",
    last: "上次轮转：{{at}}",
    ioError: "日志存储异常，请检查目录权限和剩余磁盘空间。",
    truncated: "{{count}} 条超大记录已缩短，以控制日志大小。",
    conflict: "日志状态已变化，已刷新状态，请重试。",
    error: "无法更新日志状态，请重试或检查服务。",
    rotated: "轮转完成，重复请求不会再次轮转。",
    rotate: "立即轮转",
    rotating: "正在轮转…",
    refresh: "刷新状态",
  },
};
