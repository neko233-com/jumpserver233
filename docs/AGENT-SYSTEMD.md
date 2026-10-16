# systemd 原生 Agent 守护

[English](./AGENT-SYSTEMD.en.md) | [文档索引](./README.md)

在已安装 systemd 的 Linux 主机上，平台可以用当前 SSH 账号创建受管服务。常驻 Go `jms-agent` 版本 3 校验并定期执行固定启动器；systemd 管理监督进程和全部子进程，重启后恢复服务。不需要新增监听端口、平台令牌或目标机 Go 环境。

## 使用

在“工具与 Agent → 诊断与详情 → systemd 服务”查看状态、启用或停用。CLI 共用平台身份及现有审计：

```sh
jms plugin ASSET banhack233 systemd_status
jms plugin ASSET banhack233 systemd_enable
jms plugin ASSET banhack233 systemd_disable
```

`systemd_status` 需要 `plugins.inspect`，启停需要 `plugins.manage`，所有动作仍需当前目标 SSH 账号的 `connect` 授权并经过访问策略及登录/命令复核。旧 cron 守护继续可用；启用 systemd 前先停用 cron，避免同时拉起。平台不会自动安装 systemd、sudo 提权或为普通账号启用 linger。

- root：系统服务写入 `/etc/systemd/system`。
- 普通账号：使用已有用户管理器，文件写入 `~/.config/systemd/user`，需要已启用 linger 和可用用户总线。
- 服务名包含插件 ID 和规范受管目录的摘要，不会使用客户端指定的 unit 名或任意命令。

## 生命周期

后台 Go 组件只执行 SHA-256 匹配的受管 `systemd-launcher.sh`。先用不跟随符号链接的描述符读取校验，再经固定 `/bin/sh` 的 stdin 执行该快照。启动器继续核对固定制品、配置和进程身份；错误与最后检查时间写入有界本地状态。

升级、回退、策略切换和组件更新会先暂停 systemd，提交受管配置后重建固定 unit 和启动器，再恢复。未知 unit、覆盖文件、drop-in 和异常清单均拒绝操作，旧启动器备份后再替换。失败后显示暂停或异常状态，需要显式恢复；不执行未知程序。

停用 systemd 会停止受管服务；原本运行的 Agent 经校验后作为手动进程重新启动，因此存在短暂重启。停止 Agent 同时停用守护；卸载移除已确认所属的 unit，保留配置、日志、封禁状态与事件历史。取消平台任务后应重新查看远端状态。

Go 监督每 10 秒检查一次。崩溃或持久封禁对应的内核表丢失时，按已有恢复流程保留剩余封禁时间。暂时内核检查失败不会主动结束仍在运行的监测进程。集中事件沿用 [Agent 事件与审计](./AGENT-EVENTS.md)。

## 验证边界

自动化使用无 privileged、无宿主网络/文件挂载的 QEMU 软件模拟 Debian VM，验证真实 PID 1 systemd、root/用户 unit、进程组归属和重启。镜像来自 Debian 官方 cloud bookworm，下载前固定 SHA-512；测试凭据仅为隔离夹具公开合成数据。服务语义参考 [systemd v252 官方手册源码](https://github.com/systemd/systemd/blob/v252/man/systemd.service.xml)。实际验收结果见 [测试记录](./TESTING.md)。这不代表其它 Linux 发行版、ARM64 或生产 HA 已验收。
