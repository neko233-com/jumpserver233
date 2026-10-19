# 单机自动准备与安装

> 中文 | [English](./AUTOMATIC-UPDATES.en.md)

原生受管安装支持“关闭／仅准备／维护窗口内安装”。默认关闭；开启后由同一个 `jms update supervise` 进程检查官方稳定 Release、下载并暂存，安装继续使用[定时安装事务](./INSTALLATION-SCHEDULE.md)的排空、停机、加密快照和首次启动验收。不要将版本检查、候选已就绪或安装成功混为同一验收层。

## 使用

先完成[单机安装基线](./INSTALLATION.md)，以私有快照口令文件和持久可撤销的平台凭证运行监督进程。Web：系统设置 → 安全策略 → 软件更新 → 自动准备与安装发布版本。需要全局 `security.manage`；组织管理员和普通操作员不能配置。

```sh
jms update auto-status --root /srv/jumpserver233-releases
jms update auto-policy --root /srv/jumpserver233-releases --revision 1 --request-id prepare-policy-001 --mode prepare --interval-hours 24
jms update auto-policy --root /srv/jumpserver233-releases --revision 2 --request-id install-policy-001 --mode install --hour-utc 2 --minute-utc 0 --window-minutes 30 --drain-timeout 600s
```

- `off` 不自动访问发布服务。已有的手动正式版本检查策略独立配置。
- `prepare` 检查、下载、完整校验并暂存；不执行候选程序、不创建升级快照或切换业务数据。
- `install` 在每日 UTC 窗口内将已准备候选转成固定摘要的单次计划。窗口跨午夜可用，不受主机时区或夏令时改变影响。准备仍按独立小时周期执行。
- 检查间隔 1–168 小时；窗口 5–180 分钟；排空等待 5–86400 秒。策略变更可提前下一次检查，但距上次尝试至少一分钟，随后恢复小时周期。
- 窗口外不提交停机。窗口到期、关闭策略或修改修订会取消尚未提交停机的自动计划，并在原排空实例/修订仍匹配时恢复接入。已提交停机的自动计划不能修改策略；安装事务继续完成验收或恢复。
- 当前手动计划优先；准备在后台进行，到期的手动安装会取消并等待自有准备任务回收。准备/网络失败保留当前服务，按持久化时间再次检查。

## 来源与信任

生产地址固定为 `neko233-com/jumpserver233` 官方 GitHub HTTPS API 和 Release 资源，不提供自定义 feed 地址。只接受非草稿、非预发布的稳定 `vX.Y.Z`，同平台归档、已上传状态、有效大小和 `sha256:` 摘要；下载重新检查具名版本，返回的完整资源身份必须与首次选择一致。官方接口与资源摘要字段见 [GitHub Release API](https://docs.github.com/en/rest/releases/releases?apiVersion=latest)。

下载后再执行归档/清单/每个文件字节校验；版本须更高，并声明预检与首次验收协议。准备不会运行包内程序。未知版本、缺少目标归档、损坏包、版本/摘要变化、协议不符、网络失败或限流不会产生可安装候选。上游来源和操作系统 TLS 信任是信任边界；同权限的本机用户修改 CA、程序或受管根不在隔离范围内。

平台凭证只用于本机子进程的维护 API，不传给 Release 服务；下载请求不包含平台授权头。监督程序必须重新核对当前平台权限、单机能力和自己启动的 PID。短期单机登录在重启后失效；长期监督使用持久可撤销凭据。备份口令仍按既有私有文件规则提供，不写入策略或报告。

## 回执、取消与恢复

`GET/PUT /api/v1/settings/security/updates/installation/automatic` 和 SDK `AutomaticUpdateStatus` / `SaveAutomaticUpdatePolicy` 返回策略、阶段、最近/下次尝试、已验证候选和最近活动；不返回平台凭据或快照口令。PUT 输入为 `request_id` 与 `policy`，policy 包含 `revision`、`mode`、`interval_hours`、`hour_utc`、`minute_utc`、`window_minutes`、`drain_timeout_seconds`。

私有 `.jms233-automatic.json` 保存策略、时间、候选及最近 100 条回执/活动。相同请求 ID、原始输入和操作者返回当前状态，不复原旧模式；改参、换人或新请求旧修订冲突。策略修订和单次计划绑定，并在同一根目录锁内核验开始排空/提交停机，关闭策略不会与已提交停机互相覆盖。

同一策略修订和候选摘要只尝试一次，失败或重启不会重复安装。当前策略另保存最多 100 个尝试摘要，不依赖普通计划回执保留期；达到上限需显式新修订。先持久化尝试占用，再发布单次计划；两文件之间中断会保留占用，要求人工核对后以新修订授权。检查安装与恢复回执后，显式保存新策略修订可授权后续尝试。已准备候选的安装修订变化时会重新检查绑定；不猜测跨版本兼容。

临时下载位于受管根的 `.jms233-maintenance/prepare-ID/`，有绑定根、运行 ID 和摘要的私有回执。成功、失败和取消回收本次临时归档。监督重启持有 OS 排他锁后，只清理能证明归属的历史准备目录；未知目录、回执或符号链接保留并拒绝继续准备。重复清理安全；已发布的不可变版本树继续按受管版本规则保留。

单机原生实现与隔离验收结果见[测试记录](./TESTING.md)。Docker 镜像/集群更新、真实历史格式迁移与完整 Enterprise 对齐仍需对应验证。此功能不创建 Git tag、Release 或 changelog。
