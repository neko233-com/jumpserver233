# SSH 生成密码策略

> 中文 | [English](./SSH-PASSWORD-POLICY.en.md)

为组织内新发起的 SSH 随机改密设置长度、字符类别下限和排除字符。每七天自动改密、资产页手动改密及[账号改密计划](./ROTATION-PLANS.md)共用生成器。密码只进入加密 Vault/恢复日志和已授权的远端改密通道，Web、CLI、配置回执不返回生成密码。

## 使用

控制台 →「账号改密」→「SSH 生成密码策略」。展开规则，设置最短/最长长度、大写、小写、数字、特殊字符的最少数量及可选排除字符。独立权限 `accounts.password_policy.view` 与 `accounts.password_policy.manage` 分别控制查看/修改，支持组织角色授权；拥有策略权限而无计划权限的用户仍可访问策略卡片。

默认最短 43、最长 128，每类至少一个。长度范围为 16–128，类别下限之和不能超过最长长度。实际长度为最短长度与类别下限总和的较大值。使用 `crypto/rand` 抽样和随机洗牌；字符集为英文大小写、数字及 `!#%+,-.=?@[]^_{}~`。排除字符必须来自该集合、不能重复，且至少保留 16 种字符；不接收自定义正则、脚本或固定密码。

策略在新生成密码时读取。已有待确定操作继续使用原加密日志中的同一密码，不因策略变化重生密码；[历史凭据恢复](./PASSWORD-ROTATION.md)、人工导入和平台登录密码不套用本生成策略。目标 OS/PAM 仍可有额外限制，远端验证成功后才提交新凭据。

## 共享账号

同一实际主机/账号跨组织重复托管时，采用各方最强类别下限、最大最短长度、最小最长长度和排除字符并集。归档/停用组织的已加载库存同样参与。无法同时满足时，以共享凭据冲突拒绝，远端密码和各 Vault 保持原值；不向调用者公开其他组织策略。

## API 与 CLI

`GET /api/v1/accounts/password-policy` 返回当前 `policy` 与最多 200 条变更审计；`PUT` 接收 `request_id` 和完整 `policy`（含当前 `revision`）。修改递增修订，完全相同的规则不增加修订或审计。最近 100 条请求绑定原输入与操作者，重放返回当前状态，复用 ID 改内容/操作者或新请求使用过期修订返回 409。请求始终重新检查当前用户、权限及组织。

```sh
jms account password-policy show
jms account password-policy set --file ssh-policy.json
```

示例配置为公开规则，无凭据：

```json
{"request_id":"ssh-policy-001","policy":{"revision":1,"min_length":48,"max_length":64,"min_upper":4,"min_lower":4,"min_digits":5,"min_symbols":3,"exclude":"OI1l0"}}
```

Go 客户端使用 `SSHPasswordPolicy` / `SaveSSHPasswordPolicy`，继续使用平台身份及 `X-JMS-ORG`，不接触远端密码。

策略、变更审计与回执以组织 Vault key 加密保存在 `ssh-password-policy.json`；单机无需新增服务，PostgreSQL 单活模式保存到组织隔离文档。启动/离线预检读取有效策略；损坏或密钥不匹配会拒绝。整站备份包含该文件并与 Vault key 一起恢复，幂等回执随备份保留。并不支持在线热备或多活。

## 范围与证据

竞品仍为 [JumpServer 企业版](https://www.jumpserver.org/enterprise.html)，其[官方功能说明](https://www.jumpserver.org/blog/tutorial-20250610.html)包含生成密码的长度与字符类别策略。这里采用 Go 原生生成和共享约束合并；逐计划覆盖、固定密码、其他协议改密及完整企业版对齐仍待完成。实际 Go/Testify、race、原生 SSH/备份和中英浏览器结果见[测试记录](./TESTING.md)。
