# 组织标签与资源继承

> 中文 | [English](./LABELS.en.md)

## 实现状态

E41 的标签与[平台公告](./ANNOUNCEMENTS.md)源码、Web、CLI/SDK、用例和双语文档已补齐，列为**实现待验**。本轮没有运行测试、构建、浏览器或 Docker。全部 42 组实现就绪后统一验证；写好用例不等于通过验收。

## 使用方式

`/console/labels` 管理当前组织的统一标签目录。目录对该组织已登录成员可读；标签使用键、值、颜色和说明，同一键可有多个值。每个资源最多直接绑定 64 个标签，同一键只能选一个值。键去除首尾空白并忽略大小写，值区分大小写。键最多 64、值 128、说明 500 个 Unicode 字符；控制字符拒绝，颜色固定为 `#rrggbb`。

资源可绑定资产或节点。资产直接标签优先，然后为最近节点、逐级父节点；同名键由优先级较高者覆盖。清空直接绑定恢复继承，移动节点立即改变继承结果。具名 SSH 账号共享物理资产标签，不复制凭据或标签。标签仅用于元数据和筛选，不改变 SSH、文件或资产授权。

资产列表显示生效标签，可按标签精确筛选，搜索也包含键和值。资源标签入口打开对应资产的绑定页。管理页提供直接绑定、继承来源、修订及变更审计。编辑绑定遇到冲突时，显式重新加载当前修订后再选择；未改变请求的网络失败可直接重试。

## 权限和组织范围

- `labels.manage`：创建、编辑和删除当前组织目录项。
- `labels.assign`：绑定当前可见资产；绑定节点还需要 `nodes.manage`。
- `labels.audit`：查看当前组织标签变更审计。

三者均可授予组织角色。目录管理权限本身不授予目标访问权；无权访问的绑定返回 404。每次读写、包括同请求 ID 重试，都重新检查当前资源权限。普通成员只能查看已授权资产及其祖先节点的绑定。标签目录在组织内共享；`X-JMS-ORG` 切换隔离目录、绑定、回执和审计。`GLOBAL` 不会默认落到其他组织的数据。

仍绑定存活资源的标签不能删除。先清空相关直接绑定；删除资源后可在删除标签事务中清理已不存在资源的残留绑定。存在性读取失败时保守保留，不自动解绑存活资源。

## API、CLI 和 SDK

| API | 用途 |
|---|---|
| `GET /api/v1/labels/labels?search=&offset=0&limit=20` | 目录搜索和分页，limit 最大 100 |
| `GET /api/v1/labels/choices` | 有界的紧凑目录选择项，省略说明 |
| `POST /api/v1/labels/labels` | 新建目录项，revision 为 0 |
| `PUT /api/v1/labels/labels/{id}` | 编辑目录项，携带当前 revision |
| `DELETE /api/v1/labels/labels/{id}` | JSON 包含 revision、request_id |
| `GET /api/v1/labels/bindings/{asset\|node}/{id}` | 直接绑定、完整生效标签及可否修改 |
| `PUT /api/v1/labels/bindings/{asset\|node}/{id}` | 替换直接绑定，JSON 包含 label_ids、revision、request_id |
| `GET /api/v1/labels/audit?offset=0&limit=20` | 分页变更审计 |
| `GET /api/v1/assets?label=ID&label=OTHER_ID` | 授权筛选后，对生效标签做 AND 匹配 |

写入请求使用当前修订和 8–100 位字母、数字、`_`、`-` 请求 ID。同身份、同请求 ID、相同规范化内容返回原始结果；更改内容返回冲突。旧创建/绑定回执重放不会恢复后来删除的标签或覆盖后来清空的绑定。空绑定也保留修订，旧 revision 0 无法重新创建绑定。

```sh
jms labels list --search production
jms labels choices
jms labels save --file label.json
jms labels save LABEL_ID --file update.json
jms labels binding asset ASSET_ID
jms labels bind node NODE_ID --file binding.json
jms labels delete LABEL_ID --revision 2 --request-id delete-label-001
jms labels audit
```

新建 `label.json`：

```json
{"name":"Environment","value":"production","color":"#58a6ff","description":"Primary hosts","revision":0,"request_id":"create-label-001"}
```

`binding.json`：

```json
{"label_ids":["label-0123456789abcdef0123456789abcdef"],"revision":0,"request_id":"bind-label-001"}
```

CLI 支持 `--file -` 从标准输入读取，拒绝未知 JSON 字段。SDK 为 `sessionclient.Labels`、`LabelChoices`、`SaveLabel`、`DeleteLabel`、`LabelBinding`、`BindLabels`、`LabelAudit`；组织客户端使用既有 `WithOrganization`。

## 存储与最终验证

默认组织使用 `JMS_DATA_DIR/labels.json`，其他组织在自身目录内存储；AES-GCM envelope v1 使用该组织的 Vault 派生密钥。PostgreSQL 使用组织作用域的 `labels` 文档。启动及安装离线预检打开并校验，未知格式拒绝。停机整站备份覆盖数据目录及密钥；新增标签恢复链路尚待统一验证。

当前每组织上限为 2000 个标签、20000 个绑定、4000 个不可变管理回执和 32 MiB 明文状态。回执达到上限时拒绝新变更，仍允许已保存回执重试，不静默清除幂等记录；需后续显式归档/迁移策略，不能承诺无限历史。审计保留最近 1000 条，内容仅含身份、动作、资源 ID、修订及时间。资源列表使用紧凑标签，页面按需加载；体积和性能尚未实测。

已写 Go 核心/并发/PostgreSQL、API 权限/筛选、CLI、组织运行时关闭重开、整站备份恢复和 Playwright 中英窄屏用例。覆盖持久化失败原子性、修订冲突、重复请求、删除后重放、权限撤销、账号归属、最近节点继承、一次网络失败后的同请求重试与清理。原生包入口复用既有重启检查标签/公告加密、持久化和回执，不新开容器或增加重启。Linux race 入口已纳入标签包，最终与既有统一验证入口一起执行；本轮没有新增通过报告或截图。
