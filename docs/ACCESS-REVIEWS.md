# SSH/SFTP 登录复核

> 中文 | [English](./ACCESS-REVIEWS.en.md)

登录复核管理可委派 `reviews.login.manage`；全局连接权限仍需复核，只有 `login_review.bypass` 可跳过。详见 [RBAC.md](./RBAC.md)。

登录复核是 JumpServer 企业版对齐切片。它叠加在现有资产授权之上：操作员必须先拥有本次访问所需的 `connect` 或 `sftp` 授权；若资产开启登录复核，还必须等管理员批准后才能访问。

## 配置与流程

- 管理员在 SSH 资产编辑表单中开启“SSH 与 SFTP 登录需要管理员复核”。管理员自身不进入复核队列。
- 操作员从 Web SSH、`jms ssh <asset-id>` 或 SFTP 文件管理器发起访问。服务端分别检查 `connect` 或 `sftp` 授权，再创建对应类型的复核请求；等待审批时不会打开 SSH 或 SFTP 连接。
- 管理员在“系统设置 → 登录复核”查看申请者、资产、账号、申请时间与过期时间，然后批准或拒绝。
- SSH 批准后，操作员客户端读取自己的复核状态并自动重试。一次性许可绑定操作员、资产和 SSH 账号，60 秒内消费一次；连接失败也不会重复使用。
- SFTP 批准后，文件管理器通过 `POST /api/v1/assets/{assetID}/files/session` 消费一次性许可并取得 30 分钟的浏览器会话令牌。令牌绑定操作员、资产和 SSH 账号，服务端只保存摘要；关闭文件管理器时会撤销令牌。所有 SFTP 文件接口都验证该令牌。
- 申请在 5 分钟后过期。拒绝或过期都不会创建会话。对同一操作员、资产和账号的重复请求会复用当前待处理申请。

## API 与存储

- `POST /api/v1/sessions` 在需要 SSH 复核时返回 `202 Accepted` 与 `review_id`，此时尚未创建 SSH 会话。
- SFTP 文件管理器先调用 `POST /api/v1/assets/{assetID}/files/session`。待审批时返回 `202 Accepted` 与 `review_id`；批准后重试返回 `201 Created` 和短期 `session_token`。复核关闭时返回 `200 OK`，文件接口继续使用原有 `sftp` 授权流程。
- 开启复核的资产要求文件接口携带 `X-JMS-SFTP-Session`。SFTP 会话令牌保存在服务端内存，服务重启或 HA 接管后失效；操作员需要重新打开文件管理器并申请复核。
- 管理员可用 `GET /api/v1/access-reviews` 查询待处理队列，并通过 `POST /api/v1/access-reviews/{reviewID}/approve` 或 `/deny` 处理申请。
- 申请人可用 `GET /api/v1/access-reviews/{reviewID}` 查询自己的状态；其他操作员读取该 ID 时收到 `404`。
- standalone 将状态写入 `JMS_DATA_DIR/access-reviews.json`，文件权限为 `0600`；集群模式写入 PostgreSQL `access-reviews` JSONB 文档。待处理请求和审批身份可在服务切换或重启后恢复。
- 已完成记录保留 7 天后清理。记录包含申请人、资产、SSH 账号、申请与复核时间以及管理员身份，不含密码、终端票据或 SSH 会话凭据。

## 当前边界

- 复核覆盖 Web SSH、Agent CLI 和 SFTP 文件管理器。SFTP 令牌是短期浏览器会话授权，不会把 SSH 密码返回给浏览器。
- 登录复核是 `connect` 或 `sftp` 授权之外的第二道检查，不会为无授权用户开放资产访问。
- 复核许可在服务端会话创建前消费；SSH 建连失败时，操作员需要再次申请并复核。
- 单机是默认部署。集群模式依赖共享 PostgreSQL 文档与现有单活选主；SFTP 浏览器会话令牌在活动节点进程内，故障切换后需重新申请；生产级故障演练仍待完成。
