# 平台公告

> 中文 | [English](./ANNOUNCEMENTS.en.md)

## 实现状态

公告的核心、API、Web、CLI/SDK 和预写用例已经接入，**尚未运行测试、构建、浏览器或 Docker 验证**。按用户 2026-10-20 的要求，完整 42 组功能实现后再统一验证。[组织标签](./LABELS.md)源码及用例也已补齐，E41 列为实现待验，仍不计入验收完成数。

## 使用

入口为 `/console/announcements`。所有已登录的平台身份都能读取当前有效公告；系统权限 `announcements.manage` 可以管理。组织角色不能授予这个权限。公告跨组织共享，切换组织不改变内容或自己的已读回执；它不是组织通知频道。

管理者可以保存草稿、发布、置顶、编辑和删除。支持中英标题及纯文本内容，缺失语言回退到已有内容；至少填写一种标题和一种内容。正文不执行 HTML、脚本或 Markdown。开始时间留空表示立即生效，结束时间留空表示不过期；区间为 `starts_at <= now < ends_at`。读者看不到草稿及窗口外公告，管理视图保留这些记录。

修改使用修订号，过期修订返回 `409`。创建、编辑、删除必须提供 8–100 位字母/数字/下划线/短横线的 `request_id`；相同平台操作人重复相同请求返回原回执，内容变化冲突。保存失败不提交内容、修订或回执。删除后重放原创建回执不会重建公告。Web 在未改变表单的失败重试中复用请求 ID。

已读确认绑定当前平台身份和公告修订；请求不能指定其他人。重复确认返回原时间，内容修订后要求重新阅读。过期修订冲突，未发布/失效公告不可确认。变更审计保留操作人、ID、修订、动作和时间，不复制公告正文。

## API 与 CLI

- `GET /api/v1/announcements?offset=0&limit=20`：当前有效公告、自己的已读状态及未读数。
- `GET /api/v1/announcements?manage=true`：管理视图，需要系统公告权限。
- `POST /api/v1/announcements`、`PUT /api/v1/announcements/{id}`：创建/编辑。
- `DELETE /api/v1/announcements/{id}`：JSON 请求体包含 `revision`、`request_id`。
- `POST /api/v1/announcements/{id}/read`：JSON 包含当前 `revision`。
- `GET /api/v1/announcements/audit`：管理变更审计，支持分页。

```sh
jms announcements list
jms announcements list --manage
jms announcements save --file notice.json
jms announcements save NOTICE_ID --file update.json
jms announcements read NOTICE_ID --revision 2
jms announcements delete NOTICE_ID --revision 2 --request-id delete-notice-001
jms announcements audit
```

JSON 输入示例：

```json
{
  "title": {"en": "Maintenance", "zh-CN": "维护通知"},
  "body": {"en": "SSH access remains available.", "zh-CN": "SSH 访问保持可用。"},
  "severity": "maintenance",
  "published": true,
  "pinned": false,
  "revision": 0,
  "request_id": "create-notice-001"
}
```

SDK 提供 Announcements、SaveAnnouncement、DeleteAnnouncement、ReadAnnouncement 和 AnnouncementAudit；ID 在拼接路径前校验。平台调用身份与 SSH 凭据保持独立。

## 数据与边界

单机文件为 `JMS_DATA_DIR/announcements.json`，使用平台身份派生密钥的 AES-GCM；PostgreSQL 使用 `platform-identity:announcements`。服务启动/离线预检打开并校验，未知 envelope 格式拒绝。整站停机备份按既有数据目录流程包含该文件和密钥；实际恢复/接管验收留到最终统一验证。

上限为 500 条公告、20,000 条当前已读回执、4,000 条管理请求回执、最近 1,000 条变更审计，解密文档总量不超过 16 MiB，先达到的容量生效。容量不足拒绝保存，不静默丢失幂等回执。标题每语言最多 200 个 Unicode 字符，正文 16,000 个；分页最多 100 条。当前不包含附件、邮件推送或法务签名证明；已读是当前身份的阅读确认。
