# 原生云短信与企业机器人

> 中文 | [English](./NATIVE-NOTIFICATIONS.en.md)

E22 的原生短信和群机器人代码、中英 Web、现有 CLI/SDK 扩展及用例已编写，**未运行验证**。继续遵循全部 42 组实现后统一验收的门禁。本页不把通知手机号验证计作 E06 短信登录 MFA。

## 配置

组织或平台通知设置中选择提供方。两个范围的配置、联系方式、订阅与送达保持独立；默认关闭。管理需要对应范围的 `notifications.manage`。原有 SMTP、自定义 HTTPS 网关与存量客户端兼容。

| 提供方 | 设置与原生协议 |
|---|---|
| 阿里云 | AccessKey ID、只写短信秘密、签名、两类模板；`SendSms` 2017-05-25、ACS3-HMAC-SHA256，仅中国大陆号码。 |
| 腾讯云 | SecretId、只写短信秘密、地域、SDK AppId、签名、两类模板；2021-01-11、TC3-HMAC-SHA256、E.164。 |
| 华为云 | 应用 Key/只写秘密、官方应用接入地址、发送通道、签名、两类模板；`batchSendSms/v1`、SDK-HMAC-SHA256。 |
| CMPP | 六位源 ID、只写共享秘密、TLS 网关、发送号码、业务 ID、签名、两类正文模板；CMPP 2.0 双向连接认证与 SUBMIT 回执。 |
| 企微 | Webhook 通道选择企微，Bearer 填机器人 key。 |
| 钉钉 | Bearer 填机器人 access token，签名秘密必填；HMAC-SHA256 时间戳签名。 |
| 飞书/Lark | Bearer 填 hook ID，填写已启用的签名秘密；分别使用中国区/国际区固定域名。 |

原生机器人 token/hook ID 不放在公开 URL 字段。所有秘密沿用组织 AES-GCM 加密与只写字段；提供方切换会清除旧凭据，必须填写新提供方的凭据。机器人发送至管理员配置的群，订阅者同意外发；消息继续只有事件元数据和原生详情入口，不包含命令、输出、目标密码或登录验证码。

云短信先申请已审核的验证码与通知模板。参数按顺序列出：验证码为 `code`；通知可选 `title state id time link`。阿里云按名字组装 JSON，腾讯云/华为云按顺序组装数组。参数不得混用验证码和通知数据。通知手机号仍须完成既有一次性验证；API、CLI 和审计不返回验证码。

CMPP 使用校验主机名与证书的 TLS 网关，最低 TLS 1.2。仅支持 `+86` 中国大陆号码；单条 UCS-2（含签名）最多 70 字，不自动分段或重发，不支持代理运营商的全部扩展。正文使用 `{code}`、`{state}` 等已声明占位符。连接、完整帧读取、序列和回执均有边界；握手认证失败不提交短信，提交后丢失回执进入结果不明确。

## 安全、重试与 API

原生 HTTP 使用固定厂商域名；华为应用地址仅接受官方 `smsapi.*.myhuaweicloud.com` HTTPS 域名。机器人凭据在服务端组装为请求 URL，不回显。拒绝重定向、压缩回执、重复 JSON 键、超过 64 KiB 的回执；响应头上限 16 KiB，单次 HTTP 截止 15 秒。企微文本上限 2048 字节，其余机器人保守限制 3500 字节；超限明确失败。

复用现有固定送达 ID、队列、权限复查、配置修订、联系方式绑定、限流、退避、结果不明确和审计。厂商接收证明不等于终端送达；丢失回执或 5xx 不自动重放。该版本不消费运营商异步状态报告。

设置 API 仍为 `/api/v1/notifications/settings` 与 `/api/v1/platform-notifications/settings`。通道新增 `provider`、短信新增 `native_sms`。旧客户端省略提供方仍使用自定义网关。`request_id` 可用于幂等保存：同一操作者与相同内容返回原回执，改变内容返回 409；保留最多 2000 条加密回执，旧式不带请求 ID 的调用保留修订检查。CLI 沿用 `jms notifications settings-save --file -`；秘密通过标准输入传入。

## 统一验证准备

已编写原生 HTTPS 签名与回执、证书拒绝、重复/超限/重定向、CMPP 双向认证/序列/断线、设置幂等与秘密隔离、提供方切换、联系方式验证、队列不重复发送、API 权限、SDK 脱敏及 PostgreSQL 重开用例。

`native-notifications.spec.ts` 在临时组织内覆盖三类云短信和四类机器人、配置/消息幂等、手机验证、中英 390px；复用 OAuth 进程的 TLS/CONNECT 夹具，不新增容器，仅保留秘密清空后的两张截图。结束后关闭通道、清空秘密并重复执行组织归档清理；夹具内存与实例数据由既有 QA 生命周期回收。真实模板审批、短信计费、运营商链路和企业群接收尚未验收。

## 官方契约

- [阿里云 SendSms](https://help.aliyun.com/zh/sms/developer-reference/api-dysmsapi-2017-05-25-sendsms)、[ACS3 签名](https://help.aliyun.com/zh/sdk/product-overview/v3-request-structure-and-signature)。
- [腾讯云官方 2021-01-11 模型](https://github.com/tencentcloud/tencentcloud-sdk-go/blob/master/tencentcloud/sms/v20210111/models.go)。
- [华为云发送短信](https://support.huaweicloud.com/api-msgsms/sms_05_0001.html)、[官方签名实现](https://github.com/huaweicloud/huaweicloud-sdk-go-v3/blob/master/core/auth/signer/signer.go)。
- [钉钉机器人安全](https://open.dingtalk.com/document/robots/customize-robot-security-settings)、[飞书机器人](https://open.feishu.cn/document/client-docs/bot-v3/add-custom-bot)、[企微机器人](https://developer.work.weixin.qq.com/document/path/91770)；企微页面抓取受限，实际租户仍待验收。

2026-10-20 核对字段与协议，使用 Go 标准库实现，不引入完整云 SDK。
