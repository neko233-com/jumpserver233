# 品牌外观

> 中文 | [English](./BRANDING.en.md)

站点名称、独立登录标题、五种主题及强调色、顶部宽 LOGO、方形终端 LOGO、网站图标、登录图片和页脚备案信息均可在“品牌外观”集中配置。中英文内容跟随当前界面语言，保存后更新登录页、控制台、审计台和工作台。功能范围对照[竞品界面设置](https://docs.fit2cloud.com/jumpserver/manual/admin/system_settings/appearance/)；整体企业版目标继续按[计划](./PLAN.md)推进。

## 使用

需要全局 `branding.manage` 权限；系统管理员默认拥有，组织角色不能授予这项全局权限。进入控制台的“品牌外观”，修改内容、查看编辑区预览后保存。预览和图片处理不改变站点，也不写变更记录；校验拒绝保留原配置；数据库提交回执不确定时，下一次读取或重试先核对共享状态。恢复默认外观先修改草稿，再保存生效。

名称及独立登录标题各最多 64 个 Unicode 字符，登录标题留空时使用站点名称。页脚最多 160 字符，备案文字最多 80 字符；备案链接可留空，填写时必须为无用户凭据的 HTTPS URL。内容按纯文本显示，不接受 HTML/CSS。图片及文字在登录前公开，管理审计仍受权限保护。

五种受控主题为石墨、深夜、森林、紫梅和中国红，可自定义强调色。服务端要求强调色与两种主题背景均达到至少 4.5:1 对比度，并选择可读的按钮文字颜色。主题应用于界面框架、核心控件和登录 Shader；远端桌面画面、终端配色及安全水印保持各自的会话设置。

## 图片

- 只接受 PNG/JPEG。服务端先校验压缩字节与图片尺寸，再解码、去除原始元数据并重新编码为 PNG。
- 宽 LOGO 最大 512 KiB、2048 × 1024、524288 像素；方形终端 LOGO 和网站图标最大 512 KiB、512 × 512，须为正方形。
- 登录图片最大 2 MiB、2048 × 2048、1048576 像素，位于登录表单旁，窄屏顺序排列。重新编码后的 PNG 也须符合对应字节上限。
- 不接收 SVG、远程图片 URL 或任意 CSS。方形标识用于 Web 资源终端，网站图标独立设置。
- 公共图片地址使用内容摘要，响应固定为 PNG、禁止 MIME 猜测并允许不可变缓存。移除图片后当前接口不再返回旧摘要；已经缓存或下载的公开图片不属于撤回承诺。

## 保存、审计与 HA

默认单机，在数据目录的 `branding.json` 中保存版本 1 文档，采用临时文件、同步写入和原子替换。Unix 文件权限为 0600，目录为 0700。收到持久化成功回执后才替换内存快照。数据库报错可能伴随提交结果不确定：后续读取和重试先重新加载共享状态，保留原操作人，避免重复审计。公开品牌配置不含平台/SSH 凭据；此文档包含公开图片及私有管理审计，不使用 SSH Vault 密钥加密。

PostgreSQL 单活模式使用全局共享文档 `branding`，包含四种图片及最近 200 条配置审计。接管节点重新读取共享状态，无需复制本地图片目录。此能力不代表生产多活/分布式整体验收。加载时校验格式版本、记录容量、图片摘要及图像边界，文档最多 16 MiB；损坏状态拒绝启动。

保存使用当前修订。相同已保存内容的旧修订重试直接返回当前配置，不再写入或增加审计；旧修订的不同内容返回 409。文本字段采用完整替换；省略可选文本会清空它。图片字段省略表示保留，显式空字符串表示移除。跨标签通知和可见时每分钟复查更新已打开的界面，请求不重叠；保存当前标签会主动读取最新公开配置。

## API 与 CLI

- `GET /api/v1/branding`：公开配置及受控颜色，支持 ETag。
- `GET /api/v1/branding/images/{digest}`：公开当前 PNG。
- `GET /api/v1/settings/branding`：管理配置与主题选项。
- `PUT /api/v1/settings/branding`：保存，严格限制字段与请求大小。
- `POST /api/v1/settings/branding/prepare-image`：校验图片，`kind` 为 `logo`、`icon`、`mark` 或 `login_image`，`data` 为 base64；返回标准 PNG 的 base64。
- `GET /api/v1/settings/branding/audit?offset=0&limit=25`：私有变更记录，每页最多 100 条。

管理接口每次复核当前身份与全局权限，使用平台四种认证方式；`X-JMS-ORG` 不改变品牌作用域。请求失败返回明确错误码，管理响应禁止缓存。

```sh
jms branding show
jms branding audit --offset 0 --limit 25
jms branding save --file branding.json --logo logo.png --mark mark.png --icon icon.png --login-image login.jpg
jms branding save --file branding.json --clear-logo --clear-icon --clear-mark --clear-login-image
```

`branding.json` 使用 API 输入格式，包含当前 `revision`、`name_en`、`name_zh`、`theme`、`accent` 及需要保留的可选文本。`show` 返回包含 `settings` 和 `themes` 的管理响应，不能把整份响应直接作为保存输入。图片 CLI 参数在发送前执行同样的规范化，配置文件可用 `-` 从标准输入读取。Go 客户端提供 `Branding`、`SaveBranding` 和 `BrandingAudit`；`branding.AsInput` 从当前设置构造文本输入。

## 浏览器证据

2026-10-19 在隔离 Docker 生产实例中使用合成名称及页脚，实际通过页面保存配置并截图。切换语言后，站点标题、编辑器、预览及审计文字同步变化；退出后也检查了公开登录标题和页脚。自动化用例另外上传四类图片、打开真实 Web SSH，并检查公开读取与管理权限的区别。详细结果及边界见[自动化验证](./TESTING.md)。

![英文品牌管理页](./images/branding.en.png)

![中文品牌管理页](./images/branding.zh-CN.png)
