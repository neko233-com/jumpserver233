# JumpServer Community Feature Baseline (research snapshot)

> [中文](./BASELINE.md) | English

This document is the requirement source snapshot for jumpserver233, researched on 2026-10-14. Sources: github.com/jumpserver/jumpserver README and org repositories, official docs at docs.fit2cloud.com (v5), jumpserver.org/features.html comparison page, lina frontend routes, jumpserver backend `apps/` layout.

## 1. Upstream architecture components

| Component | Language | Responsibility | Protocols |
|---|---|---|---|
| JumpServer Core | Python (Django) | Platform core: users/permissions/assets/audit/API/scheduling | REST /api/v1, WebSocket gateway |
| Lina | Vue | Admin console web UI | HTTP |
| Luna | TypeScript | Web workspace, web terminal, file manager, replay | WebSocket, HTTP |
| KoKo | Go | Generic character-protocol connector: SSH/Telnet/K8s/SFTP/DB | SSH/Telnet/K8s exec/SFTP/DB |
| Chen | Java | Web database connector (web GUI) | MySQL/MariaDB/PostgreSQL etc. |
| Kael | Go | AI component | OpenAI-compatible API |
| Tinker | — | Windows application connector (free in Community) | RDP/app publishing |
| Video Worker | — | Replay transcoding (Razor/Lion replay → MP4) | — |

Notes:

- In v5, Lion's (RDP/VNC) functionality merged into KoKo and is no longer deployed separately
- rufus and koala are not part of the JumpServer org; do not include them in the baseline
- License GPL-3.0, copyright FIT2CLOUD

## 2. Backend app layout (Django apps/)

users, orgs, rbac, assets, accounts, acls, perms, terminal, audits, authentication, settings, ops, notifications, tickets, labels, reports, chat_ai, common.

## 3. Three frontend views (per lina routes)

- `/console` Console (admin)
- `/audit` Audit (auditor)
- `/workbench` Workbench (regular user)
- `/settings` System settings, `/profile` Profile
- Permissions are Django permission strings (e.g. `assets.view_asset`) enforced per route
- Enterprise routes carry `licenseRequired: true`

### 3.1 Console

- Dashboard: asset/session/user stats charts
- Users: user list (create/detail/import, password via email reset or direct set), user groups
- Assets: unified list + platform tabs (Linux/Windows hosts, databases, network devices, cloud, web, GPT, custom), platform list (protocol/account discovery params), **node tree** (`/Default` root), **zone + gateway** (multi-level proxy), connectivity tests
- Accounts: account list (password/secret ciphertext), account templates, virtual accounts
- Grants: asset grant rules (user+group × asset+node × account × action, node inheritance, time windows), session sharing
- ACL: command filtering (CommandFilterACL + command groups) is Community
- Labels; PAM (partly X-Pack, see exclusion list)

### 3.2 System settings

- Basic settings; org management / role list (X-Pack)
- AI assistant (ChatAI: built-in API/iframe, connectivity test)
- Notifications: email (SMTP/SSL/TLS/templates), SMS (basic), message subscriptions (in-app + email)
- Feature settings: announcements, tickets (1–5 approval levels, approver attribute filters, CC), job center (bulk command switch + blacklist), account storage (Vault; X-Pack status ambiguous), SSH certificate issuance (OpenBao)
- Auth settings: LDAP/LDAP-HA, CAS, RADIUS, OAuth2, OIDC, SAML2, SSO, Passkey, MFA config (backends dir: ldap, cas, radius, oauth2, oidc, saml2, passkey, pubkey, token, sso, ukey)
- Storage settings: command storage, replay storage (DB / S3 / OSS / COS / OBS / SFTP)
- Component settings: component (terminal endpoint) status, Endpoint/EndpointRule, Applet/VirtualApp/AppProvider
- Security settings: auth security (captcha, auxiliary code, idle disable, anomaly notification, **global MFA policy: off/all/admins-only**, MFA validity, OTP params), login restrictions (failure lockout by user/IP, IP allow/deny lists, single-device login), password policy (expiry, last-N reuse, length, character classes), session security (**watermark**, session sharing, close-browser expiry, idle/max duration)
- System tools, system task list, license import

### 3.3 Audit view

Dashboard; session audit (online/history, detail, live monitor and terminate, command records, file transfer records, online users); log audit (login/operation/password change/AI chat); job logs; ticket audit; reports (X-Pack).

### 3.4 Workbench

Overview; my assets (connection list, web SFTP file manager, personal credentials); job center (quick commands, job/template management, execution history; requires SECURITY_COMMAND_EXECUTION); **web terminal** (xterm.js: connection picker, file-transfer sidebar, script library, AI assistant, terminal settings); org switch, global search, system messages, daily tickets, language switch.

### 3.5 Profile

Profile, password & SSH keys, Passkey, AccessKey (API signing), temporary token, connection token, OAuth2 access token, preferences, **MFA binding (OTP)**.

## 4. API characteristics (external compatibility surfaces)

1. REST API v1 + Swagger at `/api/docs/`
2. Four auth methods:
   - Session cookie `jms_sessionid`
   - One-shot token: `POST /api/v1/authentication/auth/` {username,password} → `token`, `Authorization: Bearer <token>`
   - Permanent token: `Authorization: Token xxx`
   - Access key/secret: HTTP signature (hmac-sha256 over (request-target)/date)
3. Multi-tenant header `X-JMS-ORG`
4. MFA flow: password → OTP/SMS/third-party; user-side binding API; global policy enforcement; viewing a password triggers MFA then a validity window
5. Session WebSocket: `/ws/` endpoints, binary frames for terminal I/O (xterm.js ↔ connector), resize/clipboard/file-transfer messages; replay `replay.json.gz` (asciinema-compatible), convertible to MP4
6. Component communication: terminal components register with Core via bootstrap_token and report sessions/commands/replays

## 5. X-Pack Enterprise list (alignment target for Phase 7+, not permanently excluded)

Competitor = JumpServer Enterprise (https://www.jumpserver.org/enterprise.html). Enterprise architecture: X-Pack add-on, vendor support services, app store. X-Pack items (verbatim from enterprise.html):

Single sign-on integration; RADIUS / SMS second-factor; RBAC role management; asset sync; Oracle / SQL Server / DB2 / DM; account collection; account rotation; account backup; access control; asset-login and command review; app market; ticket management; org management; custom LOGO and themes; facial recognition; and more.

## 6. Community core (must implement)

SSH/RDP(web)/DB(MySQL/MariaDB/Redis/MongoDB)/K8s/web assets/remote apps (Chrome/DBeaver), asset tree + node grants, action/time/protocol grants, command filtering, SFTP file management, six audit types (session/command/file/login/operation/password change) + job audit, replay and cloud storage, MFA (OTP), LDAP/CAS/RADIUS/OAuth2/OIDC/SAML2/SSO/Passkey auth, watermarking, session sharing, labels, job center, scheduled tasks, notifications (email/SMS/in-app), AI assistant, full REST API.

## 7. Deviation notes for this reimplementation

1. Upstream frontend is Vue + Element; this project is React — stack substitution
2. Django monolith + connectors → Go layering: Core API/RBAC/audit separated from protocol proxies
3. Session WebSocket protocol, replay format, X-JMS-ORG, and the four auth methods are the compatibility surfaces
4. Lion merged into KoKo (v5); rufus/koala do not exist
