# Live terminal monitoring

> [中文](./LIVE-SESSIONS.md) | English

Active terminals in Audit offer Monitor live, a read-only view of new output after connection. SSH, Telnet and Kubernetes terminals are supported. Closing a monitor keeps the operator connected.

## Permissions and boundaries

- Operators can monitor their own active terminals. Cross-user monitoring requires the separate `audit.sessions.monitor_all` permission. Session metadata, replay and termination permissions do not grant it.
- System or organization roles can assign this permission. System administrators have it; existing auditor roles do not receive it automatically.
- Authorization issues a random, single-use ticket valid for 30 seconds. The server stores only its digest. WebSocket connections use `jms233-monitor-v1` and a ticket subprotocol; tickets stay out of URLs, logs and localStorage.
- Tickets bind the session, viewer, organization and issuing source. Attachment, each output write and one-second idle checks validate current identity, monitoring permission, organization membership and platform access policies.
- Raw keyboard input is never forwarded. Remote program output may display sensitive information, which is why cross-user monitoring requires its own permission.
- Any application message sent by a viewer disconnects that viewer. Monitoring cannot execute commands, resize the remote terminal or terminate the primary session. Disconnection, ticket replay and viewer revocation leave the operator connected.

## Usage and resources

Audit → active terminal → Monitor live. The dialog shows read-only guidance, connection state and a viewer ID / session ID watermark. This identifies screenshots; browser styles do not provide tamper resistance.

Historical screens and input replay are not sent. Ended encrypted recordings remain available through their separate replay flow. The view uses the operator's terminal dimensions, with scrolling on smaller screens.

Each session allows eight pending or attached viewers, with 64 per organization Broker. Each viewer queues up to 32 output chunks of at most 16 KiB. A full queue disconnects only that viewer. The browser also limits unrendered output to 512 KiB. Primary output never waits for a monitor, and monitoring does not duplicate an entire recording.

Before sending output, `monitor_started` is written and synced to the session audit index. A storage failure prevents output. Monitoring attempts to write `monitor_ended` at termination, including viewer identity and time, without tickets or terminal content. Storage failure can leave an end event missing.

## Continuous SSH authorization

SSH checks current user/group/roles, direct or inherited asset grants, grant expiry, organization membership, source/time/channel policies, and destination and gateway connection/credential revisions before and after dialing, at WebSocket attachment, before each input and every ten idle seconds. Revoked grants, group or role removal and changed targets or credentials prevent the next input; an idle connection ends at its next check. Command policies also reload current group and node scopes.

Credential rotation ends SSH sessions bound to an older revision; users reconnect. Previously downloaded data and delivered terminal output cannot be recalled.

Disabling an external identity source invalidates its SSH and monitoring identities. Approval cannot execute a pending command after access revocation. If the command policy changes to deny or to a different review rule, the pending input is cleared and the command is denied.

## API and deployment

- `POST /api/v1/sessions/{id}/monitor`: request a read-only ticket. Invisible, unattached or ended sessions return 404; capacity limits return 429.
- `GET /ws/api/v1/sessions/{id}/monitor`: single-use ticket attachment. Binary frames carry output; text frames carry resize metadata.
- Single-node deployment remains the priority. PostgreSQL single-active HA shares role and organization configuration. Tickets, queues and online sessions remain in the active process. Takeover requires new SSH and monitoring connections. Multi-active routing and session migration are unsupported.

See [interactive session security](./SESSION-SECURITY.en.md) for terminal/RDP creation-time watermarks and recording behavior. The full Enterprise objective continues under [PLAN](./PLAN.en.md). Session sharing, collaborative input and RDP live monitoring remain unimplemented.
