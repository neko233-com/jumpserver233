# Platform sign-in reviews

> English | [中文](./PLATFORM-LOGIN-REVIEWS.md)

Platform sign-in policies support approval and console notifications. Primary authentication, existing MFA requirements and Passkey verification finish first; the original requester obtains a platform session after approval. Asset grants, SSH/SFTP reviews and command reviews remain independently enforced. The competitor is [JumpServer Enterprise](https://www.jumpserver.org/enterprise.html); this feature belongs to the ongoing Enterprise implementation.

## Configuration and use

In Access policies → User sign-in, select users/groups, sources, timezone and weekly hours, then choose Require approval. Optional reviewer users/groups restrict assignment. Empty selections allow any other account with `reviews.platform_login.manage`. Selected reviewers still require that permission; self-approval is blocked. Built-in administrators and the access-reviewer role have this permission.

After authentication the applicant sees a waiting panel that survives reload. Requests expire after five minutes. Approval allows completion for one minute, bounded by the original deadline. The original source and ticket, current identity, matching policy ID and revision must remain valid. Password, role, MFA, provider/Passkey availability or matching-policy changes invalidate the request. Reviewer permission and assignment/group membership are checked again at completion. Waiting does not extend session expiry or the original authentication timestamp.

Platform sign-in reviews provides approve, deny, history and audit. Approval itself creates no session; the applicant automatically completes a one-use exchange. Denial, cancellation, expiry and replay issue no session. Cancellation racing completion can revoke the exact newly completed session.

Notify in console records a verified sign-in event and permits normal sign-in; administrators inspect the notifications tab. Email, SMS and external delivery are not implemented. Existing cookie, Bearer, permanent-token and AccessKey requests do not restart authentication under approval/notification actions; deny rules still apply to every request. These actions grant no additional permissions.

## API and credential boundary

- Browser sign-in returns HTTP 202, request ID and deadline, with no platform token or review ticket in JSON. The review ticket uses an HttpOnly, SameSite=Lax cookie on a dedicated path, with Secure on HTTPS.
- Non-browser password sign-in returns `review_token`, accepted only by POST `/api/v1/authentication/login-review/status`, `complete` or `cancel`. It is not an API identity credential. Submit the `review_token` body field; never put it in a URL.
- GET `/api/v1/authentication/login-review/pending` restores the original browser's waiting state. Status, completion and cancellation enforce Origin and the API-observed source.
- GET `/api/v1/login-reviews?state=pending&limit=25&offset=0` and GET `/audit` require review permission. POST `/{id}/approve` or `/{id}/deny` also checks reviewer assignment.
- Lists and audits contain no authentication proof, ticket, session token or digest. AES-GCM authentication proofs stay in the encrypted server review store. The initial unreturned session is revoked before HTTP 202. Only the random ticket's SHA-256 digest is retained.

## Standalone, HA and retention

Standalone uses encrypted `platform-login-reviews.json`; PostgreSQL single-active HA uses the shared `platform-login-reviews` document and the same Vault key. Requests already pending/approved after authentication continue after takeover. Incomplete SSO/Passkey authentication flows still restart. See [CLUSTER-HA](./CLUSTER-HA.en.md) for other shared-file requirements.

Up to 5,000 requests are retained. Terminal requests expire after seven days and may be removed earlier at capacity. Each user may hold five live requests, with 4,096 live requests globally. The latest 10,000 audit events are retained. Persistence failure returns no new session; failure to persist consumption revokes the just-created session.

Automation covers credential proofs/changes, ticket/source binding, one-use completion, denial/cancellation races, save rollback, encrypted restart, permission revocation, common SSO/Passkey gates, two-node takeover and bilingual browser flows. See [TESTING](./TESTING.en.md) for combined verification. Organization reviews, approval chains and external notification channels remain outstanding.
