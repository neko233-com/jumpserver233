# Automatic standalone preparation and installation

> [中文](./AUTOMATIC-UPDATES.md) | English

Managed native installation supports Off, Prepare only, and Install within a maintenance window. Default is Off. The existing `jms update supervise` checks official stable Releases, downloads and stages candidates, then uses [scheduled installation](./INSTALLATION-SCHEDULE.en.md) for drain, shutdown, encrypted checkpoints and first-start acceptance. Release checks, prepared candidates and accepted installation are separate evidence levels.

## Configuration

Adopt a [standalone baseline](./INSTALLATION.en.md), then run the supervisor with a private checkpoint passphrase file and persistent revocable platform identity. Web: Settings → Security → Software updates → Automatic release preparation and installation. Global `security.manage` is required; operators and organization administrators cannot configure it.

```sh
jms update auto-status --root /srv/jumpserver233-releases
jms update auto-policy --root /srv/jumpserver233-releases --revision 1 --request-id prepare-policy-001 --mode prepare --interval-hours 24
jms update auto-policy --root /srv/jumpserver233-releases --revision 2 --request-id install-policy-001 --mode install --hour-utc 2 --minute-utc 0 --window-minutes 30 --drain-timeout 600s
```

- `off` makes no automatic release requests. Manual/published-release check policy remains independently configured.
- `prepare` checks, downloads, fully verifies and stages; it never executes candidate programs, creates upgrade checkpoints or switches data.
- `install` queues one digest-bound plan during the daily UTC window. Windows may cross midnight and do not follow host timezone/daylight-saving changes. Preparation retains its independent hourly interval.
- Intervals: 1–168 hours; window: 5–180 minutes; drain wait: 5–86400 seconds. Policy edits may advance a check, but never before one minute after the last attempt; subsequent attempts follow the hourly interval.
- Shutdown cannot be committed outside the window. Window expiry, disabling or changing policy revokes uncommitted automatic plans and reopens admission only when the original drain instance/revision still matches. Policy changes conflict once automatic shutdown is committed; installation proceeds to acceptance/recovery.
- Manual plans take priority. Preparation runs in the background; a due manual installation cancels and waits for its owned preparation task. Network/preparation failures retain the running service and persist the next check time.

## Provenance and trust

Production URLs are fixed to the official `neko233-com/jumpserver233` GitHub HTTPS API/Release assets; custom feed URLs are unsupported. Accept only stable `vX.Y.Z`, non-draft/non-prerelease metadata, same-platform uploaded archives, bounded sizes and `sha256:` digests. Download rechecks the named version and requires the complete resource identity to match initial selection. See [GitHub Release API](https://docs.github.com/en/rest/releases/releases?apiVersion=latest) for endpoint/asset digest fields.

Verify the archive, manifest and every file again. The target must be newer and declare preflight/activation protocols. Preparation never executes package programs. Unknown versions, missing platform archives, corrupt bytes, changed version/digest, unsupported protocols, network failures or rate limits cannot create an installable candidate. Upstream identity and OS TLS trust remain boundaries; arbitrary same-user modification of CAs, programs or the managed root is outside isolation.

Platform credentials authorize the local child maintenance API and are never forwarded to Release requests. The supervisor checks current permission, standalone capability and its own child PID. Short standalone sessions expire on restart; long-running supervision uses persistent revocable credentials. Existing private-file checkpoint passphrase rules apply; secrets are absent from policy and reports.

## Receipts, cancellation and recovery

`GET/PUT /api/v1/settings/security/updates/installation/automatic`, plus SDK `AutomaticUpdateStatus` / `SaveAutomaticUpdatePolicy`, expose policy, phase, last/next attempts, verified candidate and recent activity without credentials/passphrases. PUT contains `request_id` and `policy`: `revision`, `mode`, `interval_hours`, `hour_utc`, `minute_utc`, `window_minutes`, `drain_timeout_seconds`.

Private `.jms233-automatic.json` stores policy/times/candidate and the latest 100 receipts/events. Identical request ID, original input and actor returns current state without restoring old modes. Changed input/actor and stale new requests conflict. Policy revisions bind one-shot plans; root-lock validation at drain/stop transitions prevents revocation from overriding committed shutdown.

Each policy revision/digest is attempted once; failure/restart never reinstalls it. A separate current-policy list retains up to 100 attempted digests independently of schedule receipt retention; reaching the limit requires an explicit revision. Reserve the attempt before publishing its one-shot plan. Interruption between files retains the reservation and requires inspection/new authorization. Inspect installation/recovery receipts, then explicitly save a new policy revision to authorize another attempt. Changed installation revisions require renewed candidate binding; historical compatibility is never inferred.

Downloads use private `.jms233-maintenance/prepare-ID/` receipts bound to root, run ID and digest. Success/failure/cancellation removes owned temporary archives. On restart, the supervisor OS lock permits cleanup only of provably owned previous preparations. Unknown directories/receipts/links are preserved and preparation is refused. Cleanup is idempotent; immutable published trees follow managed-release retention rules.

See [verification records](./TESTING.en.md) for native/isolated evidence. Docker-image/cluster updates, genuine historical migrations and complete Enterprise parity require separate acceptance. This feature creates no Git tag, Release or changelog.
