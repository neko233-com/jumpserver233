# Upgrade compatibility scope

> [中文](./UPGRADE-COMPATIBILITY.md) | English

## Support baseline

On 2026-10-20 the GitHub Release API check (`gh release list --repo neko233-com/jumpserver233 --limit 100 --json tagName,publishedAt,isDraft,isPrerelease`) returned an empty list; there are also no local release tags. No historical formal release archive exists, so formal-release-to-current migration cannot be claimed as accepted.

The pinned historical source baseline is `4367285202054181344e386096b89e8ea3059703`, used by the existing native Linux upgrade rehearsal. Versions `v0.0.0 → v0.0.1` identify isolated rehearsal packages without publishing a Release. Verify that source against this candidate with `node scripts/native-package-qa.mjs --batch ssh-stable-closing --historical`; [verification](./TESTING.en.md) records actual results. This document specifies constraints and does not label new cases as passed.

The first formal stable release establishes the published-version baseline. Each later stable release must identify the preceding stable tag, source SHA, archive SHA and format, retaining real upgrade, export/import and rollback evidence. Renumbering two builds of identical source does not establish cross-version migration. Unverified historical versions have no compatibility promise, and users must not be required to discard data and recreate assets.

## Formats and rejection

| Object | Current support boundary | Handling unsupported input |
|---|---|---|
| Native archive | Manifest schema 1; controlled installation requires preflight/activation protocol 1 | Staging checks every path, digest, platform and permission; incompatible protocols refuse installation |
| Business data | Target opens and validates known formats per module; each module owns semantic migration | Unknown/corrupt/oversized formats fail offline preflight; source-version strings do not establish compatibility |
| Jobs | Encrypted envelopes 1–6; directory proofs require v6 | New JSON fields in old formats cannot enable directory execution semantics |
| Batch/schedules/Playbooks | Encrypted envelopes 1–5; nonempty directory snapshots require v5; native Playbooks require v4+ | Read valid original v1–v4 records; reject directory fields in those versions; normal mutations write v5 |
| Full-site backup | Archive format 1, integrity and Vault-key binding | Wrong passphrases, unknown formats, unsafe paths or corrupt archives do not overwrite business data |
| Native enterprise notifications | Existing notification envelope 1 gains provider configuration and encrypted settings receipts; new code reads older documents with these fields omitted | Older programs are not guaranteed to read new fields; downgrade requires the pre-upgrade data snapshot without deleting new configuration or receipts |
| Downgrade | Managed installations reject downgrade, different builds of the same version and data-directory rebinding | Restore the old checkpoint before activation; retain new data and repair forward after activation |

Old programs generally cannot read new formats. Replacing only executable files is insufficient for rollback. After operation directories first write v5, returning to a v4-only program requires its matching old checkpoint; old software must not silently ignore directories and execute.

## Fixed acceptance evidence for this batch

- A real historical service creates users, grants, seven-day rotation times, SSH audit, a command template and a one-time plan. After upgrading, check identities, authorization, credential key, schedule times and snapshots, then execute real SSH.
- Change the operations envelope to future version 999 and use the actual install transaction. Target preflight must reject it, preserving original bytes and selection. Restore known valid input and upgrade; identical repeated requests return the original receipt.
- Read valid operations documents from every v1–v4 envelope and write v5. Forged directory fields in old envelopes must fail without changing the original file.
- Failed first startup restores old data/service; post-activation failure retains new writes. Existing unified entrypoints cover backup import, repeated restore, revision conflict, approval replay and resource cleanup.

Offline preflight opens no port, background task or remote business operation. Backups still require downtime; online backup, PostgreSQL cluster backup, production multi-active operation and arbitrary migration among all historical versions remain open. See [fixed progress](./PROGRESS.en.md).
