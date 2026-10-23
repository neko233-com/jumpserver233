# Web operations workspace redesign

> English | [中文](./WEB-REDESIGN.md)

## Goal and boundaries

On 2026-10-23 the user requested a complete Web UI and UX redesign. The direction is a clear, compact dark operations workspace: hosts, SSH, files and monitoring first, with security reviews and maintenance remaining accessible. Reuse the project oil-ui skill, administrator branding and existing authorization. Add no runtime dependencies or Enterprise extensions. The mini 12/12 and v0.3.2 native table 6/6 remain historical acceptance, counted independently.

## Complete implementation batch

| Gate | Delivery | Status |
| --- | --- | --- |
| W01 | Shared colors, typography, spacing, tables, controls and dialogs across shipped pages | Accepted |
| W02 | New login page, readable authentication states, existing login/MFA/branding flows | Accepted |
| W03 | Grouped icon navigation, current location, mobile navigation and table density preference | Accepted |
| W04 | Ctrl/⌘ K search of authorized host names/descriptions/IPs and pages; keyboard/empty/error states | Accepted |
| W05 | Host status filters, name/latency/CPU sorting, reset, counts and last update time | Accepted |
| W06 | SSH font controls, expand/restore and retry; remote Esc and existing review/recording protocol | Accepted |
| W07 | Directory search, relative path navigation, refresh/retry and download feedback; existing transfer audit | Accepted |
| W08 | Settings section search, keyboard tabs, dialog focus containment/restoration, accidental draft dismissal protection | Accepted |
| W09 | Chinese/English, desktop/narrow, 200% equivalent reflow, reduced motion and all reachable page regression | Accepted |
| W10 | Unified lint/build/browser/Docker validation, independent visual review and repeatable owned cleanup | Accepted |

**Implemented and locally accepted 10/10; zero gates remain in this Web batch.** No commit, push or release was performed. Production v0.3.2 keeps its existing identity. Mini and native SSH gates remain independent historical counts.

## Interaction contracts

- Sidebar search filters pages. Top quick search uses pages and authorized assets returned by the current organization API. Selecting a host opens its filtered inventory without creating a remote session. Closing the dialog aborts its host request.
- Collections can collapse. Online/offline/unknown values come from the server. Missing metrics are never invented. Filtered empty results and an inventory with no assets have distinct messages.
- Table density persists only a local appearance preference. Terminal font and size changes do not create sessions. Esc goes to the remote shell while terminal input is focused; the close button ends the session.
- File navigation uses existing server workspace boundaries, without expanding directory access. Search filters only the current directory. Transfers retain review, one-time session and audit controls.
- Esc or backdrop dismissal confirms discarding an asset draft. Explicit Cancel discards it. Saving blocks Esc/backdrop dismissal. Secrets never enter local preferences or reports.
- Modal dialogs contain Tab and restore focus after closing. Tabs support arrow keys and Home/End. Loading, empty, error and retry states remain readable.

## Verification and resources

Reuse isolated API/SSH fixtures and automatic cleanup in `pnpm test:e2e:production`. `web/e2e/web-workspace.spec.ts` covers real SSH/files entry points, quick search, same-page destinations, draft protection, density persistence and overflow checks across 25 page paths × two languages × two viewports. Existing complete cases continue to cover authorization, command reviews, file round trips, monitoring and data retention. Report case counts independently from the ten gates.

Keep compact reports and at most two essential screenshots in ignored `.cache/qa-reports/`. Remove this batch's temporary data, processes and Docker resources after validation. Repeated cleanup must be safe and must preserve business data and other projects.

## Acceptance results (2026-10-23)

- Full production regression contained 72 cases: initially 67 passed, two failed and three skipped. The affected 11-case run then passed nine and failed two; the final affected run passed 3/3. Taking the latest result per title closes 72/72, with no unresolved failure or skip. Repairs covered header interception of dialogs, search accessibility naming, row height and the SFTP fixture.
- 25 page paths × two languages × desktop/narrow produces 100 page layout checks. Real SSH keyboard/font/expand, SFTP upload/download byte comparison, quick search, draft protection and existing permission/review/monitoring regressions also passed. Edge checked the final navigation-collapse and unmatched-settings feedback in the final Docker build.
- Edge covered 1440×1000, 375×900 and 720×500 for 200% equivalent reflow, rather than native browser zoom. The first mobile host starts around y=282, Connect is 44px high, host titles use 14px and supporting information 12px. Full host and port remain readable.
- Independent oil-ui visual review covered only desktop/mobile host screenshots: initial 7/10, then no must-fix issues after four required repairs and the duplicate chevron fix. Other pages were covered through Edge interaction and automated regression, without claiming independent scores per page.
- Lint has no errors and five existing warnings. Type, build and content checks passed: 4421 keys per language and 206 bilingual documents. Initial JavaScript is 498294 bytes, gzip 160778 bytes and total JavaScript 1645144 bytes. Existing bundle budgets and dependencies are preserved.
- Isolated Docker passed default administrator login, native SSH/SFTP, raw forwarding denial and host-key/data retention after restart. Browser temporary data was removed. Owned containers, volumes, networks, SSH fixture processes, temporary binaries, raw logs and redundant screenshots were removed; repeating cleanup verified idempotency. Only compact reports and two essential screenshots remain.
- Compact evidence is in ignored `.cache/qa-reports/web-redesign-20261023/summary.json`. Three browser summaries retain failure causes and cleanup receipts. This Web acceptance does not claim a new full Go/race run or a production upgrade.
