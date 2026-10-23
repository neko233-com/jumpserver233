# Project UI design and oil-ui

> English | [中文](./UI-DESIGN.md)

2026-10-23 [complete Web redesign](./WEB-REDESIGN.en.md) is live in v0.4.0: implemented and accepted 10/10, zero remaining gates. Full CI passed 6/6 and production browser regression 72/72. BuildWorld [1078 / #10](http://192.168.110.42:8080/builds/1078) activated once; login, real Web/native SSH, file round trips, monitoring and original data retention passed. The dedicated `poke-game/deploy-jumpserver233` repository uses `Jenkinsfile_mac_single` and closes connections gracefully during upgrades. Historical acceptance follows.

## Installation and provenance

At the user's request, the bundled `skills/oil-ui` from [oil-oil/dsh-oil-ui](https://github.com/oil-oil/dsh-oil-ui) is installed at `.agents/skills/oil-ui/` for this project. The source is pinned to commit `b67ae2df6c2c9d65e177aaa1ce703e65457b24d7`; the declared skill version is `0.23.8`. `.agents/skills/oil-ui.source.json` records provenance and each file's SHA-256. Upstream text, `LICENSE` and font licensing remain intact.

Installation uses skill-installer's `install-skill-from-github.py` with `--repo oil-oil/dsh-oil-ui --path skills/oil-ui --ref b67ae2df6c2c9d65e177aaa1ce703e65457b24d7 --dest <project>/.agents/skills --method download`. The global skill directory is unchanged; no DeepSeek Harness plugin or npm runtime dependency was added. Project discovery is available next turn; this turn reads and applies the skill directly.

The native `oil_ui_*` tools belong to DeepSeek Harness. Codex uses its available file, browser and image tools for corresponding steps without claiming unavailable tools exist. No automatic skill update, paid service, media collection or recommendation script runs. Vendored fonts, images and tooling do not enter frontend dependencies; `.agents/` is excluded from Docker context.

## Console direction

**Help operators find a host, then connect, inspect or authorize an operation.** Keep the user's dark SSH-management reference and existing branding. Use a compact, quiet interface for extended operational work. Real assets and monitoring values lead; there are no additional marketing sections, decorative images, external fonts or animation libraries.

- The mini console foregrounds hosts, monitoring, rotation, Agent/login audit, users/roles, access policies and maintenance. Seventeen cloud, AI, complex identity and related Enterprise pages leave the default routes/build graph; source, backend permissions/APIs and data remain. Reports and less frequent local controls move behind “More features”. Search only finds shipped pages and cannot expose dead links.
- Search filters currently visible page labels, with an empty state, clear action and restored focus. It is not a global data search. Labels follow the current language without a reload.
- Desktop retains an independently scrolling sidebar. At 760px and below, a native button expands navigation; selecting a page collapses it to preserve room for assets and content. Escape clears search first, then closes the menu and restores its trigger.
- Add a skip link, visible keyboard focus, current-page indication and announced search results. Long labels wrap. Existing branding remains the color authority.
- Asset table body text becomes 13px; addresses and monitoring values use tabular numbers. Reports avoid duplicate page padding and share consistent filter, table, numeric and export controls. Playbook controls use brand variables while source editing stays monospace.
- Frequent actions get only 120ms color feedback, honoring `prefers-reduced-motion`. No blocking entrance animation, extra polling or renderer dependency is introduced. Existing business explanations, permission context and audit evidence remain.

## Verification boundary

### Native SSH table workbench

The user requests modern interactive CLI response and rejects v0.3.1's low-contrast hints. The native interface centers on a selectable host table: highlighted selection, clear headers, adjacent details and readable key hints. Background is `#0f111c`, body `#e8edf7`, secondary text `#b4c1d7`, accent `#69dfe0`. Text and separators have at least 4.5:1 contrast against the fixed background. Explicit RGB escapes avoid client ANSI dark-gray palettes that make text disappear.

A native Go state model handles arrows/Tab, Enter, immediate UTF-8 search, paging, Esc, paste protection and resizing, redrawing only changed rows. No PTY or `TERM=dumb` retains line input. Inventory reads asynchronously; searching makes no network requests and cancellation ends pending reads. Target shells restore the normal screen/cursor, then return to the list.

All six local gates passed unified verification: full backend, two Linux race runs, three real OpenSSH relay/monitor/SFTP runs, Docker browser and restart regression. The 112 bilingual dimension cases check bounds; wide, narrow and English rendering were inspected. Independent visual review confirms clear headers, selection and alignment. Its refinement emphasizes only Enter while keeping other hints readable. Earlier English help wrapping prevents the shared label limit from hiding the last shortcut.

`TestNativeWorkbenchExportVisualCases` exports actual Go ANSI frames. `scripts/native-workbench-preview.mjs` displays them using the existing xterm renderer. This preview is not actual XTerminal button acceptance. Reports and at most two screenshots stay ignored under `.cache/qa-reports/`. v0.3.2 upgraded the new UI once; BuildWorld #9 (1041), real SSH/SFTP, monitoring and restart retention passed, alongside 70/70 full production browser cases.

### Existing Web console baseline

Production browser **55/55** passed. The repaired console passed **1600/1440/1280/900/715/375px × English/Chinese**, including real fixture metrics, actions inside the table, desktop row height ≤128px, search/clear/Escape/focus, current-page state and mobile navigation. Exactly two screenshots were retained for this focused batch; the Chinese desktop capture was visually inspected. The in-app browser independently confirmed bilingual inventory and real SSH-fixture CPU/memory/network/disk data.

At 1001–1600px the sidebar is 176px; monitoring uses four compact rows and actions remain visible. The native browser also verifies the accessible directory input and bilingual desktop/mobile operation form. This is functional/rendered acceptance without an invented visual score. Source and reports: [mini acceptance](./MINI-ACCEPTANCE.en.md).

Linux Chromium showed inconsistent native anchor focus. Explicitly focus main content and close mobile navigation, with repeated keyboard activation coverage. The focused rerun passed in 15.0s.
