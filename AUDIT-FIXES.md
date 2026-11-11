# Public-site improvements — 11 November 2026

The public website keeps the NEXUS identity and existing research functions, with a task-based overview and a consistent navigation shell.

## Changes

- Three CVE candidates on the overview; detailed datasets, diagnostics, rankings and streaming are opt-in disclosures.
- Country details follow the map on phones. Country search moves focus to the result. All essential map controls remain available.
- Fixed asynchronous supplemental rendering. Healthy ASN results and genuinely empty IODA results are distinct from unavailable sources.
- Added modal focus containment, inert backgrounds, skip links, readable text, padded controls, explicit states, keyboard-scrollable tables and reduced-motion defaults.
- Unified catalog/workbench/lookup/methods navigation. Assessment links initialize the correct view. Legacy X-ray URLs forward CVE identifiers to the canonical workbench.
- Synthetic graph tracing and relationship-removal simulation work in-browser without a localhost backend or active scanning.
- Exact CVE matches rank before incidental description matches. Near-one EPSS estimates never round to an apparent 100%; collection now retains EPSS dates.
- Freshness, connection and feed coverage have independent labels. Unavailable source layers are labeled and disabled; their reasons remain visible in health details.
- Bundled selected D3/TopoJSON code, map geography and fonts. Lower-resolution overview geometry reduces geographic payload from approximately 756 KB to 108 KB; country search remains the precise selection path.
- Detail lists render when opened. Rotation pauses in background tabs. Streaming connects only after opening Live updates, pauses when hidden/collapsed, and avoids redundant frequent polling.
- Added about/help, glossary, feedback, privacy/data-flow disclosure and local-data clearing. CSP and no-referrer policies are delivered through HTML supported by GitHub Pages.
- Added canonical URLs, complete social metadata, original social card, favicon, robots.txt and sitemap.xml.
- Published missing licensed IOC lookup shards and full cleaned KEV records. The collector workflow now commits these generated files.
- Explicit Pages publication follows both code pushes and successful scheduled collections. This avoids the GitHub restriction whereby GITHUB_TOKEN commits do not trigger a branch Pages build. Public deployment packages exclude test fixtures, build dependencies and backend code.

- File-import controls and their browser parsing code were removed from the public site at the owner’s request. Exposure Lens now uses typed package identifiers. The assessment page provides guidance without accepting reports.

## Verification

- 43 existing Python regression tests passed locally.
- 10 JavaScript regression tests passed (including supplemental loading, probability formatting, exact CVE ordering, graph controls and lookup/export boundaries).
- JavaScript syntax, local links, metadata, CSP and data-index consistency checked.
- npm dependency audit reported zero known vulnerabilities at verification time.
- Browser checks cover desktop and 390-pixel phone layouts, country search/focus, catalog filtering, CVE research, graph controls, local lookup and typed package-version research.
- Automated axe checks were used to identify and fix accessibility defects. Automated checks do not constitute full screen-reader or WCAG certification.

## Operating boundaries

- URLhaus and ThreatFox geographic snapshots require operator-supplied feed access. This release does not invent credentials or replace unavailable data with zero.
- Third-party API uptime, coverage, terms and data quality remain outside the frontend's control.
- GitHub Pages does not provide arbitrary response-header configuration. HTML CSP/no-referrer policies do not substitute for server-side frame-ancestors or X-Frame-Options. Moving hosting is a separate infrastructure decision.
- No claim of perfect security, universal accessibility or field Core Web Vitals compliance is made.

## Maintenance

Use `npm ci`, then `npm run build:map` after mapping dependency changes. Run `node scripts/version-assets.mjs` after asset edits. Run `npm test`, `npm run check`, and the Python regression suite before publishing.

The checked-in map bundle is deployable without installing Node dependencies in production. Provider licenses and asset attribution are retained in `assets/` and the methodology page.
