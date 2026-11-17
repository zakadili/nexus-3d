# NEXUS — 5-minute collaborator dashboard demo

**Canonical homepage:** https://zakadili.github.io/nexus-3d/\n\nThe previous `/collaborator-demo.html` address redirects to the homepage. Superseded enterprise UI preview files were removed.

The NEXUS homepage is a static GitHub Pages enterprise dashboard with a separate fictional customer workspace. It does **not** require VPS credentials, a database, commercial feed access or a customer account.

## What is real now
- Public-source indicator counts, observed collection history, country-code allocations and source status from the checked-in `data/overview.json` snapshot
- CISA Known Exploited Vulnerabilities catalog counts and a collector-ranked subset of CVE research candidates, with optional EPSS values
- Collection timestamps, freshness warnings, published source attribution and missing-data states

These records **do not** demonstrate customer exposure, confirmed attacks, successful exploit attempts, or remediation.

## What is simulated
The sidebar **Demo Workspace** uses reserved `.example.test` domains for fictional Aster Labs. Its three assets and workflow stages illustrate the product experience, not a vulnerability scan. No customer security posture, affected asset count, exposure score or change ticket is represented as real.

## How to show it in five minutes
1. **30 seconds — Executive Dashboard:** explain that each KPI is tied to an actual source and collection time; numbers fail closed if the snapshot cannot load
2. **60 seconds — Priority CVE Research:** open a linked CVE, describe the distinction between CISA KEV, EPSS probability, and confirmed customer vulnerability
3. **60 seconds — Source Coverage & Global View:** explain the segmented *collector availability* gauge, historical indicator counts, and IP **allocation** map (not attack origin)
4. **90 seconds — Demo Workspace:** select a fictional asset and advance the simulated evidence/remediation steps; call out that ownership proof and tenant isolation are still to be built
5. **60 seconds — Build Roadmap:** discuss engineering ownership for authenticated asset onboarding, evidence-backed findings, verifiable remediation and scoped customer reports

## Engineering notes
- UI: `index.html`, `collaborator-demo.css`, `collaborator-demo.js`
- Published snapshot adapter: `enterprise-v2-intelligence.mjs`
- Map: existing local `assets/countries-110m.json`, `assets/country-codes.json`, and bundled `assets/map-vendor.js`
- Data fetches remain same-origin and subject to the page Content Security Policy
- This branch does not change the production homepage, collectors or Python backend
- Before sharing publicly: check the latest GitHub Pages publish and review whether the snapshot is fresh enough to make collection-time claims

### Demo limitations
- The current GitHub Pages environment is *snapshot-backed*, not a true real-time command stream
- Source-health statuses are reported **as of collection**, not continuous availability checks
- Retired Feodo data remains historical and must not be shown as a current live source
- Top country counts are approximate IP assignments; they cannot be interpreted as attacker geographic origin
- Real customer asset inventory, tenant authentication, scanning authorization, exposure scoring and reporting are not yet implemented
