# NEXUS SENTINEL — Focused code review (2026-11-10)

Scope: intelligence collector, radar frontend, FastAPI synthetic-lab backend, GitHub Actions CI. **scanner/** was not changed.

## High severity — fixed

1. **Snapshot integrity when every IP source fails** — Previously `main()` could overwrite a valid country snapshot with an unavailable indicator payload when CISA KEV still succeeded. The collector now refuses publication if all IP feeds fail, regardless of CISA status. Added an offline regression test.
2. **Local backend did not serve the active radar module** — `index.html` imports `radar-plus.js`, but FastAPI's public-asset allowlist omitted it, so a local deployment could show a blank map. Added the static asset to the backend allowlist.
3. **Misparsed CVE identifiers in Shodan enrichment and ransomware candidates** — Double-escaped regular expressions incorrectly rejected valid CVE IDs. Corrected the regex and validated CISA IDs before selection.

## Medium severity — fixed

1. **Unbounded graph identifier strings** — `Scenario` had array-length limits but no element-length bounds; added validation for source, target, disabled edges and nodes. This affects only the synthetic attack-graph endpoint, not the scanner.
2. **Feed format brittleness** — DShield malformed numeric fields could invalidate the entire feed; Feodo JSON wrapper formats were not accepted; non-dict CISA entries could break processing. Hardened parsers.
3. **Country trend comparisons** — A country trend could be misread when the successful source set changed. Trend and ranking now require matching successful feed sets, with visible explanatory labels.
4. **Large blank panel beneath the map** — The map card was stretched to match the taller sidebar grid column. Fixed with `align-items:start` and non-growing ranking.
5. **Repeated country clicks and scroll** — Previously repeated focus and scroll could move the page. The selected-country click is idempotent, and ranking scroll is scoped to the ranking panel.

## XSS / input review

- `radar-plus.js`, `radar.js`, `sentinel.js` and `app.js` were checked for `innerHTML`, `insertAdjacentHTML`, `eval`, `new Function` and `document.write`. No such calls were found in those files during this review.
- The radar uses `textContent`/DOM node creation for third-party strings. Links to CVE pages use URL-encoded IDs.
- FastAPI's public file route uses a fixed filename allowlist, and the attack graph checks that source/target nodes exist. Added size limits to graph identifiers.
- **Residual risk:** third-party JavaScript and geographic datasets are loaded from CDNs at runtime. Consider version pinning and Subresource Integrity / a strict Content Security Policy after a browser regression test.

## Testing / verification limits

The GitHub Actions CI workflow contains the exact command:

```bash
PYTHONPATH=.:sentinel python3 -m unittest discover -s sentinel -p 'test_*.py' -v
```

The working container could not clone GitHub because DNS/network access was unavailable. Therefore this review **does not claim that the Python test suite has executed successfully**. Check the GitHub Actions `NEXUS quality checks` workflow on the latest commit. JS syntax was parsed in the connector session; a browser-based regression test is still required.

## Notes

All active scanner files remain unchanged. The site is refreshed on a six-hour schedule, not live. Country changes represent list membership, not compromises. Third-party country-level CVE sample data is not a national exposure census.
