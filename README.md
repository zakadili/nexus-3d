# NEXUS SENTINEL — Global Threat Radar

**The homepage is now a geographic threat-intelligence observatory**, not a CVE search form. The previous live CISA KEV dashboard is preserved at [intel.html](./intel.html), and the evidence-linked synthetic attack graph remains at [sentinel.html](./sentinel.html).

## Live modules

| Module | What it actually does | Data provenance |
|---|---|---|
| **Global Radar** (`index.html`) | Rotating geographic globe, source-country ranking, source-IP drill-down, sampled report counters and top targeted ports | SANS ISC / DShield top-IP and top-port sensor summaries, enriched with approximate ipwho.is location |
| **CVE Intelligence** (`intel.html`) | CISA Known Exploited Vulnerabilities, filtering and FIRST EPSS lookup | CISA + FIRST |
| **SENTINEL Attack Paths** (`sentinel.html`) | Network/identity graph, potential path analysis, simulated remediation | Clearly labeled **synthetic** lab fixture |
| **Scope-Controlled Scanner** (`scanner/`) | Local TCP, HTTP-header and TLS checks against explicitly authorized IPs | Live results from your own authorized scan |

### Open the public radar

GitHub Pages: https://zakadili.github.io/nexus-3d/

The public page can request SANS and ipwho.is directly. **Browser CORS policies, provider rate limits, or upstream outages may prevent direct collection.** In that case, the UI shows a failure rather than fictitious telemetry.

## Run with a real local collector (recommended)

```bash
git clone https://github.com/zakadili/nexus-3d.git
cd nexus-3d
python3 -m venv .venv
source .venv/bin/activate
pip install -r sentinel/requirements.txt

# Optional but recommended: contact information for API provider's custom User-Agent
export NEXUS_CONTACT='your-public-contact@example.com'

python3 -m uvicorn sentinel.main:app --host 127.0.0.1 --port 8765
```

Then open: **http://127.0.0.1:8765/**

- **http://127.0.0.1:8765/** — Global Radar UI.
- **http://127.0.0.1:8765/api/radar** — backend-collected telemetry JSON.
- **http://127.0.0.1:8765/sentinel.html** — attack-path intelligence.
- **http://127.0.0.1:8765/intel.html** — original CISA KEV dashboard.
- **http://127.0.0.1:8765/docs** — FastAPI OpenAPI docs.

The Python collector uses a one-hour in-memory cache. It requests 30 ranked source IPs and 12 ranked port summaries from DShield and enriches the source IP locations with ipwho.is. It does **not** scan the displayed source IPs or any third party. Geolocation is best-effort and may be missing.

## Accuracy contract

- **A CVE has no country of origin.** NEXUS maps *observed source-IP infrastructure*, not where a vulnerability was discovered or successfully exploited.
- The numbers are for a small selected sample and are **not** global attack totals.
- Source network location is **not** attacker attribution.
- DShield reports may include benign research scanning and false positives; **do not use as a blocklist**.
- No fabricated attack arcs, victim locations, attack rates, or confirmed CVE exploitations.
- Historical data and samples are not a packet-by-packet real-time stream.
- SANS data has its own license; see [methodology](./radar-methodology.html). MIT applies to the software source, not externally obtained telemetry.

## Quality checks

A GitHub Actions workflow runs JavaScript syntax checks and Python unit tests for the graph model and feed parser.

```bash
PYTHONPATH=.:sentinel python3 -m unittest discover -s sentinel -p 'test_*.py' -v
node --check radar.js
```

## Interview demo

1. Open Global Radar and explain what every number actually measures.
2. Select a country to inspect observed IPs and report volumes.
3. Examine the independent top-port sensor telemetry.
4. Open CISA intelligence and inspect evidence for an actively exploited CVE.
5. Launch `sentinel.html` with the local FastAPI backend to demonstrate evidence-linked hypothetical attack paths and remediation simulation.
6. Run `scanner/nexus_scan.py` only on a machine explicitly within your authorized lab scope.

## Next roadmap

- Country-level vulnerability exposure data from an explicitly licensed provider, with coverage and time-window controls.
- Historical country and port time series with alert thresholds.
- Correlation between exploit *observations* and CVE records without fabricated attribution.
- Scoped authorized scanner result import into the attack graph.
- Self-hosted deployment, caching, and reliable monitoring.

**Status:** implementation committed; check Actions and live browser behavior before calling it production-ready.
