# NEXUS SENTINEL — Global Cyber Intelligence

A working multi-source cyber-intelligence command center: an interactive country-level threat-indicator globe, CISA exploited-CVE prioritization, reported EU sector impact, authorized active scanning, and an evidence-linked attack-path lab.

**Live project:** https://zakadili.github.io/nexus-3d/

## Investigation experience (v0.3)

The homepage is built for an actual on-screen investigation, not merely browsing threat lists:

- **Click a country:** smooth orthographic camera fly-to and country-focused HUD. Even unrepresented countries can be selected, with an honest "no observed coverage" message.
- **Country dossier:** total unique listed IPs, exact per-provider counts, rank, cross-feed overlap, sampled attributed IP evidence, and explanatory context. Evidence records can be investigated further using an on-demand **ipwho.is ASN/ISP/city lookup** and a SANS IPinfo link. Sample addresses are not a full inventory.
- **COUNTRY SEARCH:** press **Ctrl/⌘ + K** to jump to a country, or browse the complete ranked list. Mouse-wheel zoom and drag orbit are supported.
- **COMPARE:** pin one country, select another, then pin it to compare source-by-source listing volumes. Counts reflect feed coverage and should not be treated as comparative attack risk.
- **HISTORY:** the scheduled collector retains up to 28 recent country-count snapshots. A dossier sparkline appears when at least two comparable samples exist using the same set of successful feeds. Changes mean listing membership changes, not new compromises.
- **SHARE & EXPORT:** share deep links like `?country=MA&layer=ipsum`, export an evidence-labeled country brief, or **CAPTURE MAP** as a high-resolution PNG for X and presentations.
- **CINEMATIC TOUR:** a six-country, evidence-backed global camera tour for demonstrations, including stop and immersive-mode controls. The tour only visits countries present in the real data.

**Note:** country geolocation is approximate network allocation. It cannot identify where a specific attacker lives, prove that a device is vulnerable, or supply all malicious traffic observed in a country.

## Intelligence platform

### Multi-source country radar

GitHub Actions collects and deduplicates public IPv4 indicators from:

1. [blocklist.de](https://www.blocklist.de/en/export.html) — addresses reported during the last 48 hours.
2. [IPsum](https://github.com/stamparm/ipsum) — IP addresses appearing on at least three constituent lists.
3. [SANS ISC / DShield](https://isc.sans.edu/) — a sample of observed source addresses from reporting sensors.
4. [abuse.ch Feodo Tracker](https://feodotracker.abuse.ch/) — observed online botnet C2 infrastructure; its active feed may be empty.

Countries are inferred from the [DB-IP Lite](https://db-ip.com/) country range database (CC BY 4.0), distributed by [sapics](https://github.com/sapics/ip-location-db). The data pipeline uses IP-range binary search; it does **not** send tens of thousands of addresses to a per-IP lookup API.

**First successful collection, November 10, 2026:** 37,985 distinct listed IPv4 indicators, 37,983 country-matched, 159 countries; 25,874 blocklist.de records, 17,226 IPsum records, 300 DShield sample IPs, 1 online Feodo C2. These are source-list counts, **not global attacks**. Numbers change as feeds update; current counts are shown in the dashboard.

Use the map's **DATA LAYER** selector to compare source-specific coverage and select a country for counts from every provider. Source subtotals overlap, so do not sum them.

### Vulnerability priority engine

- [CISA Known Exploited Vulnerabilities](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) full catalog.
- [FIRST EPSS](https://www.first.org/epss/) for selected recent or ransomware-linked candidates.
- [NIST NVD](https://nvd.nist.gov/) CVSS for a small number of top-ranked CVEs, respecting public rate limits.
- Transparent ordering heuristic: EPSS probability × 100 + 25 if CISA identifies known ransomware use + 10 if added in the last 30 days.

This is **not** a CVSS rating or exploit validation for a host. The user must interpret asset exposure and business impact separately.

### Industry impact research

The [ENISA Threat Landscape 2026](https://www.enisa.europa.eu/topics/cyber-threats/threat-landscape) provides historically observed incident shares for EU sectors over January–December 2025, not live worldwide sector counts. Top entries include public administration 31.8%, business services 8.5%, transport 8%, manufacturing 6.9%, and finance/banking 5.6%.

### Other modules

- [CVE Intel](./intel.html) — searchable CISA catalog with on-demand EPSS.
- [SENTINEL Attack Graph](./sentinel.html) — synthetic network/identity relationships and remediation simulation, backed by FastAPI.
- [Scoped Active Scanner](./scanner/) — real authorized TCP/HTTP/TLS checks with explicit CIDR allowlisting.

## How the live website works

A workflow at [`.github/workflows/intelligence.yml`](./.github/workflows/intelligence.yml) runs **every six hours** (also manually triggerable), runs [`sentinel/intelligence_pipeline.py`](./sentinel/intelligence_pipeline.py), and commits the JSON snapshot to [`data/overview.json`](./data/overview.json). The GitHub Pages homepage reads this committed JSON without needing API keys or a hosted backend.

The snapshot includes independent feed-health statuses. If a source fails, that source is explicitly marked unavailable; if no source succeeds, the snapshot is not overwritten. This is periodically updated intelligence, **not a live packet stream**.

## Run locally

```bash
git clone https://github.com/zakadili/nexus-3d.git
cd nexus-3d
python3 -m venv .venv
source .venv/bin/activate
pip install -r sentinel/requirements.txt
python3 -m uvicorn sentinel.main:app --host 127.0.0.1 --port 8765
```

Open http://127.0.0.1:8765/ for the global radar and http://127.0.0.1:8765/sentinel.html for the attack-path lab.

To regenerate the snapshot manually on a networked machine:

```bash
python3 sentinel/intelligence_pipeline.py
```

To run the tests:

```bash
PYTHONPATH=.:sentinel python3 -m unittest discover -s sentinel -p 'test_*.py' -v
node --check radar-plus.js
```

## Professional interpretation & ethics

A public IP on a suspicious-IP list is **not proof of malicious ownership**, a country code is **not attacker attribution**, and a CISA-listed CVE does **not prove any specific host is vulnerable**. Sensor-based rankings can be heavily biased by where sensors are deployed and what protocols they observe. Sectors use a dated ENISA EU study and are not combined with unrelated sources to create false global totals.

Read the full [methodology and licenses](./radar-methodology.html). The code is MIT licensed; third-party intelligence data retains its providers' own terms (including SANS attribution/noncommercial obligations and DB-IP attribution).

## Next milestones

- Longitudinal country trends and change detection across snapshots.
- Licensed country-level *vulnerable-device exposure* statistics to complement suspicious-IP infrastructure maps.
- Verified asset context (authorized scans, owned domains, confidence & provenance).
- Incident case builder and report generator.
- Advanced global map overlays and real-time event ingestion from an authorized honeypot fleet.
