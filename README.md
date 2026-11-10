# NEXUS Hybrid — Threat Intelligence & Authorized Assessment

A working black-and-blood-red security intelligence dashboard, replacing the original fictional 3D network demo.

## What works now

- **Live CISA KEV**: fetches the real Known Exploited Vulnerabilities JSON catalog from CISA's GitHub mirror (fallback to CISA's official feed). Displays catalog size, recent additions, search and filtering by CVE/vendor/product/date/ransomware flag.
- **CVE investigation**: select a record to inspect the CISA description, required action, date and NVD link.
- **FIRST EPSS**: fetches exploitation probability on demand for the selected CVE.
- **CSV export**: download filtered KEV records.
- **Local assessment workbench**: import Nmap XML, list hosts and open ports, inspect service fingerprint information and jump to NVD research. Import parsing stays inside the browser; the app does not upload scan evidence.
- **JSON export**: download imported asset inventory.

## Run

Serve the repository root using a static web server:

```bash
python3 -m http.server 8000
```

Open http://localhost:8000. No build step required. Live intelligence requires network access and browser permission to fetch the public feeds.

## Authorized assessment example

Only scan systems you own or have explicit permission to assess:

```bash
nmap -sV -oX report.xml <authorized-target>
```

Open **ASSESSMENT LAB** and select `report.xml`. NEXUS parses it locally. A service version is **not** proof of a vulnerability, and KEV membership is **not** proof that a given host is affected.

## Data sources

- [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) / [CISA-maintained GitHub mirror](https://github.com/cisagov/kev-data)
- [FIRST EPSS API](https://api.first.org/data/v1/epss)
- [NIST NVD](https://nvd.nist.gov/) links for deeper research

## Limits

This is a **read-only threat-intelligence and offline evidence-analysis tool**, not a global internet scanner. It does not discover internet hosts, perform active vulnerability checks, exploit targets, or verify CVEs. The feeds may be temporarily unavailable because of provider rate limits, CORS policy, or network restrictions. It deliberately does not invent host geolocation, global exposure counts, or confirmed findings.

## Planned

- Authenticated backend with scope-validated asset ownership and rate-limited authorized checks
- Optional licensed external exposure-search integration
- Evidence-based version matching and triage
- Case history, reports, and interactive graph exploration

MIT licensed.