# NEXUS 1.0 — Interactive Network Universe

A cinematic black-and-blood-red 3D cybersecurity **simulation** built with Three.js and vanilla JavaScript. Explore eight fictional hosts, animated network connections, click-to-inspect nodes, and a functional command console.

## Run locally

```bash
python3 -m http.server 8000
# Open http://localhost:8000
```

Requires internet access to load Three.js from esm.sh and fonts from Google Fonts. No npm installation required.

## Controls

- Drag to orbit; scroll to zoom; click a node to inspect it.
- Terminal: `help`, `hosts`, `inspect web`, `focus db`, `links`, `scan`, `pulse`, `reset`, `clear`, `about`.
- The `scan` command only prints built-in fictional data. **No live network scanning or backend is included.**

## Deploy

Upload these files to a new GitHub repository, then deploy with GitHub Pages (Settings → Pages → Deploy from branch → main / root), Cloudflare Pages, or any static host.

## Security and privacy

All hostnames, IPs, ports, and findings are simulated. There are no credentials, forms transmitting data, external scan requests, or server-side processes. The application loads Three.js via a third-party CDN; for production hardening, vendor and pin the dependency locally and set a restrictive CSP.

## Next milestones

1. Editable topology and JSON import/export.
2. Time-travel playback of simulated security events.
3. Evidence-linked findings and an investigation timeline.
4. Optional authenticated backend for explicitly scoped, authorized scans.

MIT License.