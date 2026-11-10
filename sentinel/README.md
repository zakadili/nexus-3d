# NEXUS SENTINEL — Full Hybrid Vertical Slice

**Implemented:** local FastAPI backend, evidence-linked hybrid network/identity graph, breadth-first path calculation, interactive SVG graph, and remediation simulation. The supplied lab is explicitly **synthetic** and deterministic.

## Run locally

```bash
git clone https://github.com/zakadili/nexus-3d.git
cd nexus-3d
python3 -m venv .venv
source .venv/bin/activate
pip install -r sentinel/requirements.txt
python3 -m uvicorn sentinel.main:app --host 127.0.0.1 --port 8765
```

Open **http://127.0.0.1:8765/**. API docs: http://127.0.0.1:8765/docs

Select **TRACE ENTRY → DC**, then choose **admins → dc** under remediation and press **SIMULATE CONTROL**. The modeled path should disappear. Try **api → db** instead; the path should remain.

## Tests

```bash
PYTHONPATH=sentinel python3 -m unittest discover -s sentinel -p 'test_*.py'
```

## API

- `GET /api/health` — health
- `GET /api/graph` — nodes, edges, fictional evidence
- `GET /api/evidence` — lab findings and supporting relationships
- `POST /api/paths` — shortest path under selected edge/node restrictions
- `GET /api/remediations` — simulated impact of removing each edge

## What is real vs. simulated

The graph algorithm, API, remediation calculations, and UI interactions are real software. The eight lab entities, their relationships, and their evidence IDs are synthetic fixtures. **Graph reachability does not prove a feasible exploitation chain.** No attack payloads are executed. The separately implemented `scanner/nexus_scan.py` performs authorized active port/TLS/HTTP checks; it is not yet wired into the graph model. Nmap XML import and CISA KEV/EPSS research remain in the existing `index.html` dashboard.

## Next engineering steps

1. Convert Nmap XML and scoped scanner JSON to normalized, provenance-tagged graph edges.
2. Import authorized AD group membership/ACL exports.
3. Evidence quality gates and attack precondition modeling.
4. Persistence and multi-lab workspaces.
5. Containerized isolated test environment and CI.
