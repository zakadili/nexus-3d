"""NEXUS SENTINEL: evidence-backed attack-path modeling and remediation simulation.
The bundled lab is SYNTHETIC. No scanning or exploitation is triggered by this API.
"""
from collections import deque
from copy import deepcopy
from pathlib import Path
import json
import os
from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse
from sentinel.radar_feed import snapshot
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field, field_validator

ROOT = Path(__file__).resolve().parent
DATA = json.loads((ROOT / "lab.json").read_text(encoding="utf-8"))
app = FastAPI(title="NEXUS SENTINEL", version="0.1.0")
app.add_middleware(CORSMiddleware, allow_origins=["http://localhost:8000", "http://127.0.0.1:8000", "http://localhost:5173", "http://127.0.0.1:5173"], allow_methods=["GET", "POST"], allow_headers=["Content-Type"])

class Scenario(BaseModel):
    source: str = Field(default="internet", min_length=1, max_length=80)
    target: str = Field(default="dc", min_length=1, max_length=80)
    disabled_edges: list[str] = Field(default_factory=list, max_length=100)
    disabled_nodes: list[str] = Field(default_factory=list, max_length=100)

    @field_validator("disabled_edges", "disabled_nodes")
    @classmethod
    def validate_items(cls, values: list[str]) -> list[str]:
        if any(not isinstance(item, str) or not 1 <= len(item) <= 160 for item in values):
            raise ValueError("Each graph identifier must be a nonempty string of at most 160 characters")
        return values

def edge_key(e):
    return e["source"] + "->" + e["target"]

def shortest_path(data, source, target, disabled_edges=(), disabled_nodes=()):
    nodes = {n["id"] for n in data["nodes"]}
    if source not in nodes or target not in nodes:
        raise ValueError("Unknown source or target")
    disabled = set(disabled_nodes)
    if source in disabled or target in disabled:
        return []
    blocked = set(disabled_edges)
    adjacency = {n: [] for n in nodes}
    for e in data["edges"]:
        if edge_key(e) not in blocked and e["source"] not in disabled and e["target"] not in disabled:
            adjacency[e["source"]].append(e["target"])
    queue = deque([[source]])
    visited = {source}
    while queue:
        path = queue.popleft()
        if path[-1] == target:
            return path
        for nxt in adjacency[path[-1]]:
            if nxt not in visited:
                visited.add(nxt)
                queue.append(path + [nxt])
    return []

def analyze(data, scenario):
    path = shortest_path(data, scenario.source, scenario.target, scenario.disabled_edges, scenario.disabled_nodes)
    lookup = {(e["source"], e["target"]): e for e in data["edges"]}
    steps = [lookup[(a, b)] for a, b in zip(path, path[1:])]
    return {"source": scenario.source, "target": scenario.target, "path": path, "steps": steps,
            "reachable": bool(path), "hop_count": max(0, len(path)-1),
            "interpretation": "Graph reachability based on supplied relationships; not proof of an executable attack chain.",
            "assumptions": ["A network-reachable edge does not imply code execution.",
                            "Session and permission edges require source validation.",
                            "Synthetic lab evidence is illustrative, not observed production data."]}

@app.get("/")
def dashboard():
    return FileResponse(ROOT.parent / "index.html")

@app.get("/sentinel.js")
def dashboard_script():
    return FileResponse(ROOT.parent / "sentinel.js", media_type="application/javascript")

@app.get("/sentinel.html")
def sentinel_dashboard():
    return FileResponse(ROOT.parent / "sentinel.html")

@app.get("/{asset_name}")
def public_asset(asset_name: str):
    allowed = {"radar.js", "radar-plus.js", "radar-extras.js", "collection-clock.mjs", "radar.css", "intel.html", "app.js", "styles.css",
               "radar-methodology.html", "index.html"}
    if asset_name not in allowed:
        raise HTTPException(status_code=404, detail="Asset not found")
    return FileResponse(ROOT.parent / asset_name)

@app.get("/api/overview")
def global_overview():
    path = ROOT.parent / "data" / "overview.json"
    if not path.exists():
        raise HTTPException(status_code=503, detail="Run scheduled intelligence collection to generate overview.json")
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise HTTPException(status_code=503, detail="Intelligence snapshot is unreadable") from exc

@app.get("/api/extra")
def supplementary_intelligence():
    path = ROOT.parent / "data" / "extra.json"
    if not path.exists():
        raise HTTPException(status_code=503, detail="No supplementary intelligence snapshot generated")
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(payload, dict) or payload.get("schema") != 1:
            raise ValueError("Invalid supplementary schema")
        return payload
    except (OSError, ValueError) as exc:
        raise HTTPException(status_code=503, detail="Supplementary snapshot unavailable") from exc

@app.get("/api/radar")
def radar():
    try:
        return snapshot()
    except RuntimeError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc

@app.get("/api/health")
def health():
    return {"status": "ok", "mode": "synthetic-lab"}

@app.get("/api/graph")
def graph():
    return deepcopy(DATA)

@app.post("/api/paths")
def paths(scenario: Scenario):
    try:
        return analyze(DATA, scenario)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc

@app.get("/api/evidence")
def evidence():
    return {"findings": deepcopy(DATA["findings"]), "edges": deepcopy(DATA["edges"])}

@app.get("/api/remediations")
def remediations():
    baseline = analyze(DATA, Scenario())
    options = []
    for edge in DATA["edges"]:
        key = edge_key(edge)
        result = analyze(DATA, Scenario(disabled_edges=[key]))
        options.append({"edge": key, "control": "Remove or restrict " + edge["type"].replace("_", " "),
                        "blocks_path": baseline["reachable"] and not result["reachable"],
                        "remaining_hops": result["hop_count"] if result["reachable"] else None,
                        "evidence": edge["evidence"]})
    return {"baseline": baseline, "options": options}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8765)
