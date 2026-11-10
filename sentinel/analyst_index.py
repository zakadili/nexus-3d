"""NEXUS static analyst-index generator.

Only redistributes explicitly permitted sources: abuse.ch Feodo (CC0) and
CISA KEV (CC0). Other providers' IP membership is *not* republished here
until their redistribution conditions have been independently verified.
"""
from collections import defaultdict
from datetime import datetime, timezone
import ipaddress
import json
from pathlib import Path
import re

SAFE_CVE = re.compile(r"^CVE-[0-9]{4}-[0-9]{4,}$")
SOURCE_URL = "https://feodotracker.abuse.ch/"
MAX_KEV_ROWS = 10000
MAX_INDICATORS = 100000


def build_ip_index(memberships, geodb, stamp):
    """A sharded IPv4 index of source-licensed Feodo indicators only."""
    if not isinstance(memberships, dict) or len(memberships) > MAX_INDICATORS * 10:
        raise ValueError("invalid indicator membership map")
    shards = defaultdict(list)
    for value, sources in memberships.items():
        if not isinstance(sources, (set, list, tuple)) or "feodo" not in sources:
            continue
        try:
            ip = ipaddress.ip_address(str(value))
        except ValueError:
            continue
        if ip.version != 4 or not ip.is_global:
            continue
        code = geodb.locate(str(ip))
        shards[str(ip.packed[0])].append({
            "type": "ipv4", "value": str(ip), "country": code,
            "sources": ["feodo"], "first_seen": None, "last_seen": None,
            "source_url": SOURCE_URL
        })
    if sum(len(v) for v in shards.values()) > MAX_INDICATORS:
        raise ValueError("index exceeds indicator limit")
    return {k: {"schema": 1, "generated_at": stamp,
                "license": "Feodo Tracker (abuse.ch), CC0", "records": sorted(v,key=lambda x:ipaddress.IPv4Address(x["value"]))}
            for k,v in shards.items()}


def clean_kev(doc, stamp):
    if not isinstance(doc, dict) or not isinstance(doc.get("vulnerabilities"), list):
        raise ValueError("invalid CISA KEV payload")
    rows = doc["vulnerabilities"]
    if len(rows) > MAX_KEV_ROWS:
        raise ValueError("CISA KEV row limit exceeded")
    kept = []
    seen = set()
    allowed = ("vendorProject", "product", "vulnerabilityName", "dateAdded",
               "dueDate", "knownRansomwareCampaignUse", "requiredAction",
               "shortDescription", "notes")
    for row in rows:
        if not isinstance(row, dict):
            continue
        cve = row.get("cveID")
        if not isinstance(cve, str) or not SAFE_CVE.fullmatch(cve) or cve in seen:
            continue
        seen.add(cve)
        record = {"id": cve}
        for field in allowed:
            value = row.get(field)
            record[field] = value[:2000] if isinstance(value, str) else None
        kept.append(record)
    if rows and not kept:
        raise ValueError("no valid CISA KEV records")
    return {"schema": 1, "generated_at": stamp, "source": "CISA KEV",
            "source_url": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
            "license": "CC0 1.0", "records": kept}


def write_static_index(folder, shards, catalog=None):
    """Write only verified content and remove *stale index shards*, never overview."""
    folder = Path(folder)
    folder.mkdir(parents=True, exist_ok=True)
    expected = {k + ".json" for k in shards}
    for path in folder.glob("*.json"):
        if path.name != "manifest.json" and path.name not in expected:
            path.unlink()
    for key, value in shards.items():
        if not key.isdigit() or not 0 <= int(key) <= 255:
            raise ValueError("invalid shard name")
        (folder / (key + ".json")).write_text(
            json.dumps(value, separators=(",", ":"), ensure_ascii=True)+"\n", encoding="utf-8")
    manifest = {
        "schema": 1, "source": "Feodo Tracker / abuse.ch (CC0)",
        "source_url": SOURCE_URL, "shard_keys": sorted(shards, key=int),
        "total_records": sum(len(shard["records"]) for shard in shards.values()),
        "limitations": "Only explicitly redistributable Feodo IPs are indexed. Not listed means not found in indexed feeds, not safe."
    }
    (folder / "manifest.json").write_text(json.dumps(manifest, indent=2)+"\n",encoding="utf-8")
    if catalog is not None:
        (folder.parent / "kev.json").write_text(json.dumps(catalog, separators=(",", ":"))+"\n",encoding="utf-8")
    return manifest


def snapshot_diff(now, old):
    """Future-only exact KEV ID diff; country-count changes are not IOC churn."""
    def ids(snapshot):
        if not isinstance(snapshot, dict):
            return None
        values = snapshot.get("kev_ids")
        if not isinstance(values, list) or not all(isinstance(v,str) and SAFE_CVE.fullmatch(v) for v in values):
            return None
        return set(values)
    a, b = ids(old), ids(now)
    if a is None or b is None:
        return {"status": "unavailable", "reason": "Historical KEV identifiers not retained in older snapshots"}
    return {"status": "ok", "added": sorted(b - a), "removed": sorted(a - b)}
