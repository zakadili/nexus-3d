"""Real source-country telemetry collector for NEXUS GLOBAL RADAR.

Reads SANS ISC / DShield top-source and top-port summaries; geolocates source
IPs via ipwho.is. Caches for one hour. Never fabricates missing observations.
No network scanning, active exploitation, or user-supplied upstream URLs.
"""
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
import ipaddress
import json
import os
import threading
import time
from urllib.error import HTTPError, URLError
from urllib.parse import quote
from urllib.request import Request, urlopen

SOURCES_URL = "https://isc.sans.edu/api/topips/records/30?json"
PORTS_URL = "https://isc.sans.edu/api/topports/records/12?json"
CACHE_SECONDS = 3600
_lock = threading.Lock()
_cache = None
_cached_at = 0.0


def _fetch_json(url, timeout=12):
    contact = os.environ.get("NEXUS_CONTACT", "https://github.com/zakadili/nexus-3d/issues")
    request = Request(url, headers={
        "User-Agent": "NEXUS-Sentinel-Radar/0.1 (contact: " + contact + ")",
        "Accept": "application/json",
    })
    with urlopen(request, timeout=timeout) as resp:
        if resp.status != 200:
            raise RuntimeError("Upstream HTTP " + str(resp.status))
        raw = resp.read(2_000_001)
        if len(raw) > 2_000_000:
            raise ValueError("Upstream response exceeds size limit")
        return json.loads(raw)


def _rows(doc, singular):
    if isinstance(doc, list):
        return doc
    if not isinstance(doc, dict):
        return []
    if isinstance(doc.get(singular), list):
        return doc[singular]
    if isinstance(doc.get("data"), list):
        return doc["data"]
    for name in ("topips", "topports"):
        nested = doc.get(name)
        if isinstance(nested, list):
            return nested
        if isinstance(nested, dict):
            found = _rows(nested, singular)
            if found:
                return found
    return [doc[k] for k in sorted(doc, key=lambda x: int(x) if x.isdigit() else 2_000_000) if k.isdigit() and isinstance(doc[k], dict)]


def _int(value):
    try:
        return max(0, int(value))
    except (ValueError, TypeError):
        return 0


def _source(record):
    if not isinstance(record, dict):
        return None
    try:
        ip = ipaddress.ip_address(str(record.get("source") or record.get("ip") or "").strip())
        if ip.version != 4 or not ip.is_global:
            return None
    except ValueError:
        return None
    return {
        "ip": str(ip),
        "reports": _int(record.get("reports", record.get("count", 0))),
        "targets": _int(record.get("targets", record.get("attacks", 0))),
    }


def _port(record):
    if not isinstance(record, dict):
        return None
    port = _int(record.get("targetport", record.get("port", -1)))
    if port > 65535 or (port == 0 and str(record.get("targetport", record.get("port", ""))) != "0"):
        return None
    return {"port": port, "reports": _int(record.get("records", record.get("reports", 0))), "sources": _int(record.get("sources", 0))}


def _enrich(item):
    value = dict(item)
    value.update({"country": None, "code": None, "latitude": None, "longitude": None})
    try:
        geo = _fetch_json("https://ipwho.is/" + quote(item["ip"]), timeout=9)
        if geo.get("success", True) is False or not geo.get("country_code"):
            return value
        lat, lon = float(geo["latitude"]), float(geo["longitude"])
        if not (-90 <= lat <= 90 and -180 <= lon <= 180):
            return value
        value.update({"country": str(geo.get("country") or geo["country_code"]),
                      "code": str(geo["country_code"]).upper(),
                      "latitude": lat, "longitude": lon})
    except (KeyError, TypeError, ValueError, URLError, HTTPError, TimeoutError):
        pass
    return value


def collect():
    source_doc = _fetch_json(SOURCES_URL)
    items = []
    seen = set()
    for record in _rows(source_doc, "ipaddress"):
        source = _source(record)
        if source and source["ip"] not in seen:
            seen.add(source["ip"])
            items.append(source)
        if len(items) >= 30:
            break
    if not items:
        raise RuntimeError("SANS source feed returned no usable public source addresses.")
    notes = None
    try:
        ports_doc = _fetch_json(PORTS_URL)
        ports = [p for row in _rows(ports_doc, "port") if (p := _port(row)) is not None]
    except (HTTPError, URLError, ValueError, RuntimeError, TimeoutError):
        ports_doc = {}
        ports = []
        notes = "DShield port summary is unavailable."
    with ThreadPoolExecutor(max_workers=3) as executor:
        sources = list(executor.map(_enrich, items))
    return {
        "source": "SANS ISC / DShield",
        "mode": "LOCAL COLLECTOR",
        "sample_basis": "Highest-ranked DShield source IPs (top 30 sample)",
        "retrieved_at": datetime.now(timezone.utc).isoformat(),
        "source_date": str(source_doc.get("date", "Recent source sample")),
        "ports_date": str(ports_doc.get("date", "Recent port sample")),
        "sources": sources,
        "ports": ports,
        "notes": notes,
    }


def snapshot():
    global _cache, _cached_at
    with _lock:
        if _cache and time.time() - _cached_at < CACHE_SECONDS:
            return dict(_cache, mode="LOCAL CACHE")
        try:
            result = collect()
            _cache = result
            _cached_at = time.time()
            return result
        except Exception as exc:
            if _cache:
                return dict(_cache, mode="STALE CACHE", notes="Upstream fetch failed; last known data shown: " + str(exc))
            raise RuntimeError("Live DShield collection unavailable: " + str(exc)) from exc
