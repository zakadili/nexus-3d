"""Supplementary, independently attributed NEXUS intelligence datasets.

No scanning. No invented values. No per-IP geo/ASN API calls.
The collectors are independent; unavailable feeds never become numeric zero.
"""
from bisect import bisect_right
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
import csv
import gzip
import io
import ipaddress
import json
import os
import re
from urllib.error import HTTPError
from urllib.parse import urlsplit
from urllib.request import Request, urlopen

try:
    from sentinel import intelligence_pipeline as base
except ModuleNotFoundError as exc:
    if exc.name != "sentinel":
        raise
    import intelligence_pipeline as base

ASN_URL = "https://iptoasn.com/data/ip2asn-v4.tsv.gz"
URLHAUS_TEMPLATE = "https://urlhaus-api.abuse.ch/v2/files/exports/{key}/recent.csv"
THREATFOX_URL = "https://threatfox-api.abuse.ch/api/v1/"
IODA_URL = "https://api.ioda.inetintel.cc.gatech.edu/v2/outages/events"
MAX_DOWNLOAD = 20_000_000
MAX_UNCOMPRESSED = 110_000_000
MAX_RECORDS = 400_000
NOTE = {
 "urlhaus": "URLs directly hosted on geolocated public IPv4 hosts only; domain URLs cannot be located without DNS. Listed URLs hosted in this country, not attacker location or successful infection.",
 "threatfox": "Geolocated public IPv4 IoCs only. Some IoCs are domains, hashes or URLs and cannot be attributed to a country. Hosted/listed IoCs do not identify attackers.",
 "iptoasn": "ASNs announcing listed source IPs; a provider's appearance is not evidence its owners are malicious.",
 "ioda": "Observed connectivity disruption events, not verified cyberattacks. Outages have many causes including weather, outages and maintenance.",
}
SOURCES = {
 "urlhaus": ("URLhaus / abuse.ch", "https://urlhaus.abuse.ch/api/"),
 "threatfox": ("ThreatFox / abuse.ch", "https://threatfox.abuse.ch/api/"),
 "iptoasn": ("IPtoASN / Frank Denis", "https://iptoasn.com/"),
 "ioda": ("IODA / Georgia Tech", "https://ioda.inetintel.cc.gatech.edu/"),
}


def health(source, status, count=None, reason=None):
    name, url = SOURCES[source]
    result = {"id": source, "name": name, "url": url, "status": status,
              "records": count, "meaning": NOTE[source]}
    if reason:
        result["reason"] = str(reason)[:120]
    return result


def fetch_bytes(url, limit=MAX_DOWNLOAD, headers=None, data=None, timeout=28):
    req = Request(url, data=data, headers={
        "User-Agent": base.USER_AGENT, "Accept": "application/json,text/csv,*/*",
        **(headers or {})
    })
    with urlopen(req, timeout=timeout) as resp:
        body = resp.read(limit + 1)
        if len(body) > limit:
            raise ValueError("source download exceeds maximum allowed bytes")
        return body


def ipv4(value):
    return base.global_v4(value)


def direct_ip_host(value):
    """No DNS resolution, no external URL fetches; only literal public IPv4 hosts."""
    try:
        url = urlsplit(str(value))
        host = url.hostname
        return ipv4(host) if url.scheme in ("http", "https") and host else None
    except ValueError:
        return None


def parse_urlhaus(raw, geodb):
    if len(raw) > MAX_DOWNLOAD:
        raise ValueError("URLhaus export exceeds limit")
    text = raw.decode("utf-8-sig")
    lines = []
    for line in text.splitlines():
        if not line.strip():
            continue
        if line.startswith("#"):
            stripped = line.lstrip("# ").strip()
            if "url" in stripped.lower().split(","):
                lines.append(stripped)
            continue
        lines.append(line)
    reader = csv.DictReader(lines)
    if not reader.fieldnames or "url" not in reader.fieldnames:
        raise ValueError("URLhaus CSV missing url header")
    countries = Counter()
    tags = Counter()
    seen = set()
    parsed = 0
    for row in reader:
        parsed += 1
        if parsed > MAX_RECORDS:
            raise ValueError("URLhaus CSV exceeds record cap")
        if not isinstance(row, dict) or not isinstance(row.get("url"), str):
            continue
        url = row["url"].strip()
        if not url or url in seen:
            continue
        seen.add(url)
        ip = direct_ip_host(url)
        if ip:
            code = geodb.locate(ip)
            if code:
                countries[code] += 1
        for tag in str(row.get("tags") or "").split(",")[:20]:
            tag = tag.strip()[:80]
            if tag:
                tags[tag] += 1
    return {"total_urls": len(seen), "geolocated_url_count": sum(countries.values()),
            "countries": dict(countries), "top_tags": top(tags, 15),
            "unmapped_url_count": len(seen) - sum(countries.values())}


def parse_threatfox(doc, geodb):
    if not isinstance(doc, dict) or doc.get("query_status") not in ("ok", "no_result"):
        raise ValueError("Unexpected ThreatFox API response")
    rows = doc.get("data") or []
    if not isinstance(rows, list):
        raise ValueError("Invalid ThreatFox data")
    if len(rows) > MAX_RECORDS:
        raise ValueError("ThreatFox result exceeds cap")
    countries = Counter()
    malware = Counter()
    tags = Counter()
    seen = set()
    for row in rows:
        if not isinstance(row, dict):
            continue
        ioc = row.get("ioc")
        if not isinstance(ioc, str) or not ioc or ioc in seen:
            continue
        seen.add(ioc)
        family = row.get("malware_printable") or row.get("malware")
        if isinstance(family, str) and family[:80].strip():
            malware[family[:80]] += 1
        for tag in (row.get("tags") if isinstance(row.get("tags"), list) else []):
            if isinstance(tag, str) and tag[:80].strip():
                tags[tag[:80]] += 1
        kind = row.get("ioc_type")
        ip = None
        if kind == "ip:port":
            ip = ipv4(ioc.rsplit(":", 1)[0])
        elif kind == "ip":
            ip = ipv4(ioc)
        elif kind == "url":
            ip = direct_ip_host(ioc)
        if ip:
            code = geodb.locate(ip)
            if code:
                countries[code] += 1
    return {"total_iocs": len(seen), "geolocated_ioc_count": sum(countries.values()),
            "countries": dict(countries), "top_malware": top(malware, 15),
            "top_tags": top(tags, 15), "unmapped_ioc_count": len(seen) - sum(countries.values())}


def top(counter, size):
    return [{"name": str(k), "count": v} for k, v in counter.most_common(size)]


class ASNDB:
    def __init__(self, rows):
        entries = []
        for row in rows:
            if len(row) != 5:
                continue
            try:
                start = int(ipaddress.IPv4Address(row[0]))
                end = int(ipaddress.IPv4Address(row[1]))
                asn = int(row[2])
                if start > end or asn <= 0:
                    continue
                org = row[4].strip()[:140]
                entries.append((start, end, asn, org))
            except (ValueError, TypeError):
                continue
            if len(entries) > 600_000:
                raise ValueError("ASN table exceeds range cap")
        entries.sort()
        if not entries:
            raise ValueError("Empty or malformed ASN range table")
        self.starts = [r[0] for r in entries]
        self.ends = [r[1] for r in entries]
        self.asns = [r[2] for r in entries]
        self.orgs = [r[3] for r in entries]

    def locate(self, ip):
        value = int(ipaddress.IPv4Address(ip))
        pos = bisect_right(self.starts, value) - 1
        return (self.asns[pos], self.orgs[pos]) if pos >= 0 and value <= self.ends[pos] else None


def parse_asn_gzip(raw):
    if len(raw) > MAX_DOWNLOAD:
        raise ValueError("ASN file exceeds compressed limit")
    with gzip.GzipFile(fileobj=io.BytesIO(raw)) as stream:
        extracted = stream.read(MAX_UNCOMPRESSED + 1)
    if len(extracted) > MAX_UNCOMPRESSED:
        raise ValueError("ASN file exceeds expanded size cap")
    return ASNDB(csv.reader(io.StringIO(extracted.decode("utf-8")), delimiter="\t"))


def summarize_asns(ips_by_country, db):
    global_counts = Counter()
    countries = {}
    names = {}
    for code, ips in ips_by_country.items():
        c = Counter()
        for ip in ips:
            match = db.locate(ip)
            if match:
                asn, org = match
                c[asn] += 1
                global_counts[asn] += 1
                names[asn] = org
        countries[code] = [{"asn": asn, "org": names.get(asn, ""), "listed_ips": count}
                           for asn, count in c.most_common(10)]
    return {"countries": countries,
            "top_global": [{"asn": asn, "org": names.get(asn, ""), "listed_ips": count}
                           for asn, count in global_counts.most_common(10)],
            "matched_ips": sum(global_counts.values())}


def parse_ioda(doc):
    """IODA v2 envelope: data array or nested data.events. Do not invent outage severity."""
    if isinstance(doc, dict):
        if doc.get("error"):
            raise ValueError("IODA returned an error")
        rows = doc.get("data")
        if isinstance(rows, dict):
            rows = rows.get("events") or rows.get("items")
    elif isinstance(doc, list):
        rows = doc
    else:
        raise ValueError("Malformed IODA response")
    if not isinstance(rows, list):
        raise ValueError("IODA data not an events list")
    if len(rows) > 1000:
        raise ValueError("IODA outage list exceeds requested cap")
    events = []
    for e in rows:
        if not isinstance(e, dict):
            continue
        code = e.get("entityCode")
        if not code and isinstance(e.get("location"), str):
            match = re.fullmatch(r"country/([A-Z]{2})", e["location"])
            code = match.group(1) if match else None
        if e.get("entityType") not in (None, "country"):
            continue
        if not isinstance(code, str) or not re.fullmatch("[A-Z]{2}", code):
            continue
        start = e.get("from", e.get("start"))
        if not isinstance(start, int) or start < 1_500_000_000:
            continue
        until = e.get("until")
        if until is None and isinstance(e.get("duration"), int):
            until = start + e["duration"]
        if not isinstance(until, int):
            until = None
        events.append({"code": code, "start": start, "end": until,
                       "source": str(e.get("datasource") or "IODA")[:50]})
    events.sort(key=lambda r: -r["start"])
    return {"events": events[:100], "countries": {
        code: sum(e["code"] == code for e in events) for code in sorted({e["code"] for e in events})
    }}


def unavailable(source, reason):
    return health(source, "unavailable", reason=reason)


def collect_urlhaus(geodb):
    key = os.getenv("ABUSECH_AUTH_KEY", "").strip()
    if not key:
        return None, unavailable("urlhaus", "no key configured")
    try:
        raw = fetch_bytes(URLHAUS_TEMPLATE.format(key=key))
        out = parse_urlhaus(raw, geodb)
        return out, health("urlhaus", "ok", out["total_urls"])
    except Exception as exc:
        return None, unavailable("urlhaus", type(exc).__name__)


def collect_threatfox(geodb):
    key = os.getenv("ABUSECH_AUTH_KEY", "").strip()
    if not key:
        return None, unavailable("threatfox", "no key configured")
    try:
        request = json.dumps({"query": "get_iocs", "days": 7}).encode()
        raw = fetch_bytes(THREATFOX_URL, limit=5_000_000,
                          headers={"Auth-Key": key, "Content-Type": "application/json"}, data=request)
        out = parse_threatfox(json.loads(raw), geodb)
        return out, health("threatfox", "ok", out["total_iocs"])
    except Exception as exc:
        return None, unavailable("threatfox", type(exc).__name__)


def collect_ioda():
    now = int(datetime.now(timezone.utc).timestamp())
    url = f"{IODA_URL}?from={now-7*86400}&until={now}&entityType=country&limit=100&format=ioda"
    try:
        result = parse_ioda(json.loads(fetch_bytes(url, limit=1_500_000)))
        return result, health("ioda", "ok", len(result["events"]))
    except Exception as exc:
        return None, unavailable("ioda", type(exc).__name__)


def collect_asns(ips_by_country):
    try:
        db = parse_asn_gzip(fetch_bytes(ASN_URL, limit=12_000_000, timeout=65))
        out = summarize_asns(ips_by_country, db)
        return out, health("iptoasn", "ok", out["matched_ips"])
    except Exception as exc:
        return None, unavailable("iptoasn", type(exc).__name__)


def collect_all(geodb, ips_by_country):
    feeds = {}
    status = []
    for kind, action in [
        ("urlhaus", lambda: collect_urlhaus(geodb)),
        ("threatfox", lambda: collect_threatfox(geodb)),
        ("iptoasn", lambda: collect_asns(ips_by_country)),
        ("ioda", collect_ioda),
    ]:
        data, info = action()
        feeds[kind] = data
        status.append(info)
    return {"schema": 1, "collected_at": datetime.now(timezone.utc).isoformat(),
            "feeds": feeds, "source_health": status}
