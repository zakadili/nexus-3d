"""Bounded, aggregate-only live signals. No database writes or upstream traffic here.

All mutation runs on the single API event loop. Only RIS is currently admitted;
IODA and CT cannot be enabled by passing an environment flag around their gates.
"""
import asyncio
from collections import OrderedDict, deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
import hashlib
import hmac
import ipaddress
import json
import math
import os
import re
import secrets
import time
from urllib.parse import urlsplit

SITE_ORIGIN = "https://zakadili.github.io"
SOURCES = ("ris_live", "ioda", "certstream")
TYPES = {"bgp_announcement", "bgp_withdrawal", "routing_anomaly_candidate"}
STATES = {"disabled", "license_blocked", "connecting", "connected", "quiet",
          "stale", "unavailable", "degraded"}
COUNTRIES = frozenset("AD AE AF AG AI AL AM AO AQ AR AS AT AU AW AX AZ BA BB BD BE BF BG BH BI BJ BL BM BN BO BQ BR BS BT BV BW BY BZ CA CC CD CF CG CH CI CK CL CM CN CO CR CU CV CW CX CY CZ DE DJ DK DM DO DZ EC EE EG EH ER ES ET FI FJ FK FM FO FR GA GB GD GE GF GG GH GI GL GM GN GP GQ GR GS GT GU GW GY HK HM HN HR HT HU ID IE IL IM IN IO IQ IR IS IT JE JM JO JP KE KG KH KI KM KN KP KR KW KY KZ LA LB LC LI LK LR LS LT LU LV LY MA MC MD ME MF MG MH MK ML MM MN MO MP MQ MR MS MT MU MV MW MX MY MZ NA NC NE NF NG NI NL NO NP NR NU NZ OM PA PE PF PG PH PK PL PM PN PR PS PT PW PY QA RE RO RS RU RW SA SB SC SD SE SG SH SI SJ SK SL SM SN SO SR SS ST SV SX SY SZ TC TD TF TG TH TJ TK TL TM TN TO TR TT TV TW TZ UA UG UM US UY UZ VA VC VE VG VI VN VU WF WS YE YT ZA ZM ZW".split())
ID = re.compile(r"[a-zA-Z0-9_-]{1,96}\Z")


def utc(epoch):
    return datetime.fromtimestamp(epoch, timezone.utc).isoformat().replace("+00:00", "Z")


def stamp(value):
    if not isinstance(value, str) or len(value) > 40:
        raise ValueError("Invalid timestamp")
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None or parsed.utcoffset().total_seconds() != 0:
        raise ValueError("UTC timestamp required")
    return parsed.timestamp()


def plain(value, limit):
    if not isinstance(value, str) or len(value) > limit or any(ord(c) < 32 for c in value):
        raise ValueError("Invalid text")
    return value


def integer(value, maximum=10**12):
    if type(value) is not int or not 0 <= value <= maximum:
        raise ValueError("Invalid count")
    return value


def encoded(value, limit):
    data = json.dumps(value, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode()
    if len(data) > limit:
        raise ValueError("Size limit")
    return data


def public_base(value):
    parts = urlsplit(value)
    if (parts.scheme != "https" or not parts.hostname or parts.username or parts.password
            or parts.query or parts.fragment or parts.path not in ("", "/")):
        raise ValueError("Public HTTPS origin required")
    return value.rstrip("/")


def scope_value(value):
    if not isinstance(value, dict) or set(value) - {"prefixes", "path_asn", "collector"}:
        raise ValueError("Invalid scope")
    result = {}
    if "prefixes" in value:
        prefixes = value["prefixes"]
        if not isinstance(prefixes, list) or len(prefixes) > 32:
            raise ValueError("Invalid prefixes")
        result["prefixes"] = [str(ipaddress.ip_network(plain(p, 50), strict=False)) for p in prefixes]
    if value.get("path_asn") is not None:
        result["path_asn"] = integer(value["path_asn"], 4294967295)
        if not result["path_asn"]:
            raise ValueError("Invalid ASN")
    if "collector" in value:
        if not re.fullmatch(r"rrc\d{2}", value["collector"]):
            raise ValueError("Invalid collector")
        result["collector"] = value["collector"]
    return result


def evidence_value(value):
    """Strict projection: arbitrary provider objects never reach public evidence."""
    required = {"schema", "source", "window_start", "window_end", "source_time_start",
                "source_time_end", "units", "message_count", "prefix_count", "input_digests",
                "sample_count", "digests_truncated", "collector", "scope", "mapping",
                "complete", "reason", "baseline_windows"}
    if not isinstance(value, dict) or not required <= value.keys() or set(value) - required - {"baseline_mean"}:
        raise ValueError("Invalid evidence fields")
    if value["schema"] != "nexus.ris-evidence.v1" or value["source"] != "ris_live":
        raise ValueError("Invalid evidence source")
    result = dict(value)
    for key in ("window_start", "window_end", "source_time_start", "source_time_end"):
        stamp(value[key])
    if stamp(value["window_start"]) > stamp(value["window_end"]) or stamp(value["source_time_start"]) > stamp(value["source_time_end"]):
        raise ValueError("Inverted evidence window")
    if value["units"] not in {"prefix announcements", "prefix withdrawals", "origin changes"}:
        raise ValueError("Invalid units")
    for key in ("message_count", "prefix_count", "sample_count", "baseline_windows"):
        integer(value[key])
    if value["sample_count"] > value["message_count"]:
        raise ValueError("Invalid sample count")
    for key in ("digests_truncated", "complete"):
        if type(value[key]) is not bool:
            raise ValueError("Invalid evidence flag")
    if not re.fullmatch(r"rrc\d{2}", value["collector"]):
        raise ValueError("Invalid collector")
    digests = value["input_digests"]
    if not isinstance(digests, list) or len(digests) > 16 or any(not isinstance(d, str) or not re.fullmatch(r"[0-9a-f]{64}", d) for d in digests):
        raise ValueError("Invalid opaque digests")
    result["input_digests"] = list(digests)
    result["scope"] = scope_value(value["scope"])
    mapping = value["mapping"]
    if not isinstance(mapping, dict) or set(mapping) != {"source", "license", "source_commit", "source_sha256", "generated_at"}:
        raise ValueError("Invalid mapping provenance")
    result["mapping"] = {k: plain(v, 180) for k, v in mapping.items()}
    result["reason"] = plain(value["reason"], 240)
    if "baseline_mean" in value:
        mean = value["baseline_mean"]
        if type(mean) not in (int, float) or not math.isfinite(mean) or mean < 0:
            raise ValueError("Invalid baseline")
    encoded(result, 15000)
    return result


@dataclass(frozen=True)
class Limits:
    records: int = 2000
    max_age: int = 1800
    event_bytes: int = 8 * 1024 * 1024
    evidence_bytes: int = 8 * 1024 * 1024
    clients: int = 8
    clients_per_address: int = 2
    queue_frames: int = 64
    queue_bytes: int = 128 * 1024
    rate_addresses: int = 2048


class Admission:
    """Bounded, idle-expiring token buckets with per-process opaque address keys."""
    def __init__(self, maximum, clock):
        self.maximum, self.clock = maximum, clock
        self.entries = OrderedDict()

    def allow(self, key, rate, burst):
        now = self.clock()
        for old_key, (_, previous) in list(self.entries.items()):
            if now - previous > 120:
                del self.entries[old_key]
            else:
                break
        tokens, previous = self.entries.pop(key, (float(burst), now))
        tokens = min(float(burst), tokens + max(0, now - previous) * rate / 60)
        permitted = tokens >= 1
        self.entries[key] = (tokens - 1 if permitted else tokens, now)
        while len(self.entries) > self.maximum:
            self.entries.popitem(last=False)
        return permitted


@dataclass(eq=False)
class Client:
    address: str
    limits: Limits
    frames: deque = field(default_factory=deque)
    ready: asyncio.Event = field(default_factory=asyncio.Event)
    size: int = 0
    closed: bool = False

    def put(self, frame):
        if self.closed:
            return False
        if len(self.frames) >= self.limits.queue_frames or self.size + len(frame) > self.limits.queue_bytes:
            self.close()
            return False
        self.frames.append(frame)
        self.size += len(frame)
        self.ready.set()
        return True

    def take(self):
        if not self.frames:
            self.ready.clear()
            return None
        frame = self.frames.popleft()
        self.size -= len(frame)
        if not self.frames:
            self.ready.clear()
        return frame

    def close(self):
        self.closed = True
        self.frames.clear()
        self.size = 0
        self.ready.set()


class LiveHub:
    def __init__(self, base_url, limits=Limits(), clock=time.monotonic, wall=time.time):
        self.base_url, self.limits = public_base(base_url), limits
        self.clock, self.wall = clock, wall
        self.records = OrderedDict()
        self.input_ids = OrderedDict()
        self.event_bytes = self.evidence_bytes = 0
        self.clients = set()
        self.admission = Admission(limits.rate_addresses, clock)
        self.address_secret = secrets.token_bytes(32)
        self.boot = secrets.token_hex(8)
        self.sequence = 0
        self.rates = {}
        self.sources = {source: {"status": "disabled" if source == "ris_live" else "license_blocked",
            "reason": "Filtered RIS collection has not been enabled" if source == "ris_live" else
                ("IODA data republication permission has not been established" if source == "ioda" else
                 "Selected CT log rights and server capacity have not been approved"),
            "last_event": None, "last_received": None, "last_message": None, "last_check": None,
            "scope": {}, "complete": False, "dropped": 0, "rejected": 0} for source in SOURCES}

    def address_key(self, address):
        return hmac.new(self.address_secret, address.encode(), hashlib.sha256).hexdigest()

    def update_source(self, source, **fields):
        if source != "ris_live":
            return
        aliases = {"state": "status", "last_event_at": "last_event", "last_received_at": "last_received",
                   "last_message_at": "last_message", "last_check_at": "last_check"}
        update = {}
        try:
            for key, value in fields.items():
                key = aliases.get(key, key)
                if key == "status":
                    if value not in STATES:
                        raise ValueError("Invalid state")
                    update[key] = value
                elif key in {"last_event", "last_received", "last_message", "last_check"}:
                    if value is not None:
                        stamp(value)
                    update[key] = value
                elif key in {"reason", "baseline_status"}:
                    update[key] = plain(value, 240)
                elif key in {"dropped", "rejected"}:
                    update[key] = max(integer(value), self.sources[source][key])
                elif key == "complete":
                    if type(value) is not bool:
                        raise ValueError("Invalid completeness")
                    update[key] = value
                elif key == "scope":
                    update[key] = scope_value(value)
            self.sources[source].update(update)
        except (ValueError, TypeError, OverflowError):
            self.sources[source]["rejected"] += 1
            self.sources[source]["complete"] = False

    def _evict(self):
        now = self.clock()
        while self.records:
            first = next(iter(self.records.values()))
            if (len(self.records) <= self.limits.records and self.event_bytes <= self.limits.event_bytes
                    and self.evidence_bytes <= self.limits.evidence_bytes
                    and now - first["stored"] < self.limits.max_age):
                break
            _, old = self.records.popitem(last=False)
            self.event_bytes -= len(old["event"])
            self.evidence_bytes -= len(old["evidence"])

    def _emission_allowed(self, source):
        now = int(self.clock())
        for key, maximum in (("global", 64), (source, 50)):
            second, count = self.rates.get(key, (now, 0))
            if second == now and count >= maximum:
                return False
        for key in ("global", source):
            second, count = self.rates.get(key, (now, 0))
            self.rates[key] = (now, count + 1 if second == now else 1)
        return True

    def publish(self, event, evidence):
        """Collector callback; refuses unknown sources and unsupported evidence."""
        source = event.get("source") if isinstance(event, dict) else None
        if source != "ris_live":
            return False
        try:
            required = {"id", "source", "type", "ts_observed", "ts_received", "label", "attribution", "confidence"}
            if not required <= event.keys() or set(event) - required - {"country", "asn", "value", "evidence_url"}:
                raise ValueError("Invalid event fields")
            item = dict(event)
            if not isinstance(item["id"], str) or not ID.fullmatch(item["id"]):
                raise ValueError("Invalid ID")
            input_id = item["id"]
            if input_id in self.input_ids:
                return False
            # Public IDs are never reused, even if a collector repeats an expired ID.
            public_id = f"live-{self.boot}-{self.sequence + 1}"
            item["id"] = public_id
            if item["type"] not in TYPES:
                raise ValueError("Invalid type")
            observed, received = stamp(item["ts_observed"]), stamp(item["ts_received"])
            if observed > self.wall() + 300 or received > self.wall() + 300:
                raise ValueError("Future timestamp")
            if item["confidence"] not in {"observed", "derived", "candidate"}:
                raise ValueError("Invalid confidence")
            if item["type"] == "routing_anomaly_candidate" and item["confidence"] != "candidate":
                raise ValueError("Candidate must remain a candidate")
            plain(item["label"], 240)
            if item["attribution"] != "RIPE NCC RIS Live":
                raise ValueError("Invalid attribution")
            if "country" in item and item["country"] not in COUNTRIES:
                raise ValueError("Invalid country")
            if "asn" in item:
                integer(item["asn"], 4294967295)
                if not item["asn"]:
                    raise ValueError("Invalid ASN")
            if "value" in item:
                integer(item["value"])
            if item["type"] == "bgp_withdrawal" and ("country" in item or "asn" in item):
                raise ValueError("Withdrawals have no inferred origin")
            target = self.base_url + "/api/live/evidence/" + item["id"]
            if "evidence_url" in item and item["evidence_url"] != target:
                raise ValueError("Untrusted evidence link")
            item["evidence_url"] = target
            proof = evidence_value(evidence)
            if stamp(proof["source_time_end"]) != observed:
                raise ValueError("Evidence timestamp mismatch")
            if item.get("value") != proof["prefix_count"]:
                raise ValueError("Evidence count mismatch")
            proof.update(id=item["id"], expires_at=utc(self.wall() + self.limits.max_age),
                         expiry_note="May expire earlier when memory capacity is reached")
            event_data, proof_data = encoded(item, 2048), encoded(proof, 16384)
            if len(event_data) > self.limits.event_bytes or len(proof_data) > self.limits.evidence_bytes:
                raise ValueError("Record exceeds memory capacity")
        except (ValueError, TypeError, OverflowError, RecursionError):
            self.sources[source]["rejected"] += 1
            self.sources[source]["complete"] = False
            return False
        self._evict()
        if item["id"] in self.records:
            return False
        if not self._emission_allowed(source):
            self.sources[source]["dropped"] += 1
            self.sources[source]["complete"] = False
            return False
        self.sequence += 1
        cursor = f"{self.boot}-{self.sequence}"
        self.input_ids[input_id] = True
        while len(self.input_ids) > 4000:
            self.input_ids.popitem(last=False)
        self.records[item["id"]] = {"event": event_data, "evidence": proof_data,
                                     "stored": self.clock(), "cursor": cursor}
        self.event_bytes += len(event_data)
        self.evidence_bytes += len(proof_data)
        self._evict()
        self.sources[source].update(last_event=item["ts_observed"], last_received=item["ts_received"])
        frame = self.frame("observation", item, cursor)
        for client in tuple(self.clients):
            if not client.put(frame):
                self.remove(client)
        return True

    def health(self):
        self._evict()
        sources = {key: dict(value) for key, value in self.sources.items()}
        for value in sources.values():
            last = value["last_message"] or value["last_received"]
            if value["status"] in {"connected", "quiet", "degraded"} and last and self.wall() - stamp(last) > 90:
                value.update(status="stale", complete=False, reason="No recent source message; activity is unknown")
        first = next(iter(self.records.values()), None)
        return {"schema": "nexus.live.health.v1", "server_time": utc(self.wall()), "sources": sources,
                "retention": {"oldest_id": first["cursor"] if first else None,
                    "oldest_received": json.loads(first["event"])["ts_received"] if first else None,
                    "records": len(self.records), "max_age_seconds": self.limits.max_age},
                "clients": len(self.clients)}

    def frame(self, kind, body, cursor=None):
        payload = encoded(body, 15000)
        frame = (f"id: {cursor}\n" if cursor else "").encode() + f"event: {kind}\ndata: ".encode() + payload + b"\n\n"
        if len(frame) > 16384:
            raise ValueError("SSE frame limit")
        return frame

    def gap(self, reason):
        return self.frame("gap", {"schema": "nexus.live.gap.v1", "server_time": utc(self.wall()), "reason": reason})

    def subscribe(self, address, cursor=None):
        """Synchronous admission + replay snapshot avoids an observation race."""
        key = self.address_key(address)
        if not self.admission.allow(("sse", key), 5, 2):
            return None, 429
        if len(self.clients) >= self.limits.clients or sum(c.address == key for c in self.clients) >= self.limits.clients_per_address:
            return None, 503
        client = Client(key, self.limits)
        self.clients.add(client)
        client.put(self.frame("health", self.health()))
        if cursor:
            entries = list(self.records.values())
            found = next((i for i, row in enumerate(entries) if row["cursor"] == cursor), None)
            if found is None:
                client.put(self.gap("Cursor expired, unknown, or from a previous service start; no historical replay is claimed"))
            else:
                replay = entries[found + 1:]
                maximum = max(0, min(60, self.limits.queue_frames - 3))
                if len(replay) > maximum:
                    client.put(self.gap("Replay exceeds the bounded client queue; older retained events were omitted"))
                    replay = replay[-maximum:] if maximum else []
                for row in replay:
                    if not client.put(self.frame("replay", json.loads(row["event"]), row["cursor"])):
                        self.remove(client)
                        return None, 503
        return client, 200

    def remove(self, client):
        self.clients.discard(client)
        client.close()

    def evidence(self, event_id):
        self._evict()
        row = self.records.get(event_id)
        return row["evidence"] if row else None

    async def stream(self, client):
        try:
            while not client.closed:
                frame = client.take()
                if frame is not None:
                    # An expired queued observation must not retain an actionable pulse.
                    if frame.startswith(b"id:"):
                        cursor = frame.split(b"\n", 1)[0][4:].decode()
                        self._evict()
                        if not any(row["cursor"] == cursor for row in self.records.values()):
                            yield self.gap("Queued evidence expired before delivery")
                            continue
                    yield frame
                    continue
                try:
                    await asyncio.wait_for(client.ready.wait(), 15)
                except asyncio.TimeoutError:
                    yield self.frame("health", self.health())
                    yield b": keepalive\n\n"
        finally:
            self.remove(client)


def install(app, hub, trusted_proxies=()):
    """Mount restricted public read routes; no write/ingestion endpoint exists."""
    from fastapi import Request
    from fastapi.responses import JSONResponse, Response, StreamingResponse

    trusted = {str(ipaddress.ip_address(value)) for value in trusted_proxies}

    def address(request):
        peer = request.client.host if request.client else "unknown"
        if peer in trusted:
            value = request.headers.get("x-real-ip", "")
            try:
                return str(ipaddress.ip_address(value))
            except ValueError:
                pass
        return peer

    def headers(request):
        result = {"Cache-Control": "no-store", "X-Content-Type-Options": "nosniff"}
        if request.headers.get("origin") == SITE_ORIGIN:
            result.update({"Access-Control-Allow-Origin": SITE_ORIGIN, "Vary": "Origin"})
        return result

    class BoundedResponse(StreamingResponse):
        async def __call__(self, scope, receive, send):
            async def bounded_send(message):
                await asyncio.wait_for(send(message), 5)
            try:
                await super().__call__(scope, receive, bounded_send)
            except asyncio.TimeoutError:
                pass
            finally:
                hub.remove(self.live_client)

    @app.get("/api/live/events")
    async def events(request: Request):
        if request.headers.get("origin") not in (None, SITE_ORIGIN):
            return JSONResponse({"detail": "Origin not allowed"}, 403, headers=headers(request))
        cursor = request.headers.get("last-event-id")
        if cursor and not re.fullmatch(r"[0-9a-f]{16}-[0-9]{1,20}", cursor):
            return JSONResponse({"detail": "Invalid replay cursor"}, 400, headers=headers(request))
        client, status = hub.subscribe(address(request), cursor)
        if client is None:
            return JSONResponse({"detail": "Live connection limit reached"}, status,
                                headers={**headers(request), "Retry-After": "60"})
        response = BoundedResponse(hub.stream(client), media_type="text/event-stream",
                                   headers={**headers(request), "X-Accel-Buffering": "no"})
        response.live_client = client
        return response

    @app.get("/api/live/evidence/{event_id}")
    async def evidence(request: Request, event_id: str):
        if request.headers.get("origin") not in (None, SITE_ORIGIN):
            return JSONResponse({"detail": "Origin not allowed"}, 403, headers=headers(request))
        if not hub.admission.allow(("evidence", hub.address_key(address(request))), 30, 10):
            return JSONResponse({"detail": "Evidence request limit reached"}, 429,
                                headers={**headers(request), "Retry-After": "60"})
        if not ID.fullmatch(event_id):
            return JSONResponse({"detail": "Invalid evidence ID"}, 400, headers=headers(request))
        content = hub.evidence(event_id)
        if content is None:
            return JSONResponse({"detail": "Evidence expired or is unavailable; no permanent replay is retained"},
                                410, headers=headers(request))
        return Response(content, media_type="application/json", headers=headers(request))

