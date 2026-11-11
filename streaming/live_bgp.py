"""Filtered, passive RIS Live collection. Disabled until explicit operating gates clear.

Protocol: https://ris-live.ripe.net/manual/ (checked 2026-11-12).
Tests use authored protocol-shaped fixtures, not redistributed raw RIS records.
The collector never publishes a peer, raw message ID, prefix, or raw payload.
"""
from __future__ import annotations

import argparse
import asyncio
from collections import OrderedDict, deque
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import hmac
import ipaddress
import json
import math
import os
from pathlib import Path
import random
import re
import secrets
import time

RIS_URL = "wss://ris-live.ripe.net/v1/ws/?client=nexus-sentinel"
MAPPING_SOURCE = "https://github.com/ipverse/as-metadata"
MAX_FRAME = 65536
COUNTRIES = frozenset("AD AE AF AG AI AL AM AO AQ AR AS AT AU AW AX AZ BA BB BD BE BF BG BH BI BJ BL BM BN BO BQ BR BS BT BV BW BY BZ CA CC CD CF CG CH CI CK CL CM CN CO CR CU CV CW CX CY CZ DE DJ DK DM DO DZ EC EE EG EH ER ES ET FI FJ FK FM FO FR GA GB GD GE GF GG GH GI GL GM GN GP GQ GR GS GT GU GW GY HK HM HN HR HT HU ID IE IL IM IN IO IQ IR IS IT JE JM JO JP KE KG KH KI KM KN KP KR KW KY KZ LA LB LC LI LK LR LS LT LU LV LY MA MC MD ME MF MG MH MK ML MM MN MO MP MQ MR MS MT MU MV MW MX MY MZ NA NC NE NF NG NI NL NO NP NR NU NZ OM PA PE PF PG PH PK PL PM PN PR PS PT PW PY QA RE RO RS RU RW SA SB SC SD SE SG SH SI SJ SK SL SM SN SO SR SS ST SV SX SY SZ TC TD TF TG TH TJ TK TL TM TN TO TR TT TV TW TZ UA UG UM US UY UZ VA VC VE VG VI VN VU WF WS YE YT ZA ZM ZW".split())


def utc(value: float) -> str:
    return datetime.fromtimestamp(value, timezone.utc).isoformat().replace("+00:00", "Z")


def valid_asn(value) -> bool:
    return type(value) is int and 0 < value <= 4294967295


def strict_json(raw: str | bytes):
    """Byte cap and structural budget before traversing or accepting any feed data."""
    if not isinstance(raw, (str, bytes)) or len(raw) > MAX_FRAME:
        raise ValueError("frame_limit")
    if isinstance(raw, str) and len(raw.encode("utf-8")) > MAX_FRAME:
        raise ValueError("frame_limit")
    def reject_constant(_):
        raise ValueError("nonfinite_number")
    try:
        value = json.loads(raw, parse_constant=reject_constant)
    except (UnicodeError, RecursionError, json.JSONDecodeError) as exc:
        raise ValueError("invalid_json") from exc
    stack = [(value, 0)]
    nodes = 0
    while stack:
        item, depth = stack.pop()
        nodes += 1
        if depth > 10 or nodes > 8192:
            raise ValueError("structure_limit")
        if isinstance(item, dict):
            if len(item) > 64:
                raise ValueError("object_limit")
            stack.extend((v, depth + 1) for v in item.values())
        elif isinstance(item, list):
            if len(item) > 2048:
                raise ValueError("array_limit")
            stack.extend((v, depth + 1) for v in item)
        elif isinstance(item, str) and len(item) > 4096:
            raise ValueError("string_limit")
    if not isinstance(value, dict):
        raise ValueError("object_required")
    return value


@dataclass(frozen=True)
class BGPConfig:
    enabled: bool = False
    terms_accepted: bool = False
    capacity_approved: bool = False
    collector: str = ""
    prefixes: tuple[str, ...] = ()
    path_asn: int | None = None
    mapping_path: str = ""
    window_seconds: int = 10
    max_buckets: int = 256
    max_origins: int = 10000
    max_messages_per_second: int = 500
    max_bytes_per_second: int = 1024 * 1024

    def __post_init__(self):
        if self.collector and not re.fullmatch(r"rrc[0-9]{2}", self.collector):
            raise ValueError("invalid_collector")
        if self.path_asn is not None and not valid_asn(self.path_asn):
            raise ValueError("invalid_path_asn")
        if not isinstance(self.prefixes, tuple) or len(self.prefixes) > 16:
            raise ValueError("prefix_scope_limit")
        for prefix in self.prefixes:
            if not isinstance(prefix, str) or len(prefix) > 49:
                raise ValueError("invalid_prefix")
            network = ipaddress.ip_network(prefix, strict=True)
            if network.prefixlen < (8 if network.version == 4 else 16):
                raise ValueError("prefix_scope_too_broad")
        for name, low, high in (("window_seconds", 5, 30), ("max_buckets", 1, 512),
                                ("max_origins", 1, 10000), ("max_messages_per_second", 1, 1000),
                                ("max_bytes_per_second", 1024, 2 * 1024 * 1024)):
            if type(getattr(self, name)) is not int or not low <= getattr(self, name) <= high:
                raise ValueError("invalid_" + name)

    @classmethod
    def from_env(cls, env=None):
        env = os.environ if env is None else env
        return cls(enabled=env.get("LIVE_BGP_ENABLED", "false").lower() == "true",
                   terms_accepted=env.get("LIVE_RIS_TERMS_ACCEPTED", "false").lower() == "true",
                   capacity_approved=env.get("LIVE_BGP_CAPACITY_APPROVED", "false").lower() == "true",
                   collector=env.get("LIVE_BGP_COLLECTOR", ""),
                   prefixes=tuple(p.strip() for p in env.get("LIVE_BGP_PREFIXES", "").split(",") if p.strip()),
                   path_asn=int(env["LIVE_BGP_PATH_ASN"]) if env.get("LIVE_BGP_PATH_ASN") else None,
                   mapping_path=env.get("LIVE_ASN_MAPPING_PATH", ""))

    @property
    def gate(self):
        if not self.enabled:
            return "disabled", "Live BGP collection is disabled"
        if not self.terms_accepted:
            return "license_blocked", "RIS attribution and terms require operator acceptance"
        if not self.capacity_approved:
            return "disabled", "Filtered subscription capacity review is required"
        if not self.collector or not (self.prefixes or self.path_asn):
            return "disabled", "An approved collector and prefix or origin-ASN scope are required"
        return None

    @property
    def scope(self):
        result = {"prefixes": list(self.prefixes)}
        if self.path_asn:
            result["path_asn"] = self.path_asn
        return result

    def subscription(self):
        if self.gate:
            raise ValueError("activation_gate")
        data = {"host": self.collector, "type": "UPDATE",
                "socketOptions": {"includeRaw": False, "acknowledge": True}}
        if self.prefixes:
            data.update(prefix=list(self.prefixes), moreSpecific=True, lessSpecific=False)
        if self.path_asn:
            data["path"] = str(self.path_asn) + "$"
        return {"type": "ris_subscribe", "data": data}


class ASNMap:
    """Compact offline derivative of ipverse JSON; no runtime network lookups.

    Compilation filters metadata.origin == authoritative. The compact file stores
    only ASN/country pairs, an exact upstream SHA256 and its reviewed commit/date.
    Unknown and inferred countries stay absent. Metadata is provenance, not a
    signature: deployment must obtain the input from the recorded trusted commit.
    """
    def __init__(self, entries=None, metadata=None):
        self.entries = entries or {}
        self.metadata = metadata or {"source": MAPPING_SOURCE, "license": "CC0-1.0",
                                     "source_commit": "", "source_sha256": "", "generated_at": ""}

    def country(self, asn):
        return self.entries.get(asn)

    @classmethod
    def load(cls, path):
        with Path(path).open("rb") as handle:
            raw = handle.read(2 * 1024 * 1024 + 1)
        if len(raw) > 2 * 1024 * 1024:
            raise ValueError("mapping_size_limit")
        data = json.loads(raw)
        meta = data["metadata"]
        if (data.get("schema") != 1 or meta.get("source") != MAPPING_SOURCE
                or meta.get("license") != "CC0-1.0"
                or not re.fullmatch(r"[a-f0-9]{40}", meta.get("source_commit", ""))
                or not re.fullmatch(r"[a-f0-9]{64}", meta.get("source_sha256", ""))
                or not re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z", meta.get("generated_at", ""))):
            raise ValueError("mapping_provenance_required")
        entries = data["entries"]
        if not isinstance(entries, dict) or len(entries) > 150000:
            raise ValueError("mapping_entry_limit")
        result = {}
        for key, country in entries.items():
            if not re.fullmatch(r"[1-9][0-9]{0,9}", key) or not valid_asn(int(key)) or country not in COUNTRIES:
                raise ValueError("invalid_mapping_entry")
            result[int(key)] = country
        return cls(result, {key: meta[key] for key in ("source", "license", "source_commit", "source_sha256", "generated_at")})

    @staticmethod
    def compile(raw: bytes, source_commit: str):
        """Offline build operation; never call from the small production worker."""
        if len(raw) > 96 * 1024 * 1024 or not re.fullmatch(r"[a-f0-9]{40}", source_commit):
            raise ValueError("invalid_mapping_input")
        records = json.loads(raw)
        if not isinstance(records, list) or len(records) > 150000:
            raise ValueError("mapping_entry_limit")
        entries = {}
        for item in records:
            if not isinstance(item, dict) or not valid_asn(item.get("asn")):
                raise ValueError("invalid_mapping_record")
            meta = item.get("metadata") or {}
            if meta.get("origin") == "authoritative" and meta.get("countryCode") in COUNTRIES:
                if str(item["asn"]) in entries:
                    raise ValueError("duplicate_mapping_asn")
                entries[str(item["asn"])] = meta["countryCode"]
        return {"schema": 1, "metadata": {"source": MAPPING_SOURCE, "license": "CC0-1.0",
                    "source_commit": source_commit, "source_sha256": hashlib.sha256(raw).hexdigest(),
                    "generated_at": utc(time.time())}, "entries": entries}


class WindowAggregator:
    def __init__(self, config: BGPConfig, mapping: ASNMap | None = None):
        self.config, self.mapping = config, mapping or ASNMap()
        self._key = secrets.token_bytes(32)
        self._sequence = 0
        self.window = None
        self.buckets = {}
        self.seen = OrderedDict()
        self.origins = OrderedDict()
        self.baselines = OrderedDict()
        self.rejected = self.dropped = self.duplicates = 0
        self.last_event = self.last_received = None
        self.complete = True
        self._networks = tuple(ipaddress.ip_network(p) for p in config.prefixes)

    def digest(self, *parts):
        return hmac.new(self._key, "\0".join(str(p) for p in parts).encode(), hashlib.sha256).digest()

    def gap(self):
        """Partial windows never become normal baselines or false change candidates."""
        self.dropped += sum(bucket["prefix_count"] for bucket in self.buckets.values())
        self.buckets.clear()
        self.origins.clear()
        self.baselines.clear()
        self.window = None
        self.complete = False

    def _prefixes(self, values):
        if not isinstance(values, list) or len(values) > 1024:
            raise ValueError("prefix_limit")
        result = []
        for value in values:
            if not isinstance(value, str) or len(value) > 49:
                raise ValueError("invalid_prefix")
            network = ipaddress.ip_network(value, strict=True)
            if not self._networks or any(network.version == scope.version and network.subnet_of(scope) for scope in self._networks):
                result.append(str(network))
        return result

    def _decode(self, frame, received):
        outer = strict_json(frame)
        if outer.get("type") != "ris_message":
            return None
        data = outer.get("data")
        if not isinstance(data, dict) or data.get("type") != "UPDATE":
            return None
        if data.get("host") != self.config.collector:
            raise ValueError("collector_mismatch")
        stamp = data.get("timestamp")
        if type(stamp) not in (int, float) or not math.isfinite(stamp) or stamp < received - 120 or stamp > received + 30:
            raise ValueError("invalid_source_time")
        raw_id = data.get("id")
        if not isinstance(raw_id, str) or not 1 <= len(raw_id) <= 256:
            raise ValueError("invalid_source_id")
        peer = data.get("peer")
        if not isinstance(peer, str) or len(peer) > 45:
            raise ValueError("invalid_peer")
        peer = str(ipaddress.ip_address(peer))
        path = data.get("path", [])
        if not isinstance(path, list) or len(path) > 128:
            raise ValueError("invalid_path")
        for item in path:
            if isinstance(item, list):
                if not 1 <= len(item) <= 64 or any(not valid_asn(asn) for asn in item):
                    raise ValueError("invalid_as_set")
            elif not valid_asn(item):
                raise ValueError("invalid_asn")
        origin = path[-1] if path and valid_asn(path[-1]) else None
        if self.config.path_asn and origin != self.config.path_asn:
            return None
        announcements = data.get("announcements", [])
        if not isinstance(announcements, list) or len(announcements) > 32:
            raise ValueError("announcement_limit")
        prefixes = []
        for announcement in announcements:
            if not isinstance(announcement, dict):
                raise ValueError("invalid_announcement")
            prefixes.extend(self._prefixes(announcement.get("prefixes")))
            if len(prefixes) > 1024:
                raise ValueError("prefix_limit")
        withdrawals = self._prefixes(data.get("withdrawals", []))
        return stamp, self.digest("message", raw_id), peer, origin, prefixes, withdrawals

    def _add(self, kind, country, count, stamp, received, digest):
        if not count:
            return
        key = (kind, country)
        if key not in self.buckets and len(self.buckets) >= self.config.max_buckets:
            raise OverflowError("bucket_limit")
        bucket = self.buckets.setdefault(key, {"prefix_count": 0, "message_count": 0,
                "first": stamp, "last": stamp, "received": received, "digests": []})
        bucket["prefix_count"] += count
        bucket["message_count"] += 1
        bucket["first"] = min(bucket["first"], stamp)
        bucket["last"] = max(bucket["last"], stamp)
        bucket["received"] = max(bucket["received"], received)
        if len(bucket["digests"]) < 16:
            bucket["digests"].append(digest.hex())

    def feed(self, frame, received: float):
        """Call flush(received) before feed. Returns accepted/duplicate/ignored/rejected."""
        try:
            decoded = self._decode(frame, received)
            if decoded is None:
                return "ignored"
            stamp, digest, peer, origin, announcements, withdrawals = decoded
            if digest in self.seen:
                self.duplicates += 1
                return "duplicate"
            # Ordered insertion times expire deterministically; keys are opaque digests.
            while self.seen and (len(self.seen) >= 10000 or next(iter(self.seen.values())) < received - 120):
                self.seen.popitem(last=False)
            self.seen[digest] = received
            if not announcements and not withdrawals:
                return "ignored"
            window = int(received // self.config.window_seconds)
            if self.window is not None and self.window != window:
                raise ValueError("window_not_flushed")
            if self.window is None:
                self.window = window
                self.complete = True
            country = self.mapping.country(origin)
            self._add("bgp_announcement", country, len(announcements), stamp, received, digest)
            self._add("bgp_withdrawal", None, len(withdrawals), stamp, received, digest)
            while self.origins and next(iter(self.origins.values()))[1] < received - 300:
                self.origins.popitem(last=False)
            changes = 0
            for prefix in withdrawals:
                self.origins.pop(self.digest("route", self.config.collector, peer, prefix), None)
            for prefix in announcements:
                key = self.digest("route", self.config.collector, peer, prefix)
                previous = self.origins.pop(key, None)
                if origin is None:
                    continue
                # Out-of-order observations cannot prove an origin transition.
                if previous and stamp >= previous[2] and previous[0] != origin:
                    changes += 1
                if previous and stamp < previous[2]:
                    continue
                if len(self.origins) >= self.config.max_origins:
                    self.origins.popitem(last=False)
                self.origins[key] = (origin, received, stamp)
            self._add("routing_anomaly_candidate", country, changes, stamp, received, digest)
            self.last_event = max(stamp, self.last_event or stamp)
            self.last_received = received
            return "accepted"
        except (ValueError, TypeError, OverflowError):
            self.rejected += 1
            self.gap()
            return "rejected"

    def flush(self, received: float):
        if self.window is None or int(received // self.config.window_seconds) <= self.window:
            return []
        window, buckets = self.window, self.buckets
        self.window, self.buckets = None, {}
        result = []
        for (kind, country), bucket in buckets.items():
            key = (kind, country)
            baseline = self.baselines.pop(key, None)
            history = baseline[1] if baseline and baseline[0] == window - 1 else deque(maxlen=60)
            mean = sum(history) / len(history) if history else 0
            spike = kind == "bgp_announcement" and len(history) >= 12 and bucket["prefix_count"] >= max(20, mean * 5)
            units = {"bgp_announcement": "prefix announcements", "bgp_withdrawal": "prefix withdrawals",
                     "routing_anomaly_candidate": "origin changes"}[kind]
            self._sequence += 1
            event_id = "ris-" + self.digest("aggregate", self._sequence, window, kind, country).hex()[:32]
            event = {"id": event_id, "source": "ris_live", "type": kind,
                     "ts_observed": utc(bucket["last"]), "ts_received": utc(bucket["received"]),
                     "value": bucket["prefix_count"], "label": "BGP " + units,
                     "attribution": "RIPE NCC RIS Live", "confidence": "derived"}
            if country:
                event["country"] = country
            if kind == "routing_anomaly_candidate":
                event.update(label="Routing anomaly candidates: observed origin changes", confidence="candidate")
            evidence = {"schema": "nexus.ris-evidence.v1", "source": "ris_live",
                        "window_start": utc(window * self.config.window_seconds),
                        "window_end": utc((window + 1) * self.config.window_seconds),
                        "source_time_start": utc(bucket["first"]), "source_time_end": utc(bucket["last"]),
                        "units": units, "message_count": bucket["message_count"], "prefix_count": bucket["prefix_count"],
                        "input_digests": bucket["digests"], "sample_count": len(bucket["digests"]),
                        "digests_truncated": bucket["message_count"] > len(bucket["digests"]),
                        "collector": self.config.collector, "scope": self.config.scope,
                        "mapping": dict(self.mapping.metadata), "complete": self.complete,
                        "reason": "Filtered collector observations; registration country is not attacker attribution",
                        "baseline_windows": len(history), "baseline_mean": mean}
            result.append((event, evidence))
            if spike:
                self._sequence += 1
                candidate = dict(event, id="ris-" + self.digest("spike", self._sequence).hex()[:32],
                                 type="routing_anomaly_candidate", confidence="candidate",
                                 label="Routing anomaly candidate: announcement rate above warmed baseline")
                result.append((candidate, dict(evidence, reason="Announcement count at least 5x the mean of prior contiguous windows; not a hijack verdict")))
            history.append(bucket["prefix_count"])
            self.baselines[key] = (window, history)
            while len(self.baselines) > 512:
                self.baselines.popitem(last=False)
        return result


class BGPCollector:
    """One upstream connection; synchronous bounded API callbacks never block on I/O."""
    def __init__(self, config: BGPConfig, mapping: ASNMap | None = None):
        self.config = config
        self.aggregator = WindowAggregator(config, mapping)

    async def run(self, publish, update_source):
        cfg, agg = self.config, self.aggregator
        def status(state, reason, **extra):
            update_source("ris_live", status=state, reason=reason, scope={"collector": cfg.collector, **cfg.scope},
                          complete=agg.complete, rejected=agg.rejected, dropped=agg.dropped,
                          baseline_status="warming" if not agg.baselines else "per-series warm-up",
                          **extra)
        if cfg.gate:
            status(*cfg.gate)
            return
        # Import lazily: disabled operation/tests do not require a networking package.
        from websockets.asyncio.client import connect
        delay = 1.0
        while True:
            status("connecting", "Connecting to the approved filtered RIS subscription")
            started = time.monotonic()
            try:
                async with connect(RIS_URL, max_size=MAX_FRAME, max_queue=16, open_timeout=15,
                                   ping_interval=20, ping_timeout=20, close_timeout=5, compression=None) as ws:
                    await ws.send(json.dumps(cfg.subscription()))
                    # Acknowledgement proves subscription acceptance, not source freshness.
                    ack_deadline = time.monotonic() + 15
                    acknowledged = False
                    intake_second = int(time.monotonic())
                    intake_count = intake_bytes = emitted = 0
                    last_message = None
                    while True:
                        now = time.time()
                        second = int(time.monotonic())
                        if second != intake_second:
                            intake_second, intake_count, intake_bytes, emitted = second, 0, 0, 0
                        for event, evidence in agg.flush(now):
                            if emitted >= 50 or not publish(event, evidence):
                                agg.dropped += 1
                                agg.gap()
                                status("degraded", "Public emission capacity exceeded; baseline reset")
                            else:
                                emitted += 1
                        try:
                            frame = await asyncio.wait_for(ws.recv(), timeout=1)
                        except asyncio.TimeoutError:
                            if not acknowledged and time.monotonic() >= ack_deadline:
                                raise ValueError("subscription_ack_timeout")
                            if last_message is not None and now - last_message > 120:
                                status("stale", "No source messages recently; no activity is invented")
                            elif acknowledged and (agg.last_received is None or now - agg.last_received > 30):
                                status("quiet", "Connection open; no recent matching observations")
                            continue
                        intake_count += 1
                        intake_bytes += len(frame.encode("utf-8") if isinstance(frame, str) else frame)
                        if intake_count > cfg.max_messages_per_second or intake_bytes > cfg.max_bytes_per_second:
                            raise ValueError("intake_capacity_exceeded")
                        message = strict_json(frame)
                        if message.get("type") == "ris_error":
                            raise ValueError("provider_reported_error")
                        if message.get("type") == "ris_subscribe_ok":
                            acknowledged = True
                            status("connected", "Filtered subscription acknowledged")
                            continue
                        if message.get("type") == "ping":
                            await ws.send('{"type":"pong","data":null}')
                            continue
                        if message.get("type") != "ris_message":
                            continue
                        if not acknowledged:
                            if time.monotonic() >= ack_deadline:
                                raise ValueError("subscription_ack_timeout")
                            continue
                        last_message = time.time()
                        result = agg.feed(frame, last_message)
                        fields = {"last_message": utc(last_message)}
                        if agg.last_event is not None:
                            fields.update(last_event=utc(agg.last_event), last_received=utc(agg.last_received))
                        status("degraded" if result == "rejected" else "connected",
                               "Invalid input rejected; baseline reset" if result == "rejected" else "Receiving filtered routing observations", **fields)
            except asyncio.CancelledError:
                raise
            except Exception:
                # Never log exception text: upstream errors can contain payloads/addresses.
                agg.gap()
                status("unavailable", "RIS connection unavailable; reconnecting with backoff")
            if time.monotonic() - started >= 60:
                delay = 1.0
            await asyncio.sleep(random.uniform(delay / 2, delay))
            delay = min(delay * 2, 120)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Offline compact ASN-map build; no feed connection")
    parser.add_argument("--input", required=True)
    parser.add_argument("--source-commit", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    with Path(args.input).open("rb") as handle:
        source = handle.read(96 * 1024 * 1024 + 1)
    compiled = json.dumps(ASNMap.compile(source, args.source_commit), separators=(",", ":"))
    if len(compiled.encode()) > 2 * 1024 * 1024:
        raise ValueError("compiled_mapping_size_limit")
    Path(args.output).write_text(compiled, encoding="utf-8")

