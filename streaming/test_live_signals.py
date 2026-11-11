"""Authored fixtures only: no network collection, personal data or production writes."""
import asyncio
from dataclasses import replace
import json
import unittest

from live_signals import LiveHub, Limits, Admission, Client, install, utc


class Clock:
    def __init__(self):
        self.now = 1800000000.0

    def __call__(self):
        return self.now


def fixture(clock, number=1):
    event = {"id": f"ris-fixture-{number}", "source": "ris_live", "type": "bgp_announcement",
             "ts_observed": utc(clock()), "ts_received": utc(clock()), "value": 3,
             "label": "BGP prefix announcements", "attribution": "RIPE NCC RIS Live",
             "confidence": "derived", "country": "FR"}
    proof = {"schema": "nexus.ris-evidence.v1", "source": "ris_live", "window_start": utc(clock()-10),
             "window_end": utc(clock()), "source_time_start": utc(clock()-2), "source_time_end": utc(clock()),
             "units": "prefix announcements", "message_count": 1, "prefix_count": 3,
             "input_digests": ["a"*64], "sample_count": 1, "digests_truncated": False,
             "collector": "rrc21", "scope": {"prefixes": ["192.0.2.0/24"]},
             "mapping": {"source": "https://github.com/ipverse/as-metadata", "license": "CC0-1.0",
                         "source_commit": "a"*40, "source_sha256": "b"*64, "generated_at": utc(clock())},
             "complete": True, "reason": "Authored test fixture", "baseline_windows": 0}
    return event, proof


class HubTests(unittest.TestCase):
    def setUp(self):
        self.clock = Clock()
        self.hub = LiveHub("https://api.example", clock=self.clock, wall=self.clock)

    def add(self, n=1):
        self.assertTrue(self.hub.publish(*fixture(self.clock, n)))
        return next(reversed(self.hub.records))

    def test_default_status_never_fabricates_timestamps(self):
        health = self.hub.health()
        self.assertEqual(health["sources"]["ris_live"]["status"], "disabled")
        for source in ("ioda", "certstream"):
            self.assertEqual(health["sources"][source]["status"], "license_blocked")
            self.hub.update_source(source, status="connected")
            self.assertEqual(self.hub.health()["sources"][source]["status"], "license_blocked")
        self.assertIsNone(health["sources"]["ris_live"]["last_event"])

    def test_public_evidence_and_deduplication(self):
        event_id = self.add()
        event = json.loads(self.hub.records[event_id]["event"])
        proof = json.loads(self.hub.evidence(event_id))
        self.assertEqual(event["evidence_url"], "https://api.example/api/live/evidence/"+event_id)
        self.assertEqual(proof["id"], event_id)
        self.assertIn("expires_at", proof)
        self.assertFalse(self.hub.publish(*fixture(self.clock)))
        self.assertEqual(len(self.hub.records), 1)

    def test_expiry_evicts_event_and_evidence_together(self):
        event_id = self.add()
        self.clock.now += 1800
        self.assertIsNone(self.hub.evidence(event_id))
        self.assertEqual(self.hub.health()["retention"]["records"], 0)
        self.assertEqual((self.hub.event_bytes, self.hub.evidence_bytes), (0, 0))

    def test_public_ids_do_not_reuse_evicted_source_ids(self):
        event_id = self.add()
        self.clock.now += 1800
        self.hub.evidence(event_id)
        self.hub.input_ids.clear()  # Simulate bounded collector-ID deduplication expiry.
        new_id = self.add()
        self.assertNotEqual(new_id, event_id)
        self.assertIsNone(self.hub.evidence(event_id))

    def test_count_and_byte_limits(self):
        self.hub = LiveHub("https://api.example", replace(Limits(), records=2), self.clock, self.clock)
        old = self.add(1)
        self.add(2)
        self.add(3)
        self.assertIsNone(self.hub.evidence(old))
        self.assertEqual(len(self.hub.records), 2)
        self.hub = LiveHub("https://api.example", replace(Limits(), evidence_bytes=1500), self.clock, self.clock)
        old = self.add(1)
        self.add(2)
        self.assertLessEqual(self.hub.evidence_bytes, 1500)
        self.assertIsNone(self.hub.evidence(old))

    def test_rejects_untrusted_fields_and_inconsistent_proof(self):
        mutations = [lambda e,p: e.update(country="ZZ"), lambda e,p: e.update(asn=True),
                     lambda e,p: e.update(value=float("nan")), lambda e,p: e.update(label="x"*241),
                     lambda e,p: e.update(ts_observed="2026-01-01T01:00:00"),
                     lambda e,p: e.update(evidence_url="https://evil.example/payload"),
                     lambda e,p: p.update(raw={"peer": "192.0.2.8"}),
                     lambda e,p: p.update(input_digests=["192.0.2.8"]),
                     lambda e,p: p.update(source_time_end=utc(self.clock()-1)),
                     lambda e,p: p.update(prefix_count=5),
                     lambda e,p: e.update(type="attack"),
                     lambda e,p: e.update(ts_received=utc(self.clock()+301))]
        for mutate in mutations:
            event, proof = fixture(self.clock)
            mutate(event, proof)
            self.assertFalse(self.hub.publish(event, proof))
        self.assertEqual(len(self.hub.records), 0)
        self.assertEqual(self.hub.sources["ris_live"]["rejected"], len(mutations))

    def test_unapproved_source_and_located_withdrawal_rejected(self):
        event, proof = fixture(self.clock)
        event["source"] = "ioda"
        self.assertFalse(self.hub.publish(event, proof))
        event["source"], event["type"] = "ris_live", "bgp_withdrawal"
        self.assertFalse(self.hub.publish(event, proof))

    def test_emission_cap_reports_incomplete_data(self):
        for n in range(50):
            self.add(n)
        self.assertFalse(self.hub.publish(*fixture(self.clock, 51)))
        self.assertEqual(self.hub.sources["ris_live"]["dropped"], 1)
        self.assertFalse(self.hub.sources["ris_live"]["complete"])
        self.clock.now += 1
        self.add(52)

    def test_client_count_and_attempt_limits(self):
        first, status = self.hub.subscribe("192.0.2.1")
        self.assertEqual(status, 200)
        self.hub.subscribe("192.0.2.1")
        self.assertEqual(self.hub.subscribe("192.0.2.1")[1], 429)
        self.clock.now += 60
        self.assertEqual(self.hub.subscribe("192.0.2.1")[1], 503)
        self.hub.remove(first)
        self.assertEqual(self.hub.subscribe("192.0.2.1")[1], 200)
        for n in range(6):
            self.assertEqual(self.hub.subscribe(f"192.0.2.{n+2}")[1], 200)
        self.assertEqual(self.hub.subscribe("192.0.2.99")[1], 503)
        self.assertNotIn("192.0.2.1", repr(self.hub.admission.entries))

    def test_slow_clients_disconnect_and_release_buffers(self):
        self.hub = LiveHub("https://api.example", replace(Limits(), queue_frames=2), self.clock, self.clock)
        client, _ = self.hub.subscribe("192.0.2.1")
        self.add(1)
        self.add(2)
        self.assertTrue(client.closed)
        self.assertNotIn(client, self.hub.clients)
        self.assertEqual(client.size, 0)

    def test_byte_queue_cap_is_separate_from_frame_count(self):
        client = Client("opaque", replace(Limits(), queue_bytes=10))
        self.assertTrue(client.put(b"123456"))
        self.assertFalse(client.put(b"123456"))
        self.assertTrue(client.closed)

    def test_replay_has_separate_event_and_restart_gap(self):
        first = self.add(1)
        cursor = self.hub.records[first]["cursor"]
        self.add(2)
        client, _ = self.hub.subscribe("192.0.2.1", cursor)
        self.assertIn(b"event: health", client.take())
        self.assertIn(b"event: replay", client.take())
        other = LiveHub("https://api.example", clock=self.clock, wall=self.clock)
        client, _ = other.subscribe("192.0.2.1", cursor)
        client.take()
        self.assertIn(b"event: gap", client.take())

    def test_initial_connection_does_not_pulse_old_history(self):
        self.add()
        client, _ = self.hub.subscribe("192.0.2.1")
        self.assertIn(b"event: health", client.take())
        self.assertIsNone(client.take())

    def test_stale_source_is_not_zero_or_live(self):
        self.hub.update_source("ris_live", state="connected", last_message_at=utc(self.clock()), complete=True)
        self.clock.now += 91
        status = self.hub.health()["sources"]["ris_live"]
        self.assertEqual(status["status"], "stale")
        self.assertFalse(status["complete"])
        self.assertIsNone(status["last_event"])

    def test_admission_keys_expire_and_are_bounded(self):
        limiter = Admission(2, self.clock)
        for key in range(3):
            limiter.allow(key, 5, 2)
        self.assertEqual(len(limiter.entries), 2)
        self.clock.now += 121
        limiter.allow("new", 5, 2)
        self.assertEqual(list(limiter.entries), ["new"])


class AsyncTests(unittest.IsolatedAsyncioTestCase):
    async def test_expired_queued_events_become_gap(self):
        clock = Clock()
        hub = LiveHub("https://api.example", clock=clock, wall=clock)
        client, _ = hub.subscribe("192.0.2.1")
        hub.publish(*fixture(clock))
        stream = hub.stream(client)
        self.assertIn(b"event: health", await anext(stream))
        clock.now += 1800
        self.assertIn(b"event: gap", await anext(stream))
        await stream.aclose()
        self.assertEqual(len(hub.clients), 0)

    async def test_http_origin_rate_and_expiry(self):
        import httpx
        from fastapi import FastAPI
        clock = Clock()
        hub = LiveHub("https://api.example", clock=clock, wall=clock)
        hub.publish(*fixture(clock))
        event_id = next(iter(hub.records))
        app = FastAPI()
        install(app, hub)
        transport = httpx.ASGITransport(app=app, client=("192.0.2.1", 123))
        async with httpx.AsyncClient(transport=transport, base_url="https://api.example") as client:
            path = "/api/live/evidence/"+event_id
            result = await client.get(path, headers={"Origin": "https://evil.example"})
            self.assertEqual(result.status_code, 403)
            self.assertNotIn("access-control-allow-origin", result.headers)
            result = await client.get(path, headers={"Origin": "https://zakadili.github.io"})
            self.assertEqual(result.status_code, 200)
            self.assertEqual(result.headers["access-control-allow-origin"], "https://zakadili.github.io")
            self.assertEqual(result.headers["cache-control"], "no-store")
            self.assertNotIn("access-control-allow-credentials", result.headers)
            clock.now += 1800
            self.assertEqual((await client.get(path)).status_code, 410)
            statuses = [(await client.get(path, headers={"X-Real-IP": f"192.0.2.{n}"})).status_code for n in range(12)]
            self.assertIn(429, statuses, "Untrusted X-Real-IP bypassed admission")
            result = await client.get("/api/live/events", headers={"Origin": "https://evil.example"})
            self.assertEqual(result.status_code, 403)
            result = await client.get("/api/live/events", headers={"Last-Event-ID": "bad\u0020cursor"})
            self.assertEqual(result.status_code, 400)


if __name__ == "__main__":
    unittest.main()

