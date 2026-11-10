"""Deterministic tests for the live feed parser; no external network access."""
import unittest
from unittest.mock import patch
from sentinel import radar_feed as rf


class TestRadarFeed(unittest.TestCase):
    def test_normalize_sources(self):
        self.assertEqual(rf._source({"source": "8.8.8.8", "reports": "120", "targets": 4}),
                         {"ip": "8.8.8.8", "reports": 120, "targets": 4})
        self.assertIsNone(rf._source({"source": "127.0.0.1"}))
        self.assertIsNone(rf._source({"source": "not-an-ip"}))

    def test_normalize_ranked_payload(self):
        data = {"0": {"source": "8.8.8.8", "reports": 50, "targets": 2}, "date": "2026-11-10"}
        self.assertEqual(len(rf._rows(data, "ipaddress")), 1)

    def test_collect_mock_sources(self):
        def fake_get(url, timeout=12):
            if "topips" in url:
                return {"0": {"source": "8.8.8.8", "reports": 50, "targets": 2}, "date": "2026-11-10"}
            if "topports" in url:
                return {"0": {"targetport": 443, "records": 77, "sources": 5}, "date": "2026-11-10"}
            if "ipwho.is/8.8.8.8" in url:
                return {"success": True, "country": "United States", "country_code": "US",
                        "latitude": 37.75, "longitude": -97.82}
            raise AssertionError("Unexpected URL " + url)
        with patch.object(rf, "_fetch_json", side_effect=fake_get):
            report = rf.collect()
        self.assertEqual(report["sources"][0]["country"], "United States")
        self.assertEqual(report["sources"][0]["reports"], 50)
        self.assertEqual(report["ports"][0]["port"], 443)
        self.assertEqual(report["ports"][0]["reports"], 77)
        self.assertEqual(report["mode"], "LOCAL COLLECTOR")

    def test_unavailable_feed_is_not_fabricated(self):
        with patch.object(rf, "_fetch_json", side_effect=RuntimeError("feed offline")):
            with self.assertRaises(RuntimeError):
                rf.collect()


if __name__ == "__main__":
    unittest.main()
