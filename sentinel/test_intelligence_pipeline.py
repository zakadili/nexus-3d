"""Tests for the multi-source aggregator; no network access required."""
import json
import unittest
from unittest.mock import patch
from sentinel import intelligence_pipeline as p


class GeoTests(unittest.TestCase):
    def test_ranges_and_boundaries(self):
        db = p.GeoDB([["1.1.1.0", "1.1.1.255", "AU"],
                      ["8.8.8.0", "8.8.8.255", "US"],
                      ["203.0.113.0", "203.0.113.255", "ZZ"]])
        self.assertEqual(db.locate("1.1.1.1"), "AU")
        self.assertEqual(db.locate("8.8.8.8"), "US")
        self.assertIsNone(db.locate("9.9.9.9"))

    def test_ip_validation(self):
        self.assertEqual(p.global_v4("1.1.1.1"), "1.1.1.1")
        self.assertIsNone(p.global_v4("127.0.0.1"))
        self.assertIsNone(p.global_v4("192.168.1.2"))
        self.assertIsNone(p.global_v4("not an IP"))

    def test_dshield_indexed_payload(self):
        payload = {"0": {"source": "8.8.8.8", "reports": "50", "targets": "3"},
                   "1": {"source": "127.0.0.1", "reports": "5"},
                   "date": "2026-11-10"}
        rows = p.dshield_rows(payload)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["reports"], 50)

    def test_cross_source_deduplication(self):
        fake = [
            ("blocklistde", {"1.1.1.1", "8.8.8.8"}, {"id": "blocklistde", "name": "blocklist.de", "status": "ok", "records": 2}, []),
            ("ipsum", {"8.8.8.8"}, {"id": "ipsum", "name": "IPsum", "status": "ok", "records": 1}, []),
        ]
        geo = p.GeoDB([["1.1.1.0", "1.1.1.255", "AU"], ["8.8.8.0", "8.8.8.255", "US"]])
        class Pool:
            def __init__(self, max_workers): pass
            def __enter__(self): return self
            def __exit__(self, *args): pass
            def map(self, fn, names): return iter(fake)
        with patch.object(p, "ThreadPoolExecutor", Pool), patch.object(p, "geo_db", return_value=geo):
            report = p.collect_indicators()
        self.assertEqual(report["unique_indicators"], 2)
        rows = {row["code"]: row for row in report["countries"]}
        self.assertEqual(rows["US"]["indicators"], 1)
        self.assertEqual(rows["US"]["by_source"]["ipsum"], 1)
        self.assertEqual(rows["US"]["by_source"]["blocklistde"], 1)
        self.assertEqual(rows["US"]["multi_source_count"], 1)
        self.assertEqual(rows["US"]["samples_by_source"]["ipsum"][0]["ip"], "8.8.8.8")
        self.assertEqual(rows["US"]["examples"][0]["sources"], ["blocklistde", "ipsum"])

    def test_history_only_keeps_real_samples(self):
        old = {"generated_at": "2026-11-10T00:00:00Z",
               "indicators": {"unique_indicators": 3, "source_health": [{"id": "ipsum", "status": "ok"}],
                              "countries": [{"code": "US", "indicators": 2}]}}
        new = {"generated_at": "2026-11-10T06:00:00Z",
               "indicators": {"unique_indicators": 5, "source_health": [{"id": "ipsum", "status": "ok"}],
                              "countries": [{"code": "US", "indicators": 4}]}}
        history = p.assemble_history(new, old)
        self.assertEqual(len(history), 2)
        self.assertEqual(history[0]["country_counts"]["US"], 2)
        self.assertEqual(history[-1]["country_counts"]["US"], 4)
        self.assertEqual(len(p.assemble_history(new, {"history": history})), 2)


    def test_one_feed_unavailable_others_retained(self):
        good=("ipsum", {"8.8.8.8"}, {"id":"ipsum","status":"ok","records":1}, [])
        bad=("feodo", set(), {"id":"feodo","status":"unavailable","records":None}, [])
        class Pool:
            def __init__(self, max_workers): pass
            def __enter__(self): return self
            def __exit__(self, *args): pass
            def map(self, fn, names): return iter([bad,good])
        geo=p.GeoDB([["8.8.8.0","8.8.8.255","US"]])
        with patch.object(p,"ThreadPoolExecutor",Pool),patch.object(p,"geo_db",return_value=geo):
            result=p.collect_indicators()
        self.assertEqual(result["unique_indicators"],1)
        self.assertEqual(result["countries"][0]["code"],"US")
        self.assertEqual([x["status"] for x in result["source_health"]],["unavailable","ok"])

    def test_all_feeds_unavailable_never_overwrites(self):
        import tempfile
        from pathlib import Path
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/"overview.json"
            original='{"previous":"preserve me"}\\n'
            path.write_text(original)
            with patch.object(p,"OUT",path),patch.object(p,"collect_indicators",side_effect=RuntimeError("All IP feeds failed")),patch.object(p,"collect_cves",return_value={"status":"ok","total_kev":10}):
                with self.assertRaisesRegex(RuntimeError,"refusing to overwrite"):
                    p.main()
            self.assertEqual(path.read_text(),original)

    def test_empty_feodo_is_healthy_not_failed(self):
        with patch.object(p,"fetch",return_value=b"[]"):
            key,ips,meta,rows=p.get_feed("feodo")
        self.assertEqual(key,"feodo")
        self.assertEqual(ips,set())
        self.assertEqual(meta["status"],"ok")
        self.assertEqual(meta["records"],0)

    def test_all_feeds_failed_collection(self):
        fake=[(key,set(),{"id":key,"status":"unavailable"},[]) for key in p.SOURCE_FEEDS]
        class Pool:
            def __init__(self,max_workers): pass
            def __enter__(self): return self
            def __exit__(self,*args): pass
            def map(self,fn,names): return iter(fake)
        with patch.object(p,"ThreadPoolExecutor",Pool),patch.object(p,"geo_db",side_effect=AssertionError("must not geolocate")):
            with self.assertRaisesRegex(RuntimeError,"All IP intelligence sources unavailable"):
                p.collect_indicators()


if __name__ == "__main__":
    unittest.main()
